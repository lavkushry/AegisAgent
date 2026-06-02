import logging
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger("aegisagent")


class AegisClient:
    def __init__(
        self,
        api_key: str,
        agent_id: str,
        environment: str = "production",
        endpoint: str = "http://127.0.0.1:8080",
    ):
        self.api_key = api_key
        self.agent_id = agent_id
        self.environment = environment
        self.endpoint = endpoint.rstrip("/")
        self.agent_token: Optional[str] = None

    def _tenant_id(self) -> str:
        return self.api_key if self.api_key.startswith("tenant_") else "tenant_123"

    def register_agent(
        self, agent_name: str, owner_team: Optional[str] = None, risk_tier: str = "high"
    ) -> bool:
        """Registers the agent on the AegisAgent gateway to obtain an agent token."""
        url = f"{self.endpoint}/v1/agents/register"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "agent_key": self.agent_id,
            "name": agent_name,
            "owner_team": owner_team,
            "environment": self.environment,
            "risk_tier": risk_tier,
        }
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=5)
            if response.status_code in (200, 201):
                data = response.json()
                self.agent_token = data.get("agent_token")
                logger.info(f"Agent successfully registered. Token acquired.")
                return True
            else:
                logger.error(
                    f"Failed to register agent: {response.status_code} - {response.text}"
                )
                return False
        except Exception as e:
            logger.error(f"Failed to connect to gateway during registration: {e}")
            return False

    def authorize(
        self,
        tool: str,
        action: str,
        parameters: Dict[str, Any],
        resource: Optional[str] = None,
        source_trust: str = "unknown",
        contains_sensitive_data: bool = False,
        run_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Queries the AegisAgent gateway to authorize an action."""
        if not self.agent_token:
            # Try to register agent automatically if token is missing
            self.register_agent(agent_name=self.agent_id)
            if not self.agent_token:
                logger.error("AegisAgent Client unauthorized: No agent token resolved.")
                return {
                    "decision": "deny",
                    "risk_score": 100,
                    "risk_level": "critical",
                    "reason": "Agent not registered/token not resolved. Failing closed.",
                    "matched_policies": [],
                }

        url = f"{self.endpoint}/v1/authorize"
        headers = {
            "Authorization": f"Bearer {self.agent_token}",
            "X-Aegis-Tenant-ID": self._tenant_id(),
            "Content-Type": "application/json",
        }

        payload = {
            "agent": {"id": self.agent_id, "environment": self.environment},
            "tool_call": {
                "tool": tool,
                "action": action,
                "resource": resource,
                "mutates_state": True,  # Assume mutating for authorization purposes
                "parameters": parameters,
            },
            "context": {
                "source_trust": source_trust,
                "contains_sensitive_data": contains_sensitive_data,
            },
            "trace": {
                "run_id": run_id or "run_default",
                "trace_id": trace_id or "trace_default",
            },
        }

        try:
            response = requests.post(url, json=payload, headers=headers, timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(
                    f"Gateway returned error status: {response.status_code} - {response.text}"
                )
                # Fail-closed default
                return {
                    "decision": "deny",
                    "reason": f"Gateway error: {response.status_code}. Fail-closed.",
                    "matched_policies": [],
                }
        except Exception as e:
            logger.error(f"Network error communicating with gateway: {e}")
            # Fail-closed default
            return {
                "decision": "deny",
                "reason": f"Gateway network error: {e}. Fail-closed.",
                "matched_policies": [],
            }

    def get_approval_status(self, approval_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves approval request status from the gateway."""
        url = f"{self.endpoint}/v1/approvals/{approval_id}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to query approval status: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Failed to query approval: {e}")
            return None

    def consume_approval(self, approval_id: str) -> Optional[Dict[str, Any]]:
        """Atomically consume an APPROVED approval so it cannot be reused.

        Returns the gateway response (which includes the bound ``action_hash``)
        on success, or ``None`` if the approval was already consumed, expired, or
        is not approvable. The caller MUST fail closed on ``None``.
        """
        url = f"{self.endpoint}/v1/approvals/{approval_id}/consume"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        try:
            response = requests.post(url, headers=headers, timeout=5)
            if response.status_code == 200:
                return response.json()
            logger.error(f"Approval consume rejected: {response.status_code}")
            return None
        except Exception as e:
            logger.error(f"Failed to consume approval: {e}")
            return None
