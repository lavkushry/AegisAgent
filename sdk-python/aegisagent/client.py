import asyncio
import inspect
import json
import logging
import re
import sys
import time
from functools import wraps
from typing import Any, Dict, Optional

import requests

try:
    import httpx
except ImportError:
    httpx = None

logger = logging.getLogger("aegisagent")


def retry_on_5xx(max_retries: int = 3, backoff_factor: float = 1.0):
    """Decorator to retry HTTP requests on 5xx status codes or connection/network errors.

    Works for both synchronous functions (using time.sleep) and
    asynchronous functions (using asyncio.sleep).
    """

    def decorator(func):
        if inspect.iscoroutinefunction(func):

            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                delay = backoff_factor
                for attempt in range(max_retries + 1):
                    try:
                        response = await func(*args, **kwargs)
                        status_code = getattr(response, "status_code", None)
                        if (
                            status_code in (500, 502, 503, 504)
                            and attempt < max_retries
                        ):
                            logger.warning(
                                f"HTTP {status_code} on attempt {attempt + 1}. Retrying in {delay}s..."
                            )
                            await asyncio.sleep(delay)
                            delay *= 2
                            continue
                        return response
                    except Exception as e:
                        is_network_err = False
                        if httpx is not None:
                            if isinstance(e, httpx.RequestError):
                                is_network_err = True
                        if not is_network_err:
                            if isinstance(e, requests.exceptions.RequestException):
                                is_network_err = True

                        if is_network_err and attempt < max_retries:
                            logger.warning(
                                f"Network error on attempt {attempt + 1}: {e}. Retrying in {delay}s..."
                            )
                            await asyncio.sleep(delay)
                            delay *= 2
                            continue
                        raise

            return async_wrapper
        else:

            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                delay = backoff_factor
                for attempt in range(max_retries + 1):
                    try:
                        response = func(*args, **kwargs)
                        status_code = getattr(response, "status_code", None)
                        if (
                            status_code in (500, 502, 503, 504)
                            and attempt < max_retries
                        ):
                            logger.warning(
                                f"HTTP {status_code} on attempt {attempt + 1}. Retrying in {delay}s..."
                            )
                            time.sleep(delay)
                            delay *= 2
                            continue
                        return response
                    except Exception as e:
                        is_network_err = False
                        if isinstance(e, requests.exceptions.RequestException):
                            is_network_err = True
                        elif httpx is not None and isinstance(e, httpx.RequestError):
                            is_network_err = True

                        if is_network_err and attempt < max_retries:
                            logger.warning(
                                f"Network error on attempt {attempt + 1}: {e}. Retrying in {delay}s..."
                            )
                            time.sleep(delay)
                            delay *= 2
                            continue
                        raise

            return sync_wrapper

    return decorator


class AegisBaseClient:
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

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(api_key={self.api_key!r}, agent_id={self.agent_id!r}, "
            f"environment={self.environment!r}, endpoint={self.endpoint!r})"
        )

    def __str__(self) -> str:
        return f"{self.__class__.__name__}(agent_id={self.agent_id}, environment={self.environment}, endpoint={self.endpoint})"

    def _redact_json(self, data: Any) -> Any:
        if isinstance(data, dict):
            return {
                k: (
                    "[REDACTED]"
                    if k.lower() in ("api_key", "agent_token", "agent_key", "token")
                    else self._redact_json(v)
                )
                for k, v in data.items()
            }
        elif isinstance(data, list):
            return [self._redact_json(x) for x in data]
        return data

    def _redact_response_text(self, text: str) -> str:
        if not text:
            return text
        try:
            data = json.loads(text)
            return json.dumps(self._redact_json(data))
        except Exception:
            text = re.sub(r"(?i)bearer\s+[^\s\"',}]+", "Bearer [REDACTED]", text)
            text = re.sub(
                r'(?i)"(api_key|agent_token|agent_key|token)"\s*:\s*"[^"]+"',
                r'"\1":"[REDACTED]"',
                text,
            )
            return text

    def _tenant_id(self) -> str:
        return self.api_key if self.api_key.startswith("tenant_") else "tenant_123"

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }


class AegisClient(AegisBaseClient):
    def __init__(
        self,
        api_key: str,
        agent_id: str,
        environment: str = "production",
        endpoint: str = "http://127.0.0.1:8080",
    ):
        super().__init__(api_key, agent_id, environment, endpoint)
        self.session = requests.Session()
        from urllib3.util import Retry
        from requests.adapters import HTTPAdapter

        retries = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def close(self) -> None:
        """Closes the HTTP session (connection pool cleanup) (TASK-0190)."""
        self.session.close()

    @retry_on_5xx(max_retries=3, backoff_factor=1.0)
    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        """Sends an HTTP request, handles debug level logging with redaction, and returns the response (TASK-0192)."""
        url = f"{self.endpoint}{path}"

        headers = kwargs.get("headers", {})
        json_payload = kwargs.get("json")
        params = kwargs.get("params")

        redacted_headers = {}
        for k, v in headers.items():
            if k.lower() == "authorization":
                if v.startswith("Bearer "):
                    redacted_headers[k] = "Bearer [REDACTED]"
                else:
                    redacted_headers[k] = "[REDACTED]"
            else:
                redacted_headers[k] = v

        redacted_json = self._redact_json(json_payload) if json_payload else None
        redacted_params = self._redact_json(params) if params else None

        logger.debug(
            f"Sending Request: {method} {url} headers={redacted_headers} json={redacted_json} params={redacted_params}"
        )

        if method.upper() == "POST":
            response = self.session.post(url, **kwargs)
        elif method.upper() == "GET":
            response = self.session.get(url, **kwargs)
        else:
            response = self.session.request(method, url, **kwargs)

        if hasattr(response, "text") and isinstance(response.text, str):
            redacted_response_text = self._redact_response_text(response.text)
        else:
            redacted_response_text = "[MOCKED_RESPONSE]"

        response_headers = {}
        headers_type = type(getattr(response, "headers", None)).__name__
        if (
            hasattr(response, "headers")
            and hasattr(response.headers, "items")
            and "Mock" not in headers_type
        ):
            try:
                response_headers = dict(response.headers)
            except Exception:
                pass
        elif hasattr(response, "headers") and isinstance(response.headers, dict):
            response_headers = response.headers

        logger.debug(
            f"Received Response: status={response.status_code} headers={response_headers} text={redacted_response_text}"
        )

        return response

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
            response = self._request(
                "POST", "/v1/agents/register", json=payload, headers=headers, timeout=5
            )
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
                "mutates_state": True,
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
            response = self._request(
                "POST", "/v1/authorize", json=payload, headers=headers, timeout=5
            )
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(
                    f"Gateway returned error status: {response.status_code} - {response.text}"
                )
                return {
                    "decision": "deny",
                    "reason": f"Gateway error: {response.status_code}. Fail-closed.",
                    "matched_policies": [],
                }
        except Exception as e:
            logger.error(f"Network error communicating with gateway: {e}")
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
            response = self._request(
                "GET", f"/v1/approvals/{approval_id}", headers=headers, timeout=5
            )
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to query approval status: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Failed to query approval: {e}")
            return None

    def consume_approval(self, approval_id: str) -> Optional[Dict[str, Any]]:
        """Atomically consume an APPROVED approval so it cannot be reused."""
        url = f"{self.endpoint}/v1/approvals/{approval_id}/consume"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        try:
            response = self._request(
                "POST",
                f"/v1/approvals/{approval_id}/consume",
                headers=headers,
                timeout=5,
            )
            if response.status_code == 200:
                return response.json()
            logger.error(f"Approval consume rejected: {response.status_code}")
            return None
        except Exception as e:
            logger.error(f"Failed to consume approval: {e}")
            return None

    def _post(self, path: str, json_payload: Optional[Dict[str, Any]] = None) -> bool:
        try:
            response = self._request(
                "POST", path, json=json_payload, headers=self._headers(), timeout=5
            )
            if response.status_code in (200, 201):
                return True
            logger.error(
                f"POST {path} failed: {response.status_code} - {response.text}"
            )
            return False
        except Exception as e:
            logger.error(f"Connection error on POST {path}: {e}")
            return False

    def freeze_agent(self, agent_id: str) -> bool:
        """Freezes an agent operational status."""
        return self._post(f"/v1/agents/{agent_id}/freeze")

    def unfreeze_agent(self, agent_id: str) -> bool:
        """Restores a frozen agent to active status."""
        return self._post(f"/v1/agents/{agent_id}/unfreeze")

    def revoke_agent(self, agent_id: str) -> bool:
        """Permanently revokes an agent."""
        return self._post(f"/v1/agents/{agent_id}/revoke")

    def quarantine_server(self, server_key: str) -> bool:
        """Quarantines an MCP server."""
        return self._post(f"/v1/mcp/servers/{server_key}/quarantine")

    def restore_server(self, server_key: str) -> bool:
        """Restores a quarantined MCP server to active status."""
        return self._post(f"/v1/mcp/servers/{server_key}/restore")

    def _get_list(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Optional[list]:
        try:
            response = self._request(
                "GET", path, headers=self._headers(), params=params, timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    return data
                return data
            logger.error(f"GET {path} failed: {response.status_code} - {response.text}")
            return None
        except Exception as e:
            logger.error(f"Connection error on GET {path}: {e}")
            return None

    def list_agents(self, limit: int = 50, offset: int = 0) -> Optional[list]:
        """Lists registered agents for the tenant."""
        return self._get_list("/v1/agents", params={"limit": limit, "offset": offset})

    def list_decisions(
        self,
        limit: int = 50,
        offset: int = 0,
        agent_id: Optional[str] = None,
        decision: Optional[str] = None,
    ) -> Optional[list]:
        """Lists decisions for the tenant, with optional filters."""
        params = {"limit": limit, "offset": offset}
        if agent_id:
            params["agent_id"] = agent_id
        if decision:
            params["decision"] = decision
        return self._get_list("/v1/decisions", params=params)

    def list_approvals(self, limit: int = 50, offset: int = 0) -> Optional[list]:
        """Lists pending approvals for the tenant."""
        return self._get_list(
            "/v1/approvals", params={"limit": limit, "offset": offset}
        )

    def list_receipts(self, limit: int = 50, offset: int = 0) -> Optional[list]:
        """Lists verifiable action receipts for the tenant."""
        return self._get_list("/v1/receipts", params={"limit": limit, "offset": offset})

    def verify_receipt_chain(self, receipts: list) -> Dict[str, Any]:
        """Verifies the cryptographic integrity of a chain of receipts."""
        payload = {"receipts": receipts}
        try:
            response = self._request(
                "POST",
                "/v1/receipts/verify-chain",
                json=payload,
                headers=self._headers(),
                timeout=5,
            )
            if response.status_code == 200:
                return response.json()
            logger.error(
                f"POST /v1/receipts/verify-chain failed: {response.status_code} - {response.text}"
            )
            return {
                "verified": False,
                "error": f"Gateway error: {response.status_code}",
            }
        except Exception as e:
            logger.error(f"Connection error on POST /v1/receipts/verify-chain: {e}")
            return {"verified": False, "error": str(e)}

    def upload_policy(
        self, policy_key: str, name: str, body: str
    ) -> Optional[Dict[str, Any]]:
        """Uploads/creates a Cedar policy on the gateway."""
        payload = {
            "policy_key": policy_key,
            "name": name,
            "body": body,
        }
        try:
            response = self._request(
                "POST", "/v1/policies", json=payload, headers=self._headers(), timeout=5
            )
            if response.status_code in (200, 201):
                return response.json()
            logger.error(
                f"POST /v1/policies failed: {response.status_code} - {response.text}"
            )
            return None
        except Exception as e:
            logger.error(f"Connection error on POST /v1/policies: {e}")
            return None

    def list_policies(self) -> Optional[list]:
        """Lists active policies for the tenant."""
        return self._get_list("/v1/policies")

    def register_mcp_server(
        self,
        server_key: str,
        name: str,
        transport: str,
        endpoint: str,
        trust_level: str,
        owner_team: Optional[str] = None,
        source: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Registers/updates an MCP server definition on the gateway."""
        payload = {
            "server_key": server_key,
            "name": name,
            "transport": transport,
            "endpoint": endpoint,
            "trust_level": trust_level,
            "owner_team": owner_team,
            "source": source,
        }
        try:
            response = self._request(
                "POST",
                "/v1/mcp/servers",
                json=payload,
                headers=self._headers(),
                timeout=5,
            )
            if response.status_code in (200, 201):
                return response.json()
            logger.error(
                f"POST /v1/mcp/servers failed: {response.status_code} - {response.text}"
            )
            return None
        except Exception as e:
            logger.error(f"Connection error on POST /v1/mcp/servers: {e}")
            return None

    def discover_tools(self, server_key: str, tools: list) -> Optional[Dict[str, Any]]:
        """Registers/pins tool discovery items for an MCP server on the gateway."""
        payload = {"tools": tools}
        try:
            response = self._request(
                "POST",
                f"/v1/mcp/servers/{server_key}/tools",
                json=payload,
                headers=self._headers(),
                timeout=5,
            )
            if response.status_code in (200, 201):
                return response.json()
            logger.error(
                f"POST /v1/mcp/servers/{server_key}/tools failed: {response.status_code} - {response.text}"
            )
            return None
        except Exception as e:
            logger.error(
                f"Connection error on POST /v1/mcp/servers/{server_key}/tools: {e}"
            )
            return None


class AegisAsyncClient(AegisBaseClient):
    def __init__(
        self,
        api_key: str,
        agent_id: str,
        environment: str = "production",
        endpoint: str = "http://127.0.0.1:8080",
    ):
        if httpx is None:
            raise ImportError(
                "The 'httpx' library is required to use AegisAsyncClient. "
                "Install it with 'pip install httpx'."
            )
        super().__init__(api_key, agent_id, environment, endpoint)
        self.session = httpx.AsyncClient(timeout=httpx.Timeout(5.0))

    async def close(self) -> None:
        """Closes the HTTP session (connection pool cleanup) (TASK-0190)."""
        await self.session.aclose()

    @retry_on_5xx(max_retries=3, backoff_factor=1.0)
    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Sends an HTTP request asynchronously, handles debug level logging with redaction, and returns the response."""
        url = f"{self.endpoint}{path}"

        headers = kwargs.get("headers", {})
        json_payload = kwargs.get("json")
        params = kwargs.get("params")

        redacted_headers = {}
        for k, v in headers.items():
            if k.lower() == "authorization":
                if v.startswith("Bearer "):
                    redacted_headers[k] = "Bearer [REDACTED]"
                else:
                    redacted_headers[k] = "[REDACTED]"
            else:
                redacted_headers[k] = v

        redacted_json = self._redact_json(json_payload) if json_payload else None
        redacted_params = self._redact_json(params) if params else None

        logger.debug(
            f"Sending Request: {method} {url} headers={redacted_headers} json={redacted_json} params={redacted_params}"
        )

        response = await self.session.request(method, url, **kwargs)

        if hasattr(response, "text") and isinstance(response.text, str):
            redacted_response_text = self._redact_response_text(response.text)
        else:
            redacted_response_text = "[MOCKED_RESPONSE]"

        response_headers = {}
        headers_type = type(getattr(response, "headers", None)).__name__
        if (
            hasattr(response, "headers")
            and hasattr(response.headers, "items")
            and "Mock" not in headers_type
        ):
            try:
                response_headers = dict(response.headers)
            except Exception:
                pass
        elif hasattr(response, "headers") and isinstance(response.headers, dict):
            response_headers = response.headers

        logger.debug(
            f"Received Response: status={response.status_code} headers={response_headers} text={redacted_response_text}"
        )

        return response

    async def register_agent(
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
            response = await self._request(
                "POST",
                "/v1/agents/register",
                json=payload,
                headers=headers,
                timeout=5.0,
            )
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

    async def authorize(
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
            await self.register_agent(agent_name=self.agent_id)
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
                "mutates_state": True,
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
            response = await self._request(
                "POST", "/v1/authorize", json=payload, headers=headers, timeout=5.0
            )
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(
                    f"Gateway returned error status: {response.status_code} - {response.text}"
                )
                return {
                    "decision": "deny",
                    "reason": f"Gateway error: {response.status_code}. Fail-closed.",
                    "matched_policies": [],
                }
        except Exception as e:
            logger.error(f"Network error communicating with gateway: {e}")
            return {
                "decision": "deny",
                "reason": f"Gateway network error: {e}. Fail-closed.",
                "matched_policies": [],
            }

    async def get_approval_status(self, approval_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves approval request status from the gateway."""
        url = f"{self.endpoint}/v1/approvals/{approval_id}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        try:
            response = await self._request(
                "GET", f"/v1/approvals/{approval_id}", headers=headers, timeout=5.0
            )
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to query approval status: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Failed to query approval: {e}")
            return None

    async def consume_approval(self, approval_id: str) -> Optional[Dict[str, Any]]:
        """Atomically consume an APPROVED approval so it cannot be reused."""
        url = f"{self.endpoint}/v1/approvals/{approval_id}/consume"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        try:
            response = await self._request(
                "POST",
                f"/v1/approvals/{approval_id}/consume",
                headers=headers,
                timeout=5.0,
            )
            if response.status_code == 200:
                return response.json()
            logger.error(f"Approval consume rejected: {response.status_code}")
            return None
        except Exception as e:
            logger.error(f"Failed to consume approval: {e}")
            return None

    async def _post(
        self, path: str, json_payload: Optional[Dict[str, Any]] = None
    ) -> bool:
        try:
            response = await self._request(
                "POST", path, json=json_payload, headers=self._headers(), timeout=5.0
            )
            if response.status_code in (200, 201):
                return True
            logger.error(
                f"POST {path} failed: {response.status_code} - {response.text}"
            )
            return False
        except Exception as e:
            logger.error(f"Connection error on POST {path}: {e}")
            return False

    async def freeze_agent(self, agent_id: str) -> bool:
        """Freezes an agent operational status."""
        return await self._post(f"/v1/agents/{agent_id}/freeze")

    async def unfreeze_agent(self, agent_id: str) -> bool:
        """Restores a frozen agent to active status."""
        return await self._post(f"/v1/agents/{agent_id}/unfreeze")

    async def revoke_agent(self, agent_id: str) -> bool:
        """Permanently revokes an agent."""
        return await self._post(f"/v1/agents/{agent_id}/revoke")

    async def quarantine_server(self, server_key: str) -> bool:
        """Quarantines an MCP server."""
        return await self._post(f"/v1/mcp/servers/{server_key}/quarantine")

    async def restore_server(self, server_key: str) -> bool:
        """Restores a quarantined MCP server to active status."""
        return await self._post(f"/v1/mcp/servers/{server_key}/restore")

    async def _get_list(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Optional[list]:
        try:
            response = await self._request(
                "GET", path, headers=self._headers(), params=params, timeout=5.0
            )
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    return data
                return data
            logger.error(f"GET {path} failed: {response.status_code} - {response.text}")
            return None
        except Exception as e:
            logger.error(f"Connection error on GET {path}: {e}")
            return None

    async def list_agents(self, limit: int = 50, offset: int = 0) -> Optional[list]:
        """Lists registered agents for the tenant."""
        return await self._get_list(
            "/v1/agents", params={"limit": limit, "offset": offset}
        )

    async def list_decisions(
        self,
        limit: int = 50,
        offset: int = 0,
        agent_id: Optional[str] = None,
        decision: Optional[str] = None,
    ) -> Optional[list]:
        """Lists decisions for the tenant, with optional filters."""
        params = {"limit": limit, "offset": offset}
        if agent_id:
            params["agent_id"] = agent_id
        if decision:
            params["decision"] = decision
        return await self._get_list("/v1/decisions", params=params)

    async def list_approvals(self, limit: int = 50, offset: int = 0) -> Optional[list]:
        """Lists pending approvals for the tenant."""
        return await self._get_list(
            "/v1/approvals", params={"limit": limit, "offset": offset}
        )

    async def list_receipts(self, limit: int = 50, offset: int = 0) -> Optional[list]:
        """Lists verifiable action receipts for the tenant."""
        return await self._get_list(
            "/v1/receipts", params={"limit": limit, "offset": offset}
        )

    async def verify_receipt_chain(self, receipts: list) -> Dict[str, Any]:
        """Verifies the cryptographic integrity of a chain of receipts."""
        payload = {"receipts": receipts}
        try:
            response = await self._request(
                "POST",
                "/v1/receipts/verify-chain",
                json=payload,
                headers=self._headers(),
                timeout=5.0,
            )
            if response.status_code == 200:
                return response.json()
            logger.error(
                f"POST /v1/receipts/verify-chain failed: {response.status_code} - {response.text}"
            )
            return {
                "verified": False,
                "error": f"Gateway error: {response.status_code}",
            }
        except Exception as e:
            logger.error(f"Connection error on POST /v1/receipts/verify-chain: {e}")
            return {"verified": False, "error": str(e)}

    async def upload_policy(
        self, policy_key: str, name: str, body: str
    ) -> Optional[Dict[str, Any]]:
        """Uploads/creates a Cedar policy on the gateway."""
        payload = {
            "policy_key": policy_key,
            "name": name,
            "body": body,
        }
        try:
            response = await self._request(
                "POST",
                "/v1/policies",
                json=payload,
                headers=self._headers(),
                timeout=5.0,
            )
            if response.status_code in (200, 201):
                return response.json()
            logger.error(
                f"POST /v1/policies failed: {response.status_code} - {response.text}"
            )
            return None
        except Exception as e:
            logger.error(f"Connection error on POST /v1/policies: {e}")
            return None

    async def list_policies(self) -> Optional[list]:
        """Lists active policies for the tenant."""
        return await self._get_list("/v1/policies")

    async def register_mcp_server(
        self,
        server_key: str,
        name: str,
        transport: str,
        endpoint: str,
        trust_level: str,
        owner_team: Optional[str] = None,
        source: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Registers/updates an MCP server definition on the gateway."""
        payload = {
            "server_key": server_key,
            "name": name,
            "transport": transport,
            "endpoint": endpoint,
            "trust_level": trust_level,
            "owner_team": owner_team,
            "source": source,
        }
        try:
            response = await self._request(
                "POST",
                "/v1/mcp/servers",
                json=payload,
                headers=self._headers(),
                timeout=5.0,
            )
            if response.status_code in (200, 201):
                return response.json()
            logger.error(
                f"POST /v1/mcp/servers failed: {response.status_code} - {response.text}"
            )
            return None
        except Exception as e:
            logger.error(f"Connection error on POST /v1/mcp/servers: {e}")
            return None

    async def discover_tools(
        self, server_key: str, tools: list
    ) -> Optional[Dict[str, Any]]:
        """Registers/pins tool discovery items for an MCP server on the gateway."""
        payload = {"tools": tools}
        try:
            response = await self._request(
                "POST",
                f"/v1/mcp/servers/{server_key}/tools",
                json=payload,
                headers=self._headers(),
                timeout=5.0,
            )
            if response.status_code in (200, 201):
                return response.json()
            logger.error(
                f"POST /v1/mcp/servers/{server_key}/tools failed: {response.status_code} - {response.text}"
            )
            return None
        except Exception as e:
            logger.error(
                f"Connection error on POST /v1/mcp/servers/{server_key}/tools: {e}"
            )
            return None
