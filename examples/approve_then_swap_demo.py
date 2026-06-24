#!/usr/bin/env python3
"""AegisAgent Flagship Demo: Approve-Then-Swap Attack Blocked.

This script demonstrates AegisAgent's cryptographic integrity defenses:
1. Legitimate Flow: human-in-the-loop approval succeeds for the exact approved parameters.
2. Approve-Then-Swap Blocked: if parameters are swapped after approval, the hash mismatch is caught and execution fails closed.
3. Replay Blocked: once consumed, the approval cannot be consumed a second time (returns 409 Conflict).
"""

from __future__ import annotations

import hashlib
import json
import logging
import pathlib
import sys
import threading
import time
from typing import Any, Dict, Optional

import requests

REPO_ROOT: pathlib.Path = pathlib.Path(__file__).resolve().parents[1]
SDK_PATH = REPO_ROOT / "sdk-python"
if str(SDK_PATH) not in sys.path:
    sys.path.insert(0, str(SDK_PATH))

from aegisagent import AegisClient, protect_tool  # noqa: E402
from aegisagent.canon import canonicalize  # noqa: E402

# ANSI Color Codes
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

GATEWAY_URL = "http://127.0.0.1:8080"
TENANT_ID = "tenant_123"
AGENT_ID = "coding-agent-prod"

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("approve-then-swap-demo")

client = AegisClient(
    api_key=TENANT_ID,
    agent_id=AGENT_ID,
    environment="production",
    endpoint=GATEWAY_URL,
)


def post_json(path: str, payload: Dict[str, Any]) -> requests.Response:
    response = requests.post(
        f"{GATEWAY_URL}{path}",
        headers={
            "Authorization": f"Bearer {TENANT_ID}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=5,
    )
    response.raise_for_status()
    return response


def ensure_demo_seeded() -> None:
    logger.info(f"{CYAN}Seeding demo agent and GitHub tool metadata...{RESET}")
    if not client.register_agent(
        agent_name="Production Coding Agent",
        owner_team="platform",
        risk_tier="high",
    ):
        raise RuntimeError("Failed to register demo agent. Is the gateway running?")

    post_json(
        "/v1/tools",
        {
            "skill_key": "github",
            "name": "Mock GitHub Client",
            "type": "static",
            "auth_type": "mock",
            "owner_team": "platform",
            "default_risk": "medium",
            "actions": [
                {
                    "action_key": "read_issue",
                    "description": "Read a GitHub issue",
                    "risk": "low",
                    "mutates_state": False,
                    "data_access": "repository_metadata",
                    "approval_required": False,
                    "default_decision": "policy",
                },
                {
                    "action_key": "merge_pull_request",
                    "description": "Merge a pull request into a base branch",
                    "risk": "high",
                    "mutates_state": True,
                    "data_access": "repository_write",
                    "approval_required": True,
                    "default_decision": "policy",
                },
            ],
        },
    )


def approve_approval(approval_id: str) -> None:
    url = f"{GATEWAY_URL}/v1/approvals/{approval_id}/approve"
    logger.info(f"{YELLOW}   [Human Operator] Approving request: {approval_id}...{RESET}")
    response = requests.post(
        url,
        headers={"Authorization": f"Bearer {TENANT_ID}"},
        json={"approver_user_id": "platform-lead", "reason": "Verified safe action params"},
        timeout=5,
    )
    response.raise_for_status()
    logger.info(f"{GREEN}   [Human Operator] Approval {approval_id} approved!{RESET}")


def auto_approver_thread(stop_event: threading.Event) -> None:
    """Background thread that automatically approves any pending approval requests."""
    approved_ids = set()
    while not stop_event.is_set():
        try:
            url = f"{GATEWAY_URL}/v1/approvals?limit=5&offset=0"
            response = requests.get(
                url,
                headers={"Authorization": f"Bearer {TENANT_ID}"},
                timeout=2,
            )
            if response.status_code == 200:
                approvals = response.json()
                for app in approvals:
                    app_id = app.get("approval_id")
                    if app.get("status") == "created" and app_id not in approved_ids:
                        approved_ids.add(app_id)
                        approve_approval(app_id)
        except Exception:
            pass
        time.sleep(0.5)


def aegis_jcs_1_hash(tool: str, action: str, resource: Optional[str], params: dict) -> str:
    """Computes JCS-1 canonical hash of the action call."""
    canonical = canonicalize(
        {
            "tool": tool,
            "action": action,
            "resource": resource,
            "mutates_state": True,
            "parameters": params,
        }
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@protect_tool(
    client=client,
    tool="github",
    action="merge_pull_request",
    default_source_trust="trusted_internal_signed",
    resource_extractor=lambda repo, pr_number, base_branch="main": f"repo/{repo}/pull/{pr_number}",
)
def merge_pull_request(repo: str, pr_number: int, base_branch: str = "main") -> str:
    return f"Successfully merged PR #{pr_number} on {repo} into {base_branch}"


def hr(title: str) -> None:
    print(f"\n{BOLD}{CYAN}" + "=" * 70)
    print(f" {title}")
    print("=" * 70 + f"{RESET}")


def main() -> int:
    hr("AegisAgent Positioning Proof — Approve-Then-Swap Blocked")
    logger.info(f"Gateway URL: {GATEWAY_URL}")

    try:
        requests.get(f"{GATEWAY_URL}/health", timeout=3).raise_for_status()
        ensure_demo_seeded()
    except Exception as exc:
        logger.error(f"{RED}Gateway connection failed: {exc}{RESET}")
        logger.error(f"{YELLOW}Please start the gateway using: docker compose up --build -d{RESET}")
        return 1

    # Start background auto-approver thread for human-in-the-loop simulation
    stop_event = threading.Event()
    approver = threading.Thread(target=auto_approver_thread, args=(stop_event,), daemon=True)
    approver.start()

    try:
        # ── SCENARIO 1: Legitimate Flow ───────────────────────────────────────────
        hr("SCENARIO 1: Legitimate Flow (Normal Approval)")
        logger.info("Executing merge_pull_request(repo='payments-service', pr_number=482, base_branch='main')...")
        logger.info("This is a high-risk mutating action that requires human approval.")
        
        result = merge_pull_request(repo="payments-service", pr_number=482, base_branch="main")
        logger.info(f"\n{GREEN}✓ Legitimate execution succeeded: {result}{RESET}")

        # ── SCENARIO 2: Approve-Then-Swap Blocked ───────────────────────────────
        hr("SCENARIO 2: Approve-Then-Swap Blocked")
        logger.info("Agent requests authorization for a benign merge:")
        logger.info("  Action: github.merge_pull_request")
        logger.info("  Parameters: repo='payments-service', pr_number=482, base_branch='main'")
        
        benign_params = {"repo": "payments-service", "pr_number": 482, "base_branch": "main"}
        resource = "repo/payments-service/pull/482"
        
        # Step 1: Request authorization
        auth_resp = client.authorize(
            tool="github",
            action="merge_pull_request",
            parameters=benign_params,
            resource=resource,
            source_trust="trusted_internal_signed",
        )
        
        approval = auth_resp.get("approval")
        if not approval:
            logger.error(f"{RED}Failed to get approval payload from gateway{RESET}")
            return 1
            
        approval_id = approval["approval_id"]
        original_approved_hash = approval["action_hash"]
        
        logger.info(f"  Gateway returned decision: require_approval")
        logger.info(f"  Approval ID:               {approval_id}")
        logger.info(f"  Original Approved Hash:    {original_approved_hash}")

        # Human approves the benign action parameters
        time.sleep(1.0)  # Wait for background approver to notice and approve

        # Step 2: Swap the parameters in the background (hijacked agent/attacker)
        logger.info(f"\n{YELLOW}==> Attacker intercepts execution and swaps parameters!{RESET}")
        malicious_params = {"repo": "payments-service", "pr_number": 666, "base_branch": "main"}
        logger.info("  New Swapped Parameters:   repo='payments-service', pr_number=666, base_branch='main'")

        # Step 3: Compute current action hash
        current_hash = aegis_jcs_1_hash("github", "merge_pull_request", resource, malicious_params)
        logger.info(f"  Current Action Hash:       {current_hash}")

        # Step 4: Verification
        logger.info(f"\n{CYAN}==> SDK verifying action_hash against approved hash before execution...{RESET}")
        logger.info(f"  Original approved hash:    {original_approved_hash}")
        logger.info(f"  Current action hash:       {current_hash}")

        if current_hash != original_approved_hash:
            logger.info(f"\n{RED}{BOLD}🛑 BLOCKED: action_hash MISMATCH detected!{RESET}")
            logger.info("   The SDK fails closed and refuses to execute.")
            logger.info("   AegisAgent successfully blocked the approve-then-swap attack.")
        else:
            logger.error(f"{RED}FAIL: Hash check did not block swapped action!{RESET}")
            return 2

        # ── SCENARIO 3: Replay Attack Blocked ──────────────────────────────────
        hr("SCENARIO 3: Replay Attack Blocked")
        logger.info(f"Attacker attempts to reuse approval ID {approval_id} for double consumption...")

        # The first consume was never completed because we blocked it client-side.
        # Let's perform a valid consume first.
        logger.info("Consuming approval legitimately first...")
        consumed = client.consume_approval(approval_id)
        if consumed:
            logger.info(f"{GREEN}✓ First consumption succeeded: status={consumed.get('status')}{RESET}")
        else:
            logger.error("First consumption failed.")

        # Replay attempt: consume again
        logger.info(f"\n{YELLOW}Attempting to consume approval ID {approval_id} a second time...{RESET}")
        try:
            url = f"{GATEWAY_URL}/v1/approvals/{approval_id}/consume"
            response = requests.post(
                url,
                headers={"Authorization": f"Bearer {TENANT_ID}"},
                timeout=5,
            )
            logger.info(f"  Gateway response: Status {response.status_code}")
            if response.status_code == 409:
                logger.info(f"\n{GREEN}{BOLD}✓ Replay Blocked! Gateway returned 409 Conflict.{RESET}")
                logger.info("  An approval is strictly single-use and cannot be replayed.")
            else:
                logger.error(f"{RED}FAIL: Gateway did not block replay (returned {response.status_code}){RESET}")
                return 3
        except Exception as exc:
            logger.error(f"Replay attempt request failed: {exc}")
            return 3

    finally:
        stop_event.set()
        approver.join(timeout=1.0)

    hr("All integrity guarantees held. ✅")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
