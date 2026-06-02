import logging
import threading
import time
import requests
from aegisagent import AegisClient, protect_tool, set_context_trust_level

# Configure logging to console
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("mock_integration")

# Initialize AegisClient for developer tenant "tenant_123"
GATEWAY_URL = "http://127.0.0.1:8080"
client = AegisClient(
    api_key="tenant_123",
    agent_id="coding-agent-prod",
    environment="production",
    endpoint=GATEWAY_URL,
)


# Define a mock tool representing the protected GitHub merge action
# We use the protect_tool decorator to gate it
@protect_tool(
    client=client,
    tool="github",
    action="merge_pull_request",
    resource_extractor=lambda repo, pr_number, base_branch="main": f"repo/{repo}/pull/{pr_number}",
)
def merge_pull_request(repo: str, pr_number: int, base_branch: str = "main"):
    logger.info(
        f"🚀 Executing merge_pull_request on repo={repo}, PR={pr_number}, branch={base_branch}"
    )
    return {"status": "success", "merged_sha": "sha256_mocked_merge_commit_sha"}


def simulate_human_approval(approval_id: str, action: str = "approve"):
    """Simulates a human reviewer approving or rejecting the pending action on the gateway after a delay."""
    time.sleep(3)  # Wait for agent to pause
    url = f"{GATEWAY_URL}/v1/approvals/{approval_id}/{action}"
    headers = {"Authorization": "Bearer tenant_123", "Content-Type": "application/json"}
    payload = {
        "approver_user_id": "reviewing_engineer_saket",
        "reason": f"PR code reviewed, tests passed. Simulating {action}.",
    }
    try:
        logger.info(
            f"👤 Reviewer: Sending {action.upper()} request for approval ID {approval_id}..."
        )
        response = requests.post(url, json=payload, headers=headers, timeout=5)
        if response.status_code == 200:
            logger.info(f"👤 Reviewer: Approval updated successfully.")
        else:
            logger.error(f"👤 Reviewer: Failed to update approval: {response.text}")
    except Exception as e:
        logger.error(f"👤 Reviewer: Error communicating with gateway: {e}")


def run_test_scenario():
    logger.info("=========================================")
    logger.info("Initializing AegisAgent Mock Integration")
    logger.info("=========================================")

    # 1. Register the agent
    logger.info("1. Registering agent with gateway...")
    if not client.register_agent(
        agent_name="Production Coding Agent", owner_team="platform"
    ):
        logger.error(
            "Failed to register agent. Make sure the gateway is running on port 8080."
        )
        return

    # 2. Register the tool actions on the gateway database
    logger.info("2. Registering github.merge_pull_request tool on gateway...")
    headers = {"Authorization": "Bearer tenant_123", "Content-Type": "application/json"}
    tool_payload = {
        "skill_key": "github",
        "name": "GitHub Client",
        "type": "static",
        "owner_team": "platform",
        "actions": [
            {
                "action_key": "merge_pull_request",
                "description": "Merge a pull request into base branch",
                "risk": "high",
                "mutates_state": True,
                "approval_required": True,
                "default_decision": "policy",
            }
        ],
    }
    try:
        resp = requests.post(
            f"{GATEWAY_URL}/v1/tools", json=tool_payload, headers=headers, timeout=5
        )
        if resp.status_code != 200:
            logger.error(f"Failed to register tool actions: {resp.text}")
            return
        logger.info("Tool actions registered successfully.")
    except Exception as e:
        logger.error(f"Failed to connect to gateway to register tools: {e}")
        return

    # 3. Test Scenario A: Deny outright for untrusted external context
    logger.info("\n=== Scenario A: Attempt Merge under UNTRUSTED Context ===")
    set_context_trust_level("untrusted_external")
    logger.info(
        "Context trust level set to: 'untrusted_external' (e.g. following public GitHub issue input)."
    )
    try:
        merge_pull_request(repo="payments-service", pr_number=482, base_branch="main")
        logger.error("❌ Test Fail: Action should have been denied.")
    except PermissionError as e:
        logger.info(
            f"✅ Test Pass: Action successfully blocked by AegisAgent. Error: {e}"
        )

    # 4. Test Scenario B: Pause & Approve for semi-trusted customer context
    logger.info("\n=== Scenario B: Attempt Merge under SEMI-TRUSTED Context ===")
    set_context_trust_level("semi_trusted_customer")
    logger.info(
        "Context trust level set to: 'semi_trusted_customer' (e.g. following customer comment)."
    )

    # We must start the human approval simulation in a separate thread so it fires while the main thread is blocked
    # First, we need the approval ID. Since the main thread will block, we poll for the pending approval.
    # To get the approval ID, we can intercept the call.
    # In this mock, we know that when the agent attempts authorization, it creates the approval.
    # We will fetch the pending approval from the gateway after the call starts.
    def approval_helper():
        time.sleep(1)  # wait for the request to register
        try:
            resp = requests.get(
                f"{GATEWAY_URL}/v1/audit/events", headers=headers, timeout=5
            )
            if resp.status_code == 200:
                events = resp.json()
                # Find the most recent approval_created event
                for event in events:
                    if event.get("event_type") == "approval_created":
                        import json

                        evt_data = json.loads(event.get("event_json", "{}"))
                        approval_id = evt_data.get("id")
                        if approval_id:
                            simulate_human_approval(approval_id, "approve")
                            return
            logger.error("Could not find created approval request in audit logs.")
        except Exception as e:
            logger.error(f"Error in approval helper: {e}")

    threading.Thread(target=approval_helper, daemon=True).start()

    try:
        result = merge_pull_request(
            repo="payments-service", pr_number=482, base_branch="main"
        )
        logger.info(
            f"✅ Test Pass: Action successfully approved and executed! Result: {result}"
        )
    except Exception as e:
        logger.error(f"❌ Test Fail: Action was not approved or failed with: {e}")

    # 5. Fetch final timeline
    logger.info("\n=== Scenario C: Querying Audit Timeline ===")
    try:
        resp = requests.get(
            f"{GATEWAY_URL}/v1/audit/events", headers=headers, timeout=5
        )
        if resp.status_code == 200:
            events = resp.json()
            logger.info(f"Timeline retrieved. Total events: {len(events)}")
            for event in reversed(events[:5]):  # show last 5 events
                logger.info(
                    f"  - [{event.get('created_at')}] Event: {event.get('event_type')} for action: {event.get('action')}"
                )
        else:
            logger.error(f"Failed to query audit timeline: {resp.text}")
    except Exception as e:
        logger.error(f"Error querying audit: {e}")


if __name__ == "__main__":
    run_test_scenario()
