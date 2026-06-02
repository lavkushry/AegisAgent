#!/usr/bin/env python3
"""AegisAgent integrity demo (self-contained, no gateway/network required).

Demonstrates the three things that distinguish AegisAgent from a generic
tool-call gateway, using the real SDK primitives + an in-process fake gateway:

  1. Trust the source, not the text   -> deterministic provenance gate
  2. Make the approval trustworthy     -> approve-then-swap fails closed
  3. Prove it                          -> verifiable, tamper-evident receipts

Run:
    python3 examples/integrity_demo.py
"""

import sys
from pathlib import Path

# Allow running from a source checkout without installing.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk-python"))

from aegisagent import protect_tool, seal_chain, verify_chain  # noqa: E402
from aegisagent.decorator import _hash_tool_call  # noqa: E402

FUTURE = "2099-01-01T00:00:00Z"
UNTRUSTED = ("untrusted_external", "malicious_suspected")


class DemoGateway:
    """In-process stand-in for the Rust gateway. Encodes the same decisions the
    real Cedar policy pack makes, so the demo is faithful (not canned)."""

    def __init__(self, pinned_action_hash=None):
        # When set, every approval is bound to this hash, simulating an approval
        # that was granted for one specific, human-reviewed action.
        self._pinned = pinned_action_hash
        self._issued = {}

    def authorize(
        self,
        tool,
        action,
        parameters,
        resource=None,
        source_trust="unknown",
        contains_sensitive_data=False,
        run_id=None,
        trace_id=None,
    ):
        # (1) Deterministic provenance gate: an untrusted source may not drive a
        #     mutating action, regardless of how benign the text looks.
        if source_trust in UNTRUSTED:
            return {
                "decision": "deny",
                "reason": f"mutating action triggered by {source_trust} (provenance gate)",
            }

        # Otherwise the action is frozen and the approval is bound to its hash.
        bound_hash = self._pinned or _hash_tool_call(
            tool=tool,
            action=action,
            resource=resource,
            mutates_state=True,
            parameters=parameters,
        )
        approval_id = f"apr_{tool}_{action}"
        self._issued[approval_id] = bound_hash
        return {
            "decision": "require_approval",
            "reason": "high-risk action requires human approval",
            "approval": {
                "approval_id": approval_id,
                "approver_group": "platform-leads",
                "expires_at": FUTURE,
                "action_hash": bound_hash,
            },
        }

    def get_approval_status(self, approval_id):
        return {
            "status": "APPROVED",
            "action_hash": self._issued.get(approval_id, ""),
            "expires_at": FUTURE,
        }


def hr(title):
    print("\n" + "=" * 68 + f"\n {title}\n" + "=" * 68)


def scenario_provenance():
    hr("1. Trust the source, not the text")
    gw = DemoGateway()

    @protect_tool(gw, "github", "merge_pull_request",
                  default_source_trust="untrusted_external")
    def merge(pr_number, base_branch):
        return f"merged #{pr_number}"

    print("A coding agent read a malicious GitHub issue (untrusted_external) and")
    print("now tries to merge a PR. The text looks innocent...")
    try:
        merge(pr_number=482, base_branch="main")
        raise SystemExit("FAIL: untrusted mutation should have been denied")
    except PermissionError as exc:
        print(f"  -> BLOCKED (deterministic, not a text score): {exc}")


def scenario_legit_approval():
    hr("2a. A real approval executes the EXACT approved action")
    gw = DemoGateway()

    @protect_tool(gw, "github", "merge_pull_request",
                  default_source_trust="trusted_internal_signed")
    def merge(pr_number, base_branch):
        return f"merged #{pr_number}"

    print("Trusted trigger -> approval requested, bound to the exact action...")
    result = merge(pr_number=482, base_branch="main")
    print(f"  -> APPROVED + hash matches -> executed: {result!r}")
    assert result == "merged #482"


def scenario_approve_then_swap():
    hr("2b. Approve-then-swap is blocked (the approval is the differentiator)")
    # A human reviewed and approved a benign comment. The approval is bound to
    # THAT action's hash.
    benign_hash = _hash_tool_call(
        tool="github", action="comment_on_pr",
        resource="payments-service#482", mutates_state=True,
        parameters={"body": "LGTM, looks safe"},
    )
    gw = DemoGateway(pinned_action_hash=benign_hash)

    # The hijacked agent tries to execute a *merge* under that benign approval.
    @protect_tool(gw, "github", "merge_pull_request",
                  default_source_trust="trusted_internal_signed")
    def merge(pr_number, base_branch):
        return f"merged #{pr_number}"

    print("Approval was granted for a benign comment_on_pr.")
    print("The (hijacked) agent now tries to MERGE under that approval...")
    try:
        merge(pr_number=482, base_branch="main")
        raise SystemExit("FAIL: swapped action should have failed closed")
    except PermissionError as exc:
        print(f"  -> BLOCKED (executed hash != approved hash): {exc}")


def scenario_receipts():
    hr("3. Prove it: verifiable, tamper-evident receipts")
    chain = seal_chain([
        {"event_id": "r1", "ts": "2026-06-02T12:00:00Z", "tool": "github",
         "action": "merge_pull_request", "resource": "payments-service#482",
         "source_trust": "untrusted_external", "decision": "deny"},
        {"event_id": "r2", "ts": "2026-06-02T12:01:00Z", "tool": "github",
         "action": "merge_pull_request", "resource": "payments-service#482",
         "source_trust": "trusted_internal_signed", "decision": "rejected_on_swap",
         "approver": "platform-lead"},
    ])
    print(f"Sealed a {len(chain)}-receipt chain. verify_chain -> {verify_chain(chain)}")
    assert verify_chain(chain)

    print("Now tamper with a sealed receipt (flip a decision)...")
    chain[0]["decision"] = "allow"
    print(f"  -> verify_chain -> {verify_chain(chain)}  (tamper detected)")
    assert verify_chain(chain) is False
    print("\nAuditors verify independently:  aegis-verify-receipts <receipts.json>")


def main():
    print("AegisAgent — integrity layer demo")
    print("Make the approval trustworthy. Trust the source, not the text.")
    scenario_provenance()
    scenario_legit_approval()
    scenario_approve_then_swap()
    scenario_receipts()
    hr("All integrity guarantees held. ✅")


if __name__ == "__main__":
    main()
