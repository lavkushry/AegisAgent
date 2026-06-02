"""Verifiable action-receipt format + hash-chain reference verifier.

Locks the receipt format so the gateway (Rust) can emit byte-compatible
receipts and auditors can verify them independently. See
docs/action-receipt-spec.md.
"""

import unittest

from aegisagent.receipts import (
    GENESIS_PREV,
    compute_receipt_hash,
    seal_chain,
    seal_receipt,
    verify_chain,
    verify_receipt,
)


def _receipt(decision: str, resource: str, action_hash: str) -> dict:
    return {
        "event_id": f"rcpt_{resource}",
        "ts": "2026-06-02T12:00:00Z",
        "agent_id": "coding-agent-prod",
        "user_id": "lavkush",
        "tool": "github",
        "action": "merge_pull_request",
        "resource": resource,
        "source_trust": "untrusted_external",
        "decision": decision,
        "approver": "platform-lead",
        "action_hash": action_hash,
    }


class TestReceiptChain(unittest.TestCase):
    def test_sealed_receipt_verifies(self):
        sealed = seal_receipt(_receipt("require_approval", "svc#1", "a" * 64))
        self.assertTrue(verify_receipt(sealed))
        self.assertEqual(sealed["prev_receipt_hash"], GENESIS_PREV)
        self.assertEqual(len(sealed["receipt_hash"]), 64)

    def test_chain_verifies_and_links(self):
        chain = seal_chain(
            [
                _receipt("require_approval", "svc#1", "a" * 64),
                _receipt("rejected_on_swap", "svc#1", "b" * 64),
                _receipt("allow", "svc#2", "c" * 64),
            ]
        )
        self.assertTrue(verify_chain(chain))
        # Each link references the previous receipt's hash.
        self.assertEqual(chain[1]["prev_receipt_hash"], chain[0]["receipt_hash"])
        self.assertEqual(chain[2]["prev_receipt_hash"], chain[1]["receipt_hash"])

    def test_tampered_field_is_detected(self):
        chain = seal_chain(
            [
                _receipt("require_approval", "svc#1", "a" * 64),
                _receipt("allow", "svc#2", "c" * 64),
            ]
        )
        # Flip the recorded decision after sealing.
        chain[1]["decision"] = "deny"
        self.assertFalse(verify_receipt(chain[1]))
        self.assertFalse(verify_chain(chain))

    def test_broken_link_is_detected(self):
        chain = seal_chain(
            [
                _receipt("require_approval", "svc#1", "a" * 64),
                _receipt("allow", "svc#2", "c" * 64),
            ]
        )
        # Re-point the second receipt's prev link without re-sealing.
        chain[1]["prev_receipt_hash"] = "0" * 64
        self.assertFalse(verify_chain(chain))

    def test_reordered_chain_is_detected(self):
        chain = seal_chain(
            [
                _receipt("require_approval", "svc#1", "a" * 64),
                _receipt("allow", "svc#2", "c" * 64),
            ]
        )
        self.assertFalse(verify_chain(list(reversed(chain))))

    def test_missing_hash_fails_closed(self):
        body = _receipt("allow", "svc#1", "a" * 64)
        self.assertFalse(verify_receipt(body))  # no receipt_hash field

    def test_non_ascii_receipt_roundtrips(self):
        r = _receipt("allow", "Café ☕ #1", "a" * 64)
        r["note"] = "déjà vu ☕"
        sealed = seal_receipt(r)
        self.assertTrue(verify_receipt(sealed))
        # Recompute is stable for non-ASCII content (canonicalization is raw UTF-8).
        self.assertEqual(compute_receipt_hash(sealed), sealed["receipt_hash"])

    def test_seal_does_not_mutate_input(self):
        original = _receipt("allow", "svc#1", "a" * 64)
        snapshot = dict(original)
        seal_receipt(original)
        self.assertEqual(original, snapshot)


if __name__ == "__main__":
    unittest.main()
