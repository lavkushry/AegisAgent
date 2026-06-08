"""Tests for webhook callbacks (TASK-0183, TASK-0184) and gateway test confirmations.

Covers:
- TASK-0183: Slack callback signature verification
- TASK-0184: Webhook callback handler for approval decisions
- TASK-0185: Type hints exist on public API methods
- Gateway test confirmations (already passing in cargo test):
  - TASK-0139 (#985): freeze_agent sets status to frozen
  - TASK-0140 (#986): unfreeze_agent restores to active
  - TASK-0141 (#987): revoke_agent sets status to revoked
  - TASK-0142 (#988): quarantine_mcp_server
  - TASK-0143 (#989): tenant isolation — agent
  - TASK-0144 (#990): tenant isolation — decision
  - TASK-0145 (#991): tenant isolation — approval
  - TASK-0146 (#992): tenant isolation — receipt
  - TASK-0147 (#993): MCP tool defaults to pending
  - TASK-0148 (#994): MCP tool status tenant-scoped
  - TASK-0149 (#995): MCP unknown tool denial
  - TASK-0150 (#996): approval expiry detection
"""

import hashlib
import hmac
import inspect
import json
import time
import unittest

from aegisagent.webhooks import WebhookHandler, verify_slack_signature


def _make_signature(body: bytes, timestamp: str, secret: str) -> str:
    """Create a valid Slack-style v0 signature."""
    sig_base = f"v0:{timestamp}:{body.decode('utf-8', errors='replace')}"
    sig = hmac.new(
        secret.encode("utf-8"),
        sig_base.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"v0={sig}"


class TestSlackSignatureVerification(unittest.TestCase):
    """TASK-0183: Slack callback signature verification."""

    def test_valid_signature_accepted(self):
        secret = "whsec_test_secret_12345"
        body = b'{"status":"APPROVED","approval_id":"a1"}'
        ts = str(int(time.time()))
        sig = _make_signature(body, ts, secret)
        self.assertTrue(verify_slack_signature(body, ts, sig, secret))

    def test_invalid_signature_rejected(self):
        secret = "whsec_test_secret_12345"
        body = b'{"status":"APPROVED"}'
        ts = str(int(time.time()))
        sig = "v0=0000000000000000000000000000000000000000000000000000000000000000"
        self.assertFalse(verify_slack_signature(body, ts, sig, secret))

    def test_expired_timestamp_rejected(self):
        secret = "whsec_test_secret_12345"
        body = b'{"status":"APPROVED"}'
        old_ts = str(int(time.time()) - 600)  # 10 minutes ago
        sig = _make_signature(body, old_ts, secret)
        self.assertFalse(verify_slack_signature(body, old_ts, sig, secret))

    def test_missing_params_rejected(self):
        self.assertFalse(verify_slack_signature(None, "", "", ""))
        self.assertFalse(verify_slack_signature(b"body", "", "sig", "secret"))

    def test_invalid_timestamp_rejected(self):
        self.assertFalse(
            verify_slack_signature(b"body", "not_a_number", "sig", "secret")
        )

    def test_tampered_body_rejected(self):
        secret = "whsec_test_secret_12345"
        body = b'{"status":"APPROVED"}'
        ts = str(int(time.time()))
        sig = _make_signature(body, ts, secret)
        # Tamper the body
        tampered = b'{"status":"REJECTED"}'
        self.assertFalse(verify_slack_signature(tampered, ts, sig, secret))


class TestWebhookHandler(unittest.TestCase):
    """TASK-0184: Webhook callback for approval decisions."""

    def test_approved_handler_called(self):
        handler = WebhookHandler()
        results = []
        handler.on_approved(lambda p: results.append(p))

        payload = {"status": "APPROVED", "approval_id": "a1"}
        body = json.dumps(payload).encode()
        result = handler.handle(body)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["approval_id"], "a1")

    def test_rejected_handler_called(self):
        handler = WebhookHandler()
        results = []
        handler.on_rejected(lambda p: results.append(p))

        payload = {"status": "REJECTED", "approval_id": "a2"}
        body = json.dumps(payload).encode()
        handler.handle(body)

        self.assertEqual(len(results), 1)

    def test_edited_handler_called(self):
        handler = WebhookHandler()
        results = []
        handler.on_edited(lambda p: results.append(p))

        payload = {"status": "EDITED", "edited_parameters": {"env": "staging"}}
        body = json.dumps(payload).encode()
        handler.handle(body)

        self.assertEqual(len(results), 1)

    def test_expired_handler_called(self):
        handler = WebhookHandler()
        results = []
        handler.on_expired(lambda p: results.append(p))

        payload = {"status": "EXPIRED", "approval_id": "a3"}
        body = json.dumps(payload).encode()
        handler.handle(body)

        self.assertEqual(len(results), 1)

    def test_unknown_status_no_error(self):
        handler = WebhookHandler()
        payload = {"status": "UNKNOWN_STATUS"}
        body = json.dumps(payload).encode()
        # Should not raise
        handler.handle(body)

    def test_missing_status_raises(self):
        handler = WebhookHandler()
        body = json.dumps({"approval_id": "a1"}).encode()
        with self.assertRaises(ValueError):
            handler.handle(body)

    def test_invalid_json_raises(self):
        handler = WebhookHandler()
        with self.assertRaises(ValueError):
            handler.handle(b"not valid json")

    def test_signature_required_when_configured(self):
        handler = WebhookHandler(signing_secret="secret")
        body = json.dumps({"status": "APPROVED"}).encode()
        with self.assertRaises(PermissionError):
            handler.handle(body)

    def test_valid_signature_dispatches(self):
        secret = "whsec_test_secret"
        handler = WebhookHandler(signing_secret=secret)
        results = []
        handler.on_approved(lambda p: results.append(p))

        payload = {"status": "APPROVED", "id": "a1"}
        body = json.dumps(payload).encode()
        ts = str(int(time.time()))
        sig = _make_signature(body, ts, secret)

        handler.handle(body, timestamp=ts, signature=sig)
        self.assertEqual(len(results), 1)

    def test_invalid_signature_raises(self):
        handler = WebhookHandler(signing_secret="secret")
        body = json.dumps({"status": "APPROVED"}).encode()
        ts = str(int(time.time()))
        with self.assertRaises(PermissionError):
            handler.handle(body, timestamp=ts, signature="v0=bad")

    def test_repr(self):
        handler = WebhookHandler()
        handler.on_approved(lambda p: None)
        self.assertIn("APPROVED", repr(handler))

    def test_multiple_handlers_all_called(self):
        handler = WebhookHandler()
        results = []
        handler.on_approved(lambda p: results.append("first"))
        handler.on_approved(lambda p: results.append("second"))

        body = json.dumps({"status": "APPROVED"}).encode()
        handler.handle(body)
        self.assertEqual(results, ["first", "second"])


class TestTypeHints(unittest.TestCase):
    """TASK-0185: Type hints exist on all public API methods."""

    def test_aegis_client_methods_have_annotations(self):
        from aegisagent.client import AegisClient

        public_methods = [
            m
            for m in dir(AegisClient)
            if not m.startswith("_") and callable(getattr(AegisClient, m))
        ]
        for method_name in public_methods:
            method = getattr(AegisClient, method_name)
            sig = inspect.signature(method)
            # Every public method should have a return annotation
            self.assertIsNot(
                sig.return_annotation,
                inspect.Parameter.empty,
                f"AegisClient.{method_name} missing return type annotation",
            )

    def test_aegis_async_client_methods_have_annotations(self):
        from aegisagent.client import AegisAsyncClient

        public_methods = [
            m
            for m in dir(AegisAsyncClient)
            if not m.startswith("_") and callable(getattr(AegisAsyncClient, m))
        ]
        for method_name in public_methods:
            method = getattr(AegisAsyncClient, method_name)
            sig = inspect.signature(method)
            self.assertIsNot(
                sig.return_annotation,
                inspect.Parameter.empty,
                f"AegisAsyncClient.{method_name} missing return type annotation",
            )


if __name__ == "__main__":
    unittest.main()
