"""SDK-side approval expiry enforcement.

The SDK is part of the trust boundary (it performs the final fail-closed
action_hash check), so it must also refuse to act on a stale approval: even an
APPROVED decision with a matching hash must NOT execute once expires_at has
passed. This closes the stale-approval window at the last step. A paired
gateway-side check is recommended as defense-in-depth.
"""

import unittest
from unittest.mock import MagicMock, patch

from aegisagent import AegisClient, protect_tool
from aegisagent.decorator import _hash_tool_call

_PAST = "2000-01-01T00:00:00Z"
_FUTURE = "2099-01-01T00:00:00Z"


def _approval_response(action_hash: str, expires_at: str) -> dict:
    return {
        "decision": "require_approval",
        "reason": "Approval required",
        "approval": {
            "approval_id": "89cf8b98-2103-4458-8210-344589cf8b98",
            "status": "created",
            "approver_group": "platform-leads",
            "expires_at": expires_at,
            "action_hash": action_hash,
        },
    }


class TestApprovalExpiry(unittest.TestCase):
    def setUp(self) -> None:
        self.client = AegisClient(
            api_key="test_key", agent_id="test_agent", endpoint="http://127.0.0.1:8080"
        )
        self.client.agent_token = "mock_agent_token"

    @patch("time.sleep", return_value=None)
    @patch("requests.get")
    @patch("requests.post")
    def test_approved_but_expired_fails_closed(self, mock_post, mock_get, _sleep):
        correct_hash = _hash_tool_call(
            tool="test_tool",
            action="test_action",
            resource=None,
            mutates_state=True,
            parameters={"param1": "hello"},
        )

        auth = MagicMock()
        auth.status_code = 200
        auth.json.return_value = _approval_response(correct_hash, _PAST)
        mock_post.return_value = auth

        status = MagicMock()
        status.status_code = 200
        # APPROVED, hash matches, but the approval window has already passed.
        status.json.return_value = {
            "status": "APPROVED",
            "action_hash": correct_hash,
            "expires_at": _PAST,
        }
        mock_get.return_value = status

        executed = {"ran": False}

        @protect_tool(self.client, tool="test_tool", action="test_action")
        def my_test_func(param1):
            executed["ran"] = True
            return f"executed_{param1}"

        with self.assertRaises(PermissionError):
            my_test_func("hello")
        self.assertFalse(executed["ran"], "expired approval must not execute the tool")

    @patch("time.sleep", return_value=None)
    @patch("requests.get")
    @patch("requests.post")
    def test_approved_within_window_still_executes(self, mock_post, mock_get, _sleep):
        correct_hash = _hash_tool_call(
            tool="test_tool",
            action="test_action",
            resource=None,
            mutates_state=True,
            parameters={"param1": "hello"},
        )
        auth = MagicMock()
        auth.status_code = 200
        auth.json.return_value = _approval_response(correct_hash, _FUTURE)
        consume = MagicMock()
        consume.status_code = 200
        consume.json.return_value = {"status": "consumed", "action_hash": correct_hash}
        # POST calls happen in order: authorize, then consume.
        mock_post.side_effect = [auth, consume]
        status = MagicMock()
        status.status_code = 200
        status.json.return_value = {
            "status": "APPROVED",
            "action_hash": correct_hash,
            "expires_at": _FUTURE,
        }
        mock_get.return_value = status

        @protect_tool(self.client, tool="test_tool", action="test_action")
        def my_test_func(param1):
            return f"executed_{param1}"

        self.assertEqual(my_test_func("hello"), "executed_hello")

    @patch("time.sleep", return_value=None)
    @patch("requests.get")
    @patch("requests.post")
    def test_approved_but_not_consumable_fails_closed(self, mock_post, mock_get, _sleep):
        # Single-use: if the approval is APPROVED with a matching hash but the
        # gateway refuses to consume it (already used / expired -> 409), the SDK
        # must fail closed instead of executing.
        correct_hash = _hash_tool_call(
            tool="test_tool",
            action="test_action",
            resource=None,
            mutates_state=True,
            parameters={"param1": "hello"},
        )
        auth = MagicMock()
        auth.status_code = 200
        auth.json.return_value = _approval_response(correct_hash, _FUTURE)
        consume = MagicMock()
        consume.status_code = 409  # already consumed / not consumable
        mock_post.side_effect = [auth, consume]
        status = MagicMock()
        status.status_code = 200
        status.json.return_value = {
            "status": "APPROVED",
            "action_hash": correct_hash,
            "expires_at": _FUTURE,
        }
        mock_get.return_value = status

        executed = {"ran": False}

        @protect_tool(self.client, tool="test_tool", action="test_action")
        def my_test_func(param1):
            executed["ran"] = True
            return f"executed_{param1}"

        with self.assertRaises(PermissionError):
            my_test_func("hello")
        self.assertFalse(executed["ran"], "unconsumable approval must not execute")

    def test_expiry_helpers(self):
        from aegisagent.decorator import _approval_expired, _parse_rfc3339

        self.assertTrue(_approval_expired(_PAST))
        self.assertFalse(_approval_expired(_FUTURE))
        # Unparseable / missing -> graceful (rely on poll timeout), do not crash.
        self.assertFalse(_approval_expired(None))
        self.assertFalse(_approval_expired("not-a-date"))
        # chrono may emit up to 9 fractional digits and a trailing Z.
        self.assertIsNotNone(_parse_rfc3339("2026-06-02T17:36:00.123456789Z"))
        self.assertIsNotNone(_parse_rfc3339("2026-06-02T17:36:00Z"))


if __name__ == "__main__":
    unittest.main()
