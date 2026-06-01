import unittest
from unittest.mock import MagicMock, patch

from aegisagent import (
    AegisClient,
    get_context_trust_level,
    protect_tool,
    set_context_trust_level,
)
from aegisagent.decorator import _hash_tool_call


class TestAegisSDK(unittest.TestCase):
    def setUp(self):
        self.client = AegisClient(
            api_key="test_key", agent_id="test_agent", endpoint="http://127.0.0.1:8080"
        )
        self.client.agent_token = "mock_agent_token"

    def test_trust_context_management(self):
        set_context_trust_level("trusted_internal_signed")
        self.assertEqual(get_context_trust_level(), "trusted_internal_signed")
        set_context_trust_level("unknown")
        self.assertEqual(get_context_trust_level(), "unknown")

    @patch("requests.post")
    def test_authorize_allow(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "decision": "allow",
            "reason": "Permitted by policy",
        }
        mock_post.return_value = mock_response

        @protect_tool(self.client, tool="test_tool", action="test_action")
        def my_test_func(param1):
            return f"executed_{param1}"

        result = my_test_func("hello")
        self.assertEqual(result, "executed_hello")
        mock_post.assert_called_once()
        self.assertEqual(
            mock_post.call_args.kwargs["headers"]["X-Aegis-Tenant-ID"], "tenant_123"
        )

    @patch("requests.post")
    def test_authorize_deny(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "decision": "deny",
            "reason": "Forbidden by policy",
        }
        mock_post.return_value = mock_response

        @protect_tool(self.client, tool="test_tool", action="test_action")
        def my_test_func(param1):
            return f"executed_{param1}"

        with self.assertRaises(PermissionError):
            my_test_func("hello")
        mock_post.assert_called_once()

    @patch("time.sleep", return_value=None)
    @patch("requests.get")
    @patch("requests.post")
    def test_approval_hash_mismatch_fails_closed(
        self, mock_post, mock_get, _mock_sleep
    ):
        mock_auth_resp = MagicMock()
        mock_auth_resp.status_code = 200
        mock_auth_resp.json.return_value = {
            "decision": "require_approval",
            "reason": "Approval required",
            "approval": {
                "approval_id": "89cf8b98-2103-4458-8210-344589cf8b98",
                "status": "created",
                "approver_group": "platform-leads",
                "expires_at": "2026-06-01T14:18:27Z",
                "action_hash": "0" * 64,
            },
        }
        mock_post.return_value = mock_auth_resp

        mock_status_resp = MagicMock()
        mock_status_resp.status_code = 200
        mock_status_resp.json.return_value = {
            "status": "APPROVED",
            "action_hash": "0" * 64,
        }
        mock_get.return_value = mock_status_resp

        @protect_tool(self.client, tool="test_tool", action="test_action")
        def my_test_func(param1):
            return f"executed_{param1}"

        with self.assertRaises(PermissionError):
            my_test_func("hello")

    @patch("requests.get")
    @patch("requests.post")
    def test_authorize_edited_approval(self, mock_post, mock_get):
        expected_hash = _hash_tool_call(
            tool="test_tool",
            action="test_action",
            resource=None,
            mutates_state=True,
            parameters={"param1": "original_value"},
        )

        # 1. First authorize call returns require_approval
        mock_auth_resp = MagicMock()
        mock_auth_resp.status_code = 200
        mock_auth_resp.json.return_value = {
            "decision": "require_approval",
            "reason": "Approval required",
            "approval": {
                "approval_id": "89cf8b98-2103-4458-8210-344589cf8b98",
                "status": "created",
                "approver_group": "platform-leads",
                "expires_at": "2026-06-01T14:18:27Z",
                "action_hash": expected_hash,
            },
        }
        mock_post.return_value = mock_auth_resp

        # 2. Get approval status call returns EDITED status with modified parameters
        mock_status_resp = MagicMock()
        mock_status_resp.status_code = 200
        mock_status_resp.json.return_value = {
            "status": "EDITED",
            "action_hash": expected_hash,
            "edited_tool_call": {"parameters": {"param1": "edited_value"}},
        }
        mock_get.return_value = mock_status_resp

        @protect_tool(self.client, tool="test_tool", action="test_action")
        def my_test_func(param1):
            return f"executed_{param1}"

        # Execute, should run with 'edited_value' and return 'executed_edited_value'
        result = my_test_func("original_value")
        self.assertEqual(result, "executed_edited_value")
        mock_post.assert_called_once()
        mock_get.assert_called_once()


if __name__ == "__main__":
    unittest.main()
