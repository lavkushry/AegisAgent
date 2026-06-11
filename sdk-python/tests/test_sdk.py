import unittest
from unittest.mock import MagicMock, patch

from aegisagent import (
    AegisClient,
    get_context_trust_level,
    protect_tool,
    set_context_trust_level,
    trust_level,
    StructuredJSONFormatter,
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

    @patch("requests.Session.post")
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

    @patch("requests.Session.post")
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
    @patch("requests.Session.get")
    @patch("requests.Session.post")
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
                "expires_at": "2099-01-01T00:00:00Z",
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

    @patch("time.sleep", return_value=None)
    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_approval_timeout_raises_timeout_error(
        self, mock_post, mock_get, _mock_sleep
    ):
        """Exhausting the poll_timeout must raise TimeoutError (TASK-0204).

        Every poll returns PENDING; with poll_timeout=0.001 the wall-clock
        deadline expires after one spin (time.sleep is mocked instant) and
        the guard at the end of the polling block fires.
        """
        correct_hash = _hash_tool_call(
            tool="test_tool",
            action="test_action",
            resource=None,
            mutates_state=True,
            parameters={"param1": "hello"},
        )
        auth_resp = MagicMock()
        auth_resp.status_code = 200
        auth_resp.json.return_value = {
            "decision": "require_approval",
            "reason": "Approval required",
            "approval": {
                "approval_id": "89cf8b98-2103-4458-8210-344589cf8b98",
                "status": "created",
                "approver_group": "platform-leads",
                "expires_at": "2099-01-01T00:00:00Z",
                "action_hash": correct_hash,
            },
        }
        mock_post.return_value = auth_resp

        # Every status poll returns PENDING — loop exhausts.
        pending_resp = MagicMock()
        pending_resp.status_code = 200
        pending_resp.json.return_value = {
            "status": "PENDING",
            "action_hash": correct_hash,
            "expires_at": "2099-01-01T00:00:00Z",
        }
        mock_get.return_value = pending_resp

        executed = {"ran": False}

        # poll_timeout=0.001 makes the wall-clock deadline expire immediately.
        # time.sleep is mocked (instant), time.monotonic is real, so 1 ms is
        # enough for the deadline to fall past the very first iteration.
        @protect_tool(
            self.client,
            tool="test_tool",
            action="test_action",
            poll_timeout=0.001,
        )
        def my_test_func(param1):
            executed["ran"] = True
            return f"executed_{param1}"

        with self.assertRaises(TimeoutError):
            my_test_func("hello")
        self.assertFalse(
            executed["ran"], "timed-out approval must not execute the tool"
        )

    @patch("requests.Session.get")
    @patch("requests.Session.post")
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
                "expires_at": "2099-01-01T00:00:00Z",
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

    @patch("requests.Session.post")
    def test_freeze_agent(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        res = self.client.freeze_agent("agent_abc")
        self.assertTrue(res)
        mock_post.assert_called_once_with(
            "http://127.0.0.1:8080/v1/agents/agent_abc/freeze",
            json=None,
            headers={
                "Authorization": "Bearer test_key",
                "Content-Type": "application/json",
            },
            timeout=5,
        )

    @patch("requests.Session.post")
    def test_unfreeze_agent(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        res = self.client.unfreeze_agent("agent_abc")
        self.assertTrue(res)
        mock_post.assert_called_once_with(
            "http://127.0.0.1:8080/v1/agents/agent_abc/unfreeze",
            json=None,
            headers={
                "Authorization": "Bearer test_key",
                "Content-Type": "application/json",
            },
            timeout=5,
        )

    @patch("requests.Session.post")
    def test_revoke_agent(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        res = self.client.revoke_agent("agent_abc")
        self.assertTrue(res)
        mock_post.assert_called_once_with(
            "http://127.0.0.1:8080/v1/agents/agent_abc/revoke",
            json=None,
            headers={
                "Authorization": "Bearer test_key",
                "Content-Type": "application/json",
            },
            timeout=5,
        )

    @patch("requests.Session.post")
    def test_quarantine_server(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        res = self.client.quarantine_server("server_abc")
        self.assertTrue(res)
        mock_post.assert_called_once_with(
            "http://127.0.0.1:8080/v1/mcp/servers/server_abc/quarantine",
            json=None,
            headers={
                "Authorization": "Bearer test_key",
                "Content-Type": "application/json",
            },
            timeout=5,
        )

    @patch("requests.Session.post")
    def test_restore_server(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        res = self.client.restore_server("server_abc")
        self.assertTrue(res)
        mock_post.assert_called_once_with(
            "http://127.0.0.1:8080/v1/mcp/servers/server_abc/restore",
            json=None,
            headers={
                "Authorization": "Bearer test_key",
                "Content-Type": "application/json",
            },
            timeout=5,
        )

    @patch("requests.Session.get")
    def test_list_agents(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"id": "agent_abc"}]
        mock_get.return_value = mock_response

        res = self.client.list_agents(limit=10, offset=5)
        self.assertEqual(res, [{"id": "agent_abc"}])
        mock_get.assert_called_once_with(
            "http://127.0.0.1:8080/v1/agents",
            headers={
                "Authorization": "Bearer test_key",
                "Content-Type": "application/json",
            },
            params={"limit": 10, "offset": 5},
            timeout=5,
        )

    @patch("requests.Session.get")
    def test_list_decisions(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"id": "decision_1"}]
        mock_get.return_value = mock_response

        res = self.client.list_decisions(
            limit=10, offset=5, agent_id="agent_1", decision="allow"
        )
        self.assertEqual(res, [{"id": "decision_1"}])
        mock_get.assert_called_once_with(
            "http://127.0.0.1:8080/v1/decisions",
            headers={
                "Authorization": "Bearer test_key",
                "Content-Type": "application/json",
            },
            params={
                "limit": 10,
                "offset": 5,
                "agent_id": "agent_1",
                "decision": "allow",
            },
            timeout=5,
        )

    @patch("requests.Session.get")
    def test_list_approvals(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"id": "approval_1"}]
        mock_get.return_value = mock_response

        res = self.client.list_approvals()
        self.assertEqual(res, [{"id": "approval_1"}])
        mock_get.assert_called_once_with(
            "http://127.0.0.1:8080/v1/approvals",
            headers={
                "Authorization": "Bearer test_key",
                "Content-Type": "application/json",
            },
            params={"limit": 50, "offset": 0},
            timeout=5,
        )

    @patch("requests.Session.get")
    def test_list_receipts(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"id": "receipt_1"}]
        mock_get.return_value = mock_response

        res = self.client.list_receipts()
        self.assertEqual(res, [{"id": "receipt_1"}])
        mock_get.assert_called_once_with(
            "http://127.0.0.1:8080/v1/receipts",
            headers={
                "Authorization": "Bearer test_key",
                "Content-Type": "application/json",
            },
            params={"limit": 50, "offset": 0},
            timeout=5,
        )

    @patch("requests.Session.get")
    def test_get_soc_summary(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "alerts_total": 2,
            "alerts_high": 1,
            "incidents_total": 2,
            "incidents_open": 1,
        }
        mock_get.return_value = mock_response

        res = self.client.get_soc_summary()
        self.assertEqual(res["alerts_total"], 2)
        mock_get.assert_called_once_with(
            "http://127.0.0.1:8080/v1/soc/summary",
            headers={
                "Authorization": "Bearer test_key",
                "Content-Type": "application/json",
            },
            timeout=5,
        )

    @patch("requests.Session.get")
    def test_get_soc_summary_returns_none_on_error(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_get.return_value = mock_response

        res = self.client.get_soc_summary()
        self.assertIsNone(res)

    @patch("requests.Session.post")
    def test_verify_receipt_chain(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"verified": True, "error": None}
        mock_post.return_value = mock_response

        res = self.client.verify_receipt_chain([{"id": "r1"}])
        self.assertEqual(res, {"verified": True, "error": None})
        mock_post.assert_called_once_with(
            "http://127.0.0.1:8080/v1/receipts/verify-chain",
            json={"receipts": [{"id": "r1"}]},
            headers={
                "Authorization": "Bearer test_key",
                "Content-Type": "application/json",
            },
            timeout=5,
        )

    @patch("requests.Session.post")
    def test_upload_policy(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": "p1"}
        mock_post.return_value = mock_response

        res = self.client.upload_policy("key1", "name1", "body1")
        self.assertEqual(res, {"id": "p1"})
        mock_post.assert_called_once_with(
            "http://127.0.0.1:8080/v1/policies",
            json={"policy_key": "key1", "name": "name1", "body": "body1"},
            headers={
                "Authorization": "Bearer test_key",
                "Content-Type": "application/json",
            },
            timeout=5,
        )

    @patch("requests.Session.get")
    def test_list_policies(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"id": "p1"}]
        mock_get.return_value = mock_response

        res = self.client.list_policies()
        self.assertEqual(res, [{"id": "p1"}])
        mock_get.assert_called_once_with(
            "http://127.0.0.1:8080/v1/policies",
            headers={
                "Authorization": "Bearer test_key",
                "Content-Type": "application/json",
            },
            params=None,
            timeout=5,
        )

    @patch("requests.Session.post")
    def test_register_mcp_server(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"server_id": "s1"}
        mock_post.return_value = mock_response

        res = self.client.register_mcp_server(
            "key1", "name1", "stdio", "endpoint1", "high", "team1", "source1"
        )
        self.assertEqual(res, {"server_id": "s1"})
        mock_post.assert_called_once_with(
            "http://127.0.0.1:8080/v1/mcp/servers",
            json={
                "server_key": "key1",
                "name": "name1",
                "transport": "stdio",
                "endpoint": "endpoint1",
                "trust_level": "high",
                "owner_team": "team1",
                "source": "source1",
            },
            headers={
                "Authorization": "Bearer test_key",
                "Content-Type": "application/json",
            },
            timeout=5,
        )

    @patch("requests.Session.post")
    def test_discover_tools(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok"}
        mock_post.return_value = mock_response

        res = self.client.discover_tools("server1", [{"tool_key": "t1"}])
        self.assertEqual(res, {"status": "ok"})
        mock_post.assert_called_once_with(
            "http://127.0.0.1:8080/v1/mcp/servers/server1/tools",
            json={"tools": [{"tool_key": "t1"}]},
            headers={
                "Authorization": "Bearer test_key",
                "Content-Type": "application/json",
            },
            timeout=5,
        )

    def test_client_close(self):
        # Verify close method closes the session
        with patch.object(self.client.session, "close") as mock_close:
            self.client.close()
            mock_close.assert_called_once()

    def test_client_repr_and_str(self):
        repr_str = repr(self.client)
        self.assertIn("AegisClient", repr_str)
        self.assertIn("api_key='test_key'", repr_str)
        self.assertIn("agent_id='test_agent'", repr_str)
        self.assertIn("endpoint='http://127.0.0.1:8080'", repr_str)

        str_str = str(self.client)
        self.assertIn("AegisClient", str_str)
        self.assertIn("agent_id=test_agent", str_str)
        self.assertIn("endpoint=http://127.0.0.1:8080", str_str)

    def test_trust_level_context_manager(self):
        set_context_trust_level("unknown")
        with trust_level("trusted_internal_signed"):
            self.assertEqual(get_context_trust_level(), "trusted_internal_signed")
        self.assertEqual(get_context_trust_level(), "unknown")

    @patch("requests.Session.post")
    def test_debug_logging_with_redaction(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.text = '{"status": "ok", "agent_token": "secret_token_123"}'
        mock_post.return_value = mock_response

        with self.assertLogs("aegisagent", level="DEBUG") as log_capture:
            res = self.client.freeze_agent("agent_abc")
            self.assertTrue(res)

        # Verify logs were captured and contain redacted info
        log_msgs = "\n".join(log_capture.output)
        self.assertIn("Sending Request: POST", log_msgs)
        self.assertIn("Received Response: status=200", log_msgs)
        # Ensure raw secret is not present in logged request headers or response
        self.assertNotIn("test_key", log_msgs)
        self.assertNotIn("secret_token_123", log_msgs)
        self.assertIn("[REDACTED]", log_msgs)

    def test_structured_json_logging(self):
        import io
        import json
        import logging

        log_stream = io.StringIO()
        handler = logging.StreamHandler(log_stream)
        handler.setFormatter(StructuredJSONFormatter())

        test_logger = logging.getLogger("test_structured_json")
        test_logger.addHandler(handler)
        test_logger.setLevel(logging.INFO)
        test_logger.propagate = False

        # Test standard log with extra arguments
        test_logger.info(
            "Test structured message", extra={"user_id": "u123", "action": "test"}
        )

        # Retrieve and parse log line
        log_output = log_stream.getvalue().strip()
        self.assertTrue(log_output.startswith("{") and log_output.endswith("}"))

        log_json = json.loads(log_output)
        self.assertEqual(log_json["message"], "Test structured message")
        self.assertEqual(log_json["level"], "INFO")
        self.assertEqual(log_json["name"], "test_structured_json")
        self.assertEqual(log_json["user_id"], "u123")
        self.assertEqual(log_json["action"], "test")
        self.assertIn("timestamp", log_json)
        self.assertIn("filename", log_json)
        self.assertIn("lineno", log_json)

        # Test log with exception formatting
        log_stream.seek(0)
        log_stream.truncate(0)
        try:
            raise ValueError("Something went wrong")
        except Exception:
            test_logger.exception("An exception occurred")

        log_output_exc = log_stream.getvalue().strip()
        log_json_exc = json.loads(log_output_exc)
        self.assertEqual(log_json_exc["message"], "An exception occurred")
        self.assertIn("exc_info", log_json_exc)
        self.assertIn("ValueError: Something went wrong", log_json_exc["exc_info"])


if __name__ == "__main__":
    unittest.main()
