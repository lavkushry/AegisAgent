import asyncio
import logging
import unittest
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import requests
from aegisagent import AegisAsyncClient, async_protect_tool, protect_tool
from aegisagent.client import retry_on_5xx
from aegisagent.decorator import _hash_tool_call

try:
    import httpx
except ImportError:
    httpx = None


def _make_mock_response(
    status_code: int, json_data: Any = None, text: str = "", headers: dict = None
):
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    if json_data is not None:
        mock_resp.json.return_value = json_data
        import json

        mock_resp.text = json.dumps(json_data)
    else:
        mock_resp.text = text
    mock_resp.headers = headers or {}
    return mock_resp


class TestAsyncClientBasics(unittest.TestCase):
    def test_init(self):
        client = AegisAsyncClient(
            api_key="test_key",
            agent_id="test_agent",
            endpoint="http://127.0.0.1:8080",
        )
        self.assertEqual(client.api_key, "test_key")
        self.assertEqual(client.agent_id, "test_agent")
        self.assertEqual(client.endpoint, "http://127.0.0.1:8080")

    def test_import_error_without_httpx(self):
        with patch("aegisagent.client.httpx", None):
            with self.assertRaises(ImportError):
                AegisAsyncClient(
                    api_key="test_key",
                    agent_id="test_agent",
                )

    def test_repr_str(self):
        client = AegisAsyncClient(
            api_key="test_key",
            agent_id="test_agent",
        )
        self.assertIn("AegisAsyncClient", repr(client))
        self.assertIn("AegisAsyncClient", str(client))


class TestRetryDecorator(unittest.IsolatedAsyncioTestCase):
    def test_sync_retry_on_5xx_status(self):
        call_count = 0

        @retry_on_5xx(max_retries=2, backoff_factor=0.01)
        def sync_fn():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return _make_mock_response(500)
            return _make_mock_response(200)

        res = sync_fn()
        self.assertEqual(call_count, 3)
        self.assertEqual(res.status_code, 200)

    def test_sync_retry_on_5xx_exception(self):
        call_count = 0

        @retry_on_5xx(max_retries=2, backoff_factor=0.01)
        def sync_fn():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise requests.exceptions.ConnectionError("Connection failed")
            return _make_mock_response(200)

        res = sync_fn()
        self.assertEqual(call_count, 3)
        self.assertEqual(res.status_code, 200)

    async def test_async_retry_on_5xx_status(self):
        call_count = 0

        @retry_on_5xx(max_retries=2, backoff_factor=0.01)
        async def async_fn():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return _make_mock_response(503)
            return _make_mock_response(200)

        res = await async_fn()
        self.assertEqual(call_count, 3)
        self.assertEqual(res.status_code, 200)

    async def test_async_retry_on_5xx_exception(self):
        if httpx is None:
            self.skipTest("httpx is not installed")
        call_count = 0

        @retry_on_5xx(max_retries=2, backoff_factor=0.01)
        async def async_fn():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise httpx.ConnectError("Connection failed")
            return _make_mock_response(200)

        res = await async_fn()
        self.assertEqual(call_count, 3)
        self.assertEqual(res.status_code, 200)


class TestAegisAsyncClientMethods(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.client = AegisAsyncClient(
            api_key="test_key",
            agent_id="test_agent",
            endpoint="http://127.0.0.1:8080",
        )
        self.client.agent_token = "mock_agent_token"

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_register_agent(self, mock_request):
        mock_request.return_value = _make_mock_response(
            status_code=201, json_data={"agent_token": "new_token"}
        )
        self.client.agent_token = None
        success = await self.client.register_agent("test_name")
        self.assertTrue(success)
        self.assertEqual(self.client.agent_token, "new_token")

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_authorize_allow(self, mock_request):
        mock_request.return_value = _make_mock_response(
            status_code=200, json_data={"decision": "allow", "reason": "Authorized"}
        )
        res = await self.client.authorize(tool="t", action="a", parameters={"p": 1})
        self.assertEqual(res["decision"], "allow")

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_get_approval_status(self, mock_request):
        mock_request.return_value = _make_mock_response(
            status_code=200, json_data={"status": "APPROVED"}
        )
        res = await self.client.get_approval_status("appr-123")
        self.assertEqual(res["status"], "APPROVED")

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_consume_approval(self, mock_request):
        mock_request.return_value = _make_mock_response(
            status_code=200, json_data={"consumed": True}
        )
        res = await self.client.consume_approval("appr-123")
        self.assertTrue(res["consumed"])

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_freeze_agent(self, mock_request):
        mock_request.return_value = _make_mock_response(status_code=200)
        res = await self.client.freeze_agent("agent-1")
        self.assertTrue(res)

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_unfreeze_agent(self, mock_request):
        mock_request.return_value = _make_mock_response(status_code=200)
        res = await self.client.unfreeze_agent("agent-1")
        self.assertTrue(res)

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_revoke_agent(self, mock_request):
        mock_request.return_value = _make_mock_response(status_code=200)
        res = await self.client.revoke_agent("agent-1")
        self.assertTrue(res)

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_quarantine_server(self, mock_request):
        mock_request.return_value = _make_mock_response(status_code=200)
        res = await self.client.quarantine_server("server-1")
        self.assertTrue(res)

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_restore_server(self, mock_request):
        mock_request.return_value = _make_mock_response(status_code=200)
        res = await self.client.restore_server("server-1")
        self.assertTrue(res)

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_list_agents(self, mock_request):
        mock_request.return_value = _make_mock_response(
            status_code=200, json_data=[{"id": "agent-1"}]
        )
        res = await self.client.list_agents()
        self.assertEqual(len(res), 1)

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_list_decisions(self, mock_request):
        mock_request.return_value = _make_mock_response(
            status_code=200, json_data=[{"id": "decision-1"}]
        )
        res = await self.client.list_decisions()
        self.assertEqual(len(res), 1)

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_list_approvals(self, mock_request):
        mock_request.return_value = _make_mock_response(
            status_code=200, json_data=[{"id": "approval-1"}]
        )
        res = await self.client.list_approvals()
        self.assertEqual(len(res), 1)

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_list_receipts(self, mock_request):
        mock_request.return_value = _make_mock_response(
            status_code=200, json_data=[{"id": "receipt-1"}]
        )
        res = await self.client.list_receipts()
        self.assertEqual(len(res), 1)

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_get_soc_summary(self, mock_request):
        mock_request.return_value = _make_mock_response(
            status_code=200, json_data={"alerts_total": 2, "incidents_total": 2}
        )
        res = await self.client.get_soc_summary()
        self.assertEqual(res["alerts_total"], 2)

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_close_incident(self, mock_request):
        mock_request.return_value = _make_mock_response(status_code=200)
        res = await self.client.close_incident("incident-1")
        self.assertTrue(res)

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_close_incident_returns_false_on_error(self, mock_request):
        mock_request.return_value = _make_mock_response(
            status_code=404, text="Incident not found"
        )
        res = await self.client.close_incident("incident-1")
        self.assertFalse(res)

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_narrate_incident(self, mock_request):
        mock_request.return_value = _make_mock_response(
            status_code=200,
            json_data={"incident_id": "incident-1", "narrative": "Root cause: X."},
        )
        res = await self.client.narrate_incident("incident-1")
        self.assertEqual(res, "Root cause: X.")

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_verify_receipt_chain(self, mock_request):
        mock_request.return_value = _make_mock_response(
            status_code=200, json_data={"verified": True}
        )
        res = await self.client.verify_receipt_chain([])
        self.assertTrue(res["verified"])

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_upload_policy(self, mock_request):
        mock_request.return_value = _make_mock_response(
            status_code=201, json_data={"id": "policy-1"}
        )
        res = await self.client.upload_policy("key", "name", "body")
        self.assertEqual(res["id"], "policy-1")

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_list_policies(self, mock_request):
        mock_request.return_value = _make_mock_response(
            status_code=200, json_data=[{"id": "policy-1"}]
        )
        res = await self.client.list_policies()
        self.assertEqual(len(res), 1)

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_register_mcp_server(self, mock_request):
        mock_request.return_value = _make_mock_response(
            status_code=201, json_data={"server_key": "server-1"}
        )
        res = await self.client.register_mcp_server(
            "server-1", "name", "sse", "http://...", "high"
        )
        self.assertEqual(res["server_key"], "server-1")

    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_discover_tools(self, mock_request):
        mock_request.return_value = _make_mock_response(
            status_code=200, json_data={"tools_count": 2}
        )
        res = await self.client.discover_tools("server-1", [])
        self.assertEqual(res["tools_count"], 2)


class TestAsyncProtectToolWithAsyncClient(unittest.IsolatedAsyncioTestCase):
    @patch("asyncio.sleep", new_callable=AsyncMock)
    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_async_client_flow_allows(self, mock_request, mock_sleep):
        client = AegisAsyncClient(
            api_key="test_key",
            agent_id="test_agent",
            endpoint="http://127.0.0.1:8080",
        )
        client.agent_token = "mock_agent_token"

        mock_request.return_value = _make_mock_response(
            status_code=200, json_data={"decision": "allow", "reason": "ok"}
        )

        @async_protect_tool(client, tool="t", action="a")
        async def my_tool(x):
            return x * 2

        res = await my_tool(5)
        self.assertEqual(res, 10)
        mock_request.assert_called_once()

    @patch("asyncio.sleep", new_callable=AsyncMock)
    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_async_client_flow_requires_approval(self, mock_request, mock_sleep):
        client = AegisAsyncClient(
            api_key="test_key",
            agent_id="test_agent",
            endpoint="http://127.0.0.1:8080",
        )
        client.agent_token = "mock_agent_token"

        expected_hash = _hash_tool_call("t", "a", None, True, {"x": 5})

        # Step 1: require approval, Step 2: consume approval
        mock_request.side_effect = [
            _make_mock_response(
                status_code=200,
                json_data={
                    "decision": "require_approval",
                    "reason": "review needed",
                    "approval": {
                        "approval_id": "appr-1",
                        "status": "created",
                        "approver_group": "leads",
                        "expires_at": "2099-01-01T00:00:00Z",
                        "action_hash": expected_hash,
                    },
                },
            ),
            # poll status response
            _make_mock_response(
                status_code=200,
                json_data={
                    "status": "APPROVED",
                    "action_hash": expected_hash,
                },
            ),
            # consume response
            _make_mock_response(
                status_code=200,
                json_data={
                    "consumed": True,
                    "action_hash": expected_hash,
                },
            ),
        ]

        @async_protect_tool(client, tool="t", action="a")
        async def my_tool(x):
            return x * 2

        res = await my_tool(5)
        self.assertEqual(res, 10)
        self.assertEqual(mock_request.call_count, 3)


class TestAsyncClientLogRedaction(unittest.IsolatedAsyncioTestCase):
    @patch("httpx.AsyncClient.request", new_callable=AsyncMock)
    async def test_logs_are_redacted(self, mock_request):
        logger = logging.getLogger("aegisagent")
        log_records = []

        class ListHandler(logging.Handler):
            def emit(self, record):
                log_records.append(record.getMessage())

        handler = ListHandler()
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.DEBUG)

        try:
            client = AegisAsyncClient(
                api_key="secret_api_key",
                agent_id="test_agent",
                endpoint="http://127.0.0.1:8080",
            )
            client.agent_token = "secret_agent_token"

            mock_request.return_value = _make_mock_response(
                status_code=200,
                json_data={
                    "decision": "allow",
                    "agent_token": "secret_agent_token",
                    "api_key": "secret_api_key",
                },
            )

            await client.authorize(
                tool="t", action="a", parameters={"api_key": "some_api_key"}
            )

            # Check that sensitive words are not present in raw format
            for log_str in log_records:
                self.assertNotIn("secret_api_key", log_str)
                self.assertNotIn("secret_agent_token", log_str)
                self.assertNotIn("some_api_key", log_str)

        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)


if __name__ == "__main__":
    unittest.main()
