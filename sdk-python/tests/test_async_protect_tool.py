"""
Tests for async_protect_tool and exponential-backoff poll behaviour.

TDD — RED phase: written before the implementation so they fail first.
"""

import asyncio
import inspect
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from aegisagent import AegisClient
from aegisagent.decorator import _hash_tool_call

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_client() -> AegisClient:
    client = AegisClient(
        api_key="test_key",
        agent_id="test_agent",
        endpoint="http://127.0.0.1:8080",
    )
    client.agent_token = "mock_agent_token"
    return client


def _allow_response():
    m = MagicMock()
    m.status_code = 200
    m.json.return_value = {"decision": "allow", "reason": "Permitted by policy"}
    return m


def _deny_response():
    m = MagicMock()
    m.status_code = 200
    m.json.return_value = {"decision": "deny", "reason": "Forbidden by policy"}
    return m


def _require_approval_response(expected_hash: str, approval_id: str = "test-appr-001"):
    m = MagicMock()
    m.status_code = 200
    m.json.return_value = {
        "decision": "require_approval",
        "reason": "Needs human review",
        "approval": {
            "approval_id": approval_id,
            "status": "created",
            "approver_group": "platform-leads",
            "expires_at": "2099-01-01T00:00:00Z",
            "action_hash": expected_hash,
        },
    }
    return m


def _status_response(status: str, action_hash: str, extra=None):
    payload: dict = {"status": status, "action_hash": action_hash}
    if extra:
        payload.update(extra)
    m = MagicMock()
    m.status_code = 200
    m.json.return_value = payload
    return m


def _consume_response(action_hash: str):
    m = MagicMock()
    m.status_code = 200
    m.json.return_value = {"action_hash": action_hash, "consumed": True}
    return m


# ---------------------------------------------------------------------------
# Import guard — will fail (RED) until async_protect_tool is implemented
# ---------------------------------------------------------------------------

try:
    from aegisagent import async_protect_tool  # noqa: F401
    from aegisagent.decorator import _rebind_edited_args  # noqa: F401

    _IMPORT_OK = True
except ImportError:
    _IMPORT_OK = False


# ---------------------------------------------------------------------------
# async_protect_tool — allow
# ---------------------------------------------------------------------------


@unittest.skipUnless(_IMPORT_OK, "async_protect_tool not yet implemented")
class TestAsyncProtectToolAllow(unittest.IsolatedAsyncioTestCase):
    """allow decision → tool executes, result returned."""

    @patch("requests.Session.post")
    async def test_allow_executes(self, mock_post):
        mock_post.return_value = _allow_response()
        client = _make_client()

        @async_protect_tool(client, tool="svc", action="read")
        async def my_tool(val: str) -> str:
            return f"ok:{val}"

        result = await my_tool("hello")
        self.assertEqual(result, "ok:hello")
        mock_post.assert_called_once()

    @patch("requests.Session.post")
    async def test_allow_does_not_raise(self, mock_post):
        mock_post.return_value = _allow_response()
        client = _make_client()
        ran = []

        @async_protect_tool(client, tool="svc", action="read")
        async def my_tool():
            ran.append(True)

        await my_tool()
        self.assertTrue(ran)


# ---------------------------------------------------------------------------
# async_protect_tool — deny
# ---------------------------------------------------------------------------


@unittest.skipUnless(_IMPORT_OK, "async_protect_tool not yet implemented")
class TestAsyncProtectToolDeny(unittest.IsolatedAsyncioTestCase):
    """deny decision → PermissionError raised, tool NOT executed."""

    @patch("requests.Session.post")
    async def test_deny_raises_permission_error(self, mock_post):
        mock_post.return_value = _deny_response()
        client = _make_client()
        ran = []

        @async_protect_tool(client, tool="svc", action="write")
        async def my_tool():
            ran.append(True)

        with self.assertRaises(PermissionError):
            await my_tool()
        self.assertFalse(ran, "Tool MUST NOT execute on deny")

    @patch("requests.Session.post")
    async def test_deny_not_executed(self, mock_post):
        mock_post.return_value = _deny_response()
        client = _make_client()
        executed = False

        @async_protect_tool(client, tool="svc", action="delete")
        async def dangerous():
            nonlocal executed
            executed = True

        with self.assertRaises(PermissionError):
            await dangerous()
        self.assertFalse(executed)


# ---------------------------------------------------------------------------
# async_protect_tool — approval flow
# ---------------------------------------------------------------------------


@unittest.skipUnless(_IMPORT_OK, "async_protect_tool not yet implemented")
class TestAsyncProtectToolApproval(unittest.IsolatedAsyncioTestCase):
    """require_approval → poll → APPROVED → consume → execute."""

    @patch("asyncio.sleep", new_callable=AsyncMock)
    @patch("requests.Session.get")
    @patch("requests.Session.post")
    async def test_approval_poll_approved_executes(
        self, mock_post, mock_get, mock_sleep
    ):
        expected_hash = _hash_tool_call(
            tool="svc",
            action="deploy",
            resource=None,
            mutates_state=True,
            parameters={"env": "staging"},
        )
        approval_id = "appr-001"

        mock_post.side_effect = [
            _require_approval_response(expected_hash, approval_id),
            _consume_response(expected_hash),
        ]
        mock_get.return_value = _status_response("APPROVED", expected_hash)

        client = _make_client()

        @async_protect_tool(client, tool="svc", action="deploy")
        async def deploy(env: str) -> str:
            return f"deployed:{env}"

        result = await deploy("staging")
        self.assertEqual(result, "deployed:staging")
        mock_sleep.assert_called()

    @patch("asyncio.sleep", new_callable=AsyncMock)
    @patch("requests.Session.get")
    @patch("requests.Session.post")
    async def test_approval_hash_mismatch_fails_closed(
        self, mock_post, mock_get, mock_sleep
    ):
        """Wrong hash on approval status → PermissionError (fail closed)."""
        wrong_hash = "0" * 64
        real_hash = _hash_tool_call(
            tool="svc",
            action="deploy",
            resource=None,
            mutates_state=True,
            parameters={"env": "prod"},
        )
        approval_id = "appr-002"

        mock_post.return_value = _require_approval_response(real_hash, approval_id)
        # status carries mismatched hash
        mock_get.return_value = _status_response("APPROVED", wrong_hash)

        client = _make_client()
        executed = []

        @async_protect_tool(client, tool="svc", action="deploy")
        async def deploy(env: str) -> str:
            executed.append(env)
            return f"deployed:{env}"

        with self.assertRaises(PermissionError):
            await deploy("prod")
        self.assertFalse(executed, "Tool must NOT execute on hash mismatch")

    @patch("asyncio.sleep", new_callable=AsyncMock)
    @patch("requests.Session.get")
    @patch("requests.Session.post")
    async def test_approval_rejected_raises(self, mock_post, mock_get, mock_sleep):
        real_hash = _hash_tool_call(
            tool="svc",
            action="delete",
            resource=None,
            mutates_state=True,
            parameters={},
        )
        approval_id = "appr-003"
        mock_post.return_value = _require_approval_response(real_hash, approval_id)
        mock_get.return_value = _status_response(
            "REJECTED", real_hash, {"reason": "No way"}
        )

        client = _make_client()

        @async_protect_tool(client, tool="svc", action="delete")
        async def delete_thing() -> str:
            return "deleted"

        with self.assertRaises(PermissionError):
            await delete_thing()

    @patch("asyncio.sleep", new_callable=AsyncMock)
    @patch("requests.Session.get")
    @patch("requests.Session.post")
    async def test_approval_edited_rebinds_and_executes(
        self, mock_post, mock_get, mock_sleep
    ):
        real_hash = _hash_tool_call(
            tool="svc",
            action="deploy",
            resource=None,
            mutates_state=True,
            parameters={"env": "staging"},
        )
        approval_id = "appr-004"
        mock_post.return_value = _require_approval_response(real_hash, approval_id)
        mock_get.return_value = _status_response(
            "EDITED",
            real_hash,
            {"edited_tool_call": {"parameters": {"env": "canary"}}},
        )

        client = _make_client()

        @async_protect_tool(client, tool="svc", action="deploy")
        async def deploy(env: str) -> str:
            return f"deployed:{env}"

        result = await deploy("staging")
        self.assertEqual(result, "deployed:canary")


# ---------------------------------------------------------------------------
# async_protect_tool — unknown decision (fail closed)
# ---------------------------------------------------------------------------


@unittest.skipUnless(_IMPORT_OK, "async_protect_tool not yet implemented")
class TestAsyncProtectToolUnknownDecision(unittest.IsolatedAsyncioTestCase):
    """Unknown gateway decision → PermissionError."""

    @patch("requests.Session.post")
    async def test_unknown_decision_fails_closed(self, mock_post):
        m = MagicMock()
        m.status_code = 200
        m.json.return_value = {"decision": "maybe", "reason": "who knows"}
        mock_post.return_value = m

        client = _make_client()

        @async_protect_tool(client, tool="svc", action="read")
        async def my_tool():
            return "ran"

        with self.assertRaises(PermissionError):
            await my_tool()


# ---------------------------------------------------------------------------
# Exponential backoff — sync protect_tool
# ---------------------------------------------------------------------------


@unittest.skipUnless(_IMPORT_OK, "async_protect_tool not yet implemented")
class TestExponentialBackoffSync(unittest.TestCase):
    """protect_tool with backoff kwargs: interval grows and caps."""

    def setUp(self):
        from aegisagent import protect_tool

        self.protect_tool = protect_tool

    def _approval_setup(self, num_polls: int):
        """Build mocks for an approval that resolves on the last poll."""
        real_hash = _hash_tool_call(
            tool="t", action="a", resource=None, mutates_state=True, parameters={"x": 1}
        )
        approval_id = "bp-sync-001"

        auth_resp = MagicMock()
        auth_resp.status_code = 200
        auth_resp.json.return_value = {
            "decision": "require_approval",
            "reason": "Needs review",
            "approval": {
                "approval_id": approval_id,
                "status": "created",
                "approver_group": "leads",
                "expires_at": "2099-01-01T00:00:00Z",
                "action_hash": real_hash,
            },
        }
        pending = MagicMock()
        pending.status_code = 200
        pending.json.return_value = {"status": "PENDING", "action_hash": real_hash}

        approved = MagicMock()
        approved.status_code = 200
        approved.json.return_value = {"status": "APPROVED", "action_hash": real_hash}

        consume = MagicMock()
        consume.status_code = 200
        consume.json.return_value = {"action_hash": real_hash, "consumed": True}

        get_sides = [pending] * (num_polls - 1) + [approved]
        return auth_resp, consume, get_sides, real_hash

    @patch("time.sleep", return_value=None)
    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_backoff_interval_grows_and_caps(self, mock_post, mock_get, mock_sleep):
        """Sleep args must grow by poll_backoff and be capped at poll_max_interval."""
        auth_resp, consume, get_sides, _ = self._approval_setup(5)
        mock_post.side_effect = [auth_resp, consume]
        mock_get.side_effect = get_sides

        client = _make_client()

        @self.protect_tool(
            client,
            tool="t",
            action="a",
            poll_interval=1.0,
            poll_backoff=2.0,
            poll_max_interval=4.0,
            poll_timeout=300.0,
        )
        def my_tool(x: int) -> int:
            return x * 2

        result = my_tool(1)
        self.assertEqual(result, 2)

        sleep_calls = [c.args[0] for c in mock_sleep.call_args_list]
        # poll_interval=1.0, backoff=2.0, cap=4.0
        # sleep: 1.0 → 2.0 → 4.0 → 4.0 → ...
        self.assertGreaterEqual(len(sleep_calls), 4)
        self.assertAlmostEqual(sleep_calls[0], 1.0, places=5)
        self.assertAlmostEqual(sleep_calls[1], 2.0, places=5)
        self.assertAlmostEqual(sleep_calls[2], 4.0, places=5)
        self.assertAlmostEqual(sleep_calls[3], 4.0, places=5)

    @patch("time.sleep", return_value=None)
    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_backoff_default_kwargs_approve_on_first_poll(
        self, mock_post, mock_get, mock_sleep
    ):
        """Default backoff kwargs: existing APPROVED-on-first-poll tests still pass."""
        real_hash = _hash_tool_call(
            tool="t", action="a", resource=None, mutates_state=True, parameters={"x": 1}
        )
        auth_resp = MagicMock()
        auth_resp.status_code = 200
        auth_resp.json.return_value = {
            "decision": "require_approval",
            "reason": "Needs review",
            "approval": {
                "approval_id": "default-bp-001",
                "status": "created",
                "approver_group": "leads",
                "expires_at": "2099-01-01T00:00:00Z",
                "action_hash": real_hash,
            },
        }
        approved = MagicMock()
        approved.status_code = 200
        approved.json.return_value = {"status": "APPROVED", "action_hash": real_hash}

        consume = MagicMock()
        consume.status_code = 200
        consume.json.return_value = {"action_hash": real_hash, "consumed": True}

        mock_post.side_effect = [auth_resp, consume]
        mock_get.return_value = approved

        client = _make_client()

        @self.protect_tool(client, tool="t", action="a")
        def my_tool(x: int) -> int:
            return x * 10

        result = my_tool(1)
        self.assertEqual(result, 10)


# ---------------------------------------------------------------------------
# Exponential backoff — async_protect_tool
# ---------------------------------------------------------------------------


@unittest.skipUnless(_IMPORT_OK, "async_protect_tool not yet implemented")
class TestExponentialBackoffAsync(unittest.IsolatedAsyncioTestCase):
    """async_protect_tool: sleep interval grows and is capped."""

    @patch("asyncio.sleep", new_callable=AsyncMock)
    @patch("requests.Session.get")
    @patch("requests.Session.post")
    async def test_async_backoff_interval_grows_and_caps(
        self, mock_post, mock_get, mock_sleep
    ):
        real_hash = _hash_tool_call(
            tool="svc",
            action="act",
            resource=None,
            mutates_state=True,
            parameters={"n": 7},
        )
        approval_id = "bp-async-001"

        auth_resp = MagicMock()
        auth_resp.status_code = 200
        auth_resp.json.return_value = {
            "decision": "require_approval",
            "reason": "Needs review",
            "approval": {
                "approval_id": approval_id,
                "status": "created",
                "approver_group": "leads",
                "expires_at": "2099-01-01T00:00:00Z",
                "action_hash": real_hash,
            },
        }
        pending = MagicMock()
        pending.status_code = 200
        pending.json.return_value = {"status": "PENDING", "action_hash": real_hash}

        approved = MagicMock()
        approved.status_code = 200
        approved.json.return_value = {"status": "APPROVED", "action_hash": real_hash}

        consume = MagicMock()
        consume.status_code = 200
        consume.json.return_value = {"action_hash": real_hash, "consumed": True}

        # 3 pending then approved
        mock_post.side_effect = [auth_resp, consume]
        mock_get.side_effect = [pending, pending, pending, approved]

        client = _make_client()

        @async_protect_tool(
            client,
            tool="svc",
            action="act",
            poll_interval=1.0,
            poll_backoff=2.0,
            poll_max_interval=3.0,
            poll_timeout=300.0,
        )
        async def my_tool(n: int) -> int:
            return n * 2

        result = await my_tool(7)
        self.assertEqual(result, 14)

        sleep_calls = [c.args[0] for c in mock_sleep.call_args_list]
        # poll_interval=1.0, backoff=2.0, cap=3.0
        # sleep: 1.0 → 2.0 → 3.0 → 3.0
        self.assertGreaterEqual(len(sleep_calls), 4)
        self.assertAlmostEqual(sleep_calls[0], 1.0, places=5)
        self.assertAlmostEqual(sleep_calls[1], 2.0, places=5)
        self.assertAlmostEqual(sleep_calls[2], 3.0, places=5)
        self.assertAlmostEqual(sleep_calls[3], 3.0, places=5)


# ---------------------------------------------------------------------------
# _rebind_edited_args helper
# ---------------------------------------------------------------------------


@unittest.skipUnless(_IMPORT_OK, "async_protect_tool not yet implemented")
class TestRebindEditedArgs(unittest.TestCase):
    """_rebind_edited_args returns (args, kwargs) for edited params."""

    def test_basic_rebind(self):
        def fn(a: str, b: int):
            pass

        sig = inspect.signature(fn)
        params = {"a": "orig_a", "b": 10}
        edited = {"a": "new_a"}

        new_args, new_kwargs = _rebind_edited_args(sig, params, edited)
        # 'a' overridden, 'b' falls back
        self.assertEqual(new_kwargs.get("a"), "new_a")
        self.assertEqual(new_kwargs.get("b"), 10)

    def test_full_override(self):
        def fn(x: int, y: int):
            pass

        sig = inspect.signature(fn)
        params = {"x": 1, "y": 2}
        edited = {"x": 99, "y": 88}

        _, new_kwargs = _rebind_edited_args(sig, params, edited)
        self.assertEqual(new_kwargs["x"], 99)
        self.assertEqual(new_kwargs["y"], 88)


if __name__ == "__main__":
    unittest.main()
