"""Tests for the unified `aegis` CLI dispatcher and its subcommands (#1202)."""

import json
import os
import unittest
from unittest.mock import MagicMock, patch

from aegisagent import cli


def _mock_response(status_code=200, json_data=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data if json_data is not None else {}
    resp.text = text
    return resp


class TestColorHelpers(unittest.TestCase):
    @patch("sys.stdout.isatty", return_value=True)
    def test_colorize_wraps_text_in_ansi_codes_on_a_tty(self, _isatty):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NO_COLOR", None)
            result = cli._colorize("hello", cli.GREEN)
        self.assertIn("hello", result)
        self.assertIn("\x1b[", result)

    @patch("sys.stdout.isatty", return_value=False)
    def test_colorize_is_a_noop_when_not_a_tty(self, _isatty):
        result = cli._colorize("hello", cli.GREEN)
        self.assertEqual(result, "hello")

    @patch("sys.stdout.isatty", return_value=True)
    def test_colorize_is_a_noop_when_no_color_env_set(self, _isatty):
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            result = cli._colorize("hello", cli.GREEN)
        self.assertEqual(result, "hello")


class TestStatusMain(unittest.TestCase):
    @patch.dict(os.environ, {"AEGIS_API_KEY": "test-key"})
    @patch("aegisagent.cli.requests.get")
    def test_status_main_format_json_outputs_valid_json(self, mock_get):
        mock_get.side_effect = [
            _mock_response(200, {"status": "ok", "version": "0.1.0"}),
            _mock_response(200, {"agents": 3}),
        ]
        with patch("sys.stdout") as mock_stdout:
            code = cli.status_main(["--format", "json"])
        self.assertEqual(code, 0)
        printed = "".join(
            call.args[0] for call in mock_stdout.write.call_args_list if call.args
        )
        parsed = json.loads(printed)
        self.assertEqual(parsed["health"]["status"], "ok")
        self.assertEqual(parsed["stats"]["agents"], 3)

    @patch.dict(os.environ, {"AEGIS_API_KEY": "test-key"})
    @patch("aegisagent.cli.requests.get")
    def test_status_main_legacy_json_flag_still_works(self, mock_get):
        mock_get.side_effect = [
            _mock_response(200, {"status": "ok"}),
            _mock_response(200, {}),
        ]
        with patch("sys.stdout") as mock_stdout:
            code = cli.status_main(["--json"])
        self.assertEqual(code, 0)
        printed = "".join(
            call.args[0] for call in mock_stdout.write.call_args_list if call.args
        )
        json.loads(printed)  # must not raise

    @patch.dict(os.environ, {"AEGIS_API_KEY": "test-key"})
    @patch("aegisagent.cli.requests.get", side_effect=ConnectionError("boom"))
    def test_status_main_unreachable_gateway_returns_1(self, _mock_get):
        code = cli.status_main([])
        self.assertEqual(code, 1)


class TestFreezeAgentMain(unittest.TestCase):
    @patch.dict(os.environ, {"AEGIS_API_KEY": "test-key"})
    @patch("aegisagent.cli.requests.post")
    def test_freeze_agent_main_success_format_json(self, mock_post):
        mock_post.return_value = _mock_response(200)
        with patch("sys.stdout") as mock_stdout:
            code = cli.freeze_agent_main(["agent-1", "--format", "json"])
        self.assertEqual(code, 0)
        printed = "".join(
            call.args[0] for call in mock_stdout.write.call_args_list if call.args
        )
        parsed = json.loads(printed)
        self.assertEqual(parsed["status"], "ok")
        self.assertEqual(parsed["action"], "freeze")

    @patch.dict(os.environ, {"AEGIS_API_KEY": "test-key"})
    @patch("aegisagent.cli.requests.post")
    def test_freeze_agent_main_unfreeze_flag_posts_to_unfreeze_endpoint(
        self, mock_post
    ):
        mock_post.return_value = _mock_response(200)
        code = cli.freeze_agent_main(["agent-1", "--unfreeze"])
        self.assertEqual(code, 0)
        called_url = mock_post.call_args.args[0]
        self.assertTrue(called_url.endswith("/v1/agents/agent-1/unfreeze"))

    @patch.dict(os.environ, {"AEGIS_API_KEY": "test-key"})
    @patch("aegisagent.cli.requests.post")
    def test_freeze_agent_main_failure_returns_1(self, mock_post):
        mock_post.return_value = _mock_response(404, text="agent not found")
        code = cli.freeze_agent_main(["missing-agent"])
        self.assertEqual(code, 1)


class TestSocSummaryMain(unittest.TestCase):
    @patch.dict(os.environ, {"AEGIS_API_KEY": "test-key"})
    @patch("aegisagent.cli.requests.get")
    def test_soc_summary_main_format_json(self, mock_get):
        mock_get.return_value = _mock_response(
            200, {"open_alerts": 2, "open_incidents": 1}
        )
        with patch("sys.stdout") as mock_stdout:
            code = cli.soc_summary_main(["--format", "json"])
        self.assertEqual(code, 0)
        printed = "".join(
            call.args[0] for call in mock_stdout.write.call_args_list if call.args
        )
        parsed = json.loads(printed)
        self.assertEqual(parsed["open_alerts"], 2)

    @patch.dict(os.environ, {"AEGIS_API_KEY": "test-key"})
    @patch("aegisagent.cli.requests.get")
    def test_soc_summary_main_failure_returns_1(self, mock_get):
        mock_get.return_value = _mock_response(500, text="internal error")
        code = cli.soc_summary_main([])
        self.assertEqual(code, 1)


class TestDispatcher(unittest.TestCase):
    def test_main_dispatches_status(self):
        with patch("aegisagent.cli.status_main", return_value=0) as mock_status:
            code = cli.main(["status", "--format", "json"])
        mock_status.assert_called_once_with(["--format", "json"])
        self.assertEqual(code, 0)

    def test_main_dispatches_freeze_agent(self):
        with patch("aegisagent.cli.freeze_agent_main", return_value=0) as mock_freeze:
            code = cli.main(["freeze-agent", "agent-1"])
        mock_freeze.assert_called_once_with(["agent-1"])
        self.assertEqual(code, 0)

    def test_main_dispatches_unfreeze_agent_forcing_unfreeze_flag(self):
        with patch("aegisagent.cli.freeze_agent_main", return_value=0) as mock_freeze:
            code = cli.main(["unfreeze-agent", "agent-1"])
        mock_freeze.assert_called_once_with(["agent-1", "--unfreeze"])
        self.assertEqual(code, 0)

    def test_main_dispatches_export_audit(self):
        with patch("aegisagent.cli.export_audit_main", return_value=0) as mock_export:
            code = cli.main(["export-audit", "--limit", "5"])
        mock_export.assert_called_once_with(["--limit", "5"])
        self.assertEqual(code, 0)

    def test_main_dispatches_soc_summary(self):
        with patch("aegisagent.cli.soc_summary_main", return_value=0) as mock_soc:
            code = cli.main(["soc-summary"])
        mock_soc.assert_called_once_with([])
        self.assertEqual(code, 0)

    def test_main_dispatches_verify_receipts(self):
        with patch("aegisagent.verify_receipts.main", return_value=0) as mock_verify:
            code = cli.main(["verify-receipts", "receipts.json"])
        mock_verify.assert_called_once_with(["receipts.json"])
        self.assertEqual(code, 0)

    def test_main_unknown_subcommand_returns_2(self):
        code = cli.main(["not-a-real-subcommand"])
        self.assertEqual(code, 2)

    def test_main_no_args_returns_2(self):
        code = cli.main([])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
