"""Phase 7.2 (prompt/model capture, SDK side) tests.

Covers the plan's stated acceptance for PR 7.2:
- Python SDK can emit prompt/model/tool events when configured.
- Known-agent flow links prompt/model/tool via run_id/trace_id.

And its stated tests:
- no raw sensitive prompt by default
- lineage IDs preserved
"""

import json
import unittest
from unittest.mock import MagicMock, patch

from aegisagent import AegisClient, looks_unredacted, redact_preview


class TestRedactPreview(unittest.TestCase):
    def test_scrubs_bearer_token(self):
        preview = redact_preview("Authorization: Bearer sk-abc123SecretValue")
        self.assertNotIn("sk-abc123SecretValue", preview)
        self.assertFalse(looks_unredacted(preview))

    def test_scrubs_github_token(self):
        preview = redact_preview("use token ghp_abcdefghijklmnopqrstuvwxyz0123456789")
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz0123456789", preview)
        self.assertFalse(looks_unredacted(preview))

    def test_scrubs_aws_access_key(self):
        preview = redact_preview("key: AKIAABCDEFGHIJKLMNOP")
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", preview)
        self.assertFalse(looks_unredacted(preview))

    def test_scrubs_pem_block(self):
        pem = "-----BEGIN PRIVATE KEY-----\nMIIBogIBAAJBAK\n-----END PRIVATE KEY-----"
        preview = redact_preview(f"here is the key: {pem}")
        self.assertNotIn("MIIBogIBAAJBAK", preview)
        self.assertFalse(looks_unredacted(preview))

    def test_ordinary_prose_is_unaffected(self):
        text = "Summarize the attached quarterly earnings report for Acme Corp."
        self.assertEqual(redact_preview(text), text)
        self.assertFalse(looks_unredacted(text))

    def test_truncates_to_max_len(self):
        text = "a" * 1000
        preview = redact_preview(text, max_len=50)
        self.assertEqual(len(preview), 50)


class TestEmitPromptEvent(unittest.TestCase):
    def setUp(self):
        self.client = AegisClient(
            api_key="test_key", agent_id="test_agent", endpoint="http://127.0.0.1:8080"
        )

    @patch("requests.Session.post")
    def test_disabled_by_default_makes_no_network_call(self, mock_post):
        result = self.client.emit_prompt_event("some prompt text")
        self.assertIsNone(result)
        mock_post.assert_not_called()

    @patch("requests.Session.post")
    def test_disabled_by_default_applies_to_model_call_too(self, mock_post):
        result = self.client.emit_model_call_event("openai", "gpt-5")
        self.assertIsNone(result)
        mock_post.assert_not_called()

    @patch("requests.Session.post")
    def test_enabled_never_sends_the_raw_prompt(self, mock_post):
        client = AegisClient(
            api_key="test_key",
            agent_id="test_agent",
            endpoint="http://127.0.0.1:8080",
            capture_prompts=True,
        )
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"ingested": True}
        mock_post.return_value = mock_response

        secret_prompt = (
            "Please use this token: Bearer sk-abcSuperSecretDoNotLeakThisToken123"
        )
        client.emit_prompt_event(secret_prompt, role="user")

        mock_post.assert_called_once()
        sent_body = mock_post.call_args.kwargs["json"]
        sent_json_str = json.dumps(sent_body)
        self.assertNotIn("SuperSecretDoNotLeakThisToken123", sent_json_str)
        self.assertNotIn(secret_prompt, sent_json_str)
        self.assertIn("prompt_hash", sent_body)
        self.assertEqual(len(sent_body["prompt_hash"]), 64)

    @patch("requests.Session.post")
    def test_enabled_preserves_lineage_ids(self, mock_post):
        client = AegisClient(
            api_key="test_key",
            agent_id="test_agent",
            endpoint="http://127.0.0.1:8080",
            capture_prompts=True,
        )
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"ingested": True}
        mock_post.return_value = mock_response

        client.emit_prompt_event("hello", run_id="run-xyz", trace_id="trace-abc")

        sent_body = mock_post.call_args.kwargs["json"]
        self.assertEqual(sent_body["run_id"], "run-xyz")
        self.assertEqual(sent_body["trace_id"], "trace-abc")

    @patch("requests.Session.post")
    def test_enabled_model_call_never_sends_raw_request_or_response(self, mock_post):
        client = AegisClient(
            api_key="test_key",
            agent_id="test_agent",
            endpoint="http://127.0.0.1:8080",
            capture_prompts=True,
        )
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"ingested": True}
        mock_post.return_value = mock_response

        secret_request = "system: sk-liveRequestSecretAbc123"
        secret_response = "response contains AKIAABCDEFGHIJKLMNOP"
        client.emit_model_call_event(
            "openai",
            "gpt-5",
            request_text=secret_request,
            response_text=secret_response,
            run_id="run-1",
            trace_id="trace-1",
        )

        sent_body = mock_post.call_args.kwargs["json"]
        sent_json_str = json.dumps(sent_body)
        self.assertNotIn("sk-liveRequestSecretAbc123", sent_json_str)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", sent_json_str)
        self.assertEqual(len(sent_body["request_hash"]), 64)
        self.assertEqual(len(sent_body["response_hash"]), 64)
        self.assertEqual(sent_body["run_id"], "run-1")
        self.assertEqual(sent_body["trace_id"], "trace-1")

    @patch("requests.Session.post")
    def test_ingest_rejection_is_reported_as_none(self, mock_post):
        client = AegisClient(
            api_key="test_key",
            agent_id="test_agent",
            endpoint="http://127.0.0.1:8080",
            capture_prompts=True,
        )
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = (
            "prompt_hash must be a 64-character lowercase hex SHA-256 digest"
        )
        mock_post.return_value = mock_response

        result = client.emit_prompt_event("hello")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
