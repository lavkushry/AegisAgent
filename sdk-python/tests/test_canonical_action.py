"""Cross-language canonicalization contract tests.

The SDK and the Rust gateway must hash a tool call to the SAME bytes, or the
fail-closed approval guarantee (approved action_hash == executed action_hash)
breaks. These tests pin the SDK side to the shared corpus in tests/. A matching
Rust test (gateway/src/routes.rs) pins the gateway side to the same corpus, so
equality across languages holds transitively.
"""

import hashlib
import json
import unittest
from pathlib import Path

from aegisagent.decorator import _canonical_action, _hash_tool_call

_CORPUS_PATH = (
    Path(__file__).resolve().parents[2] / "tests" / "canonical_action_vectors.json"
)


def _load_vectors() -> list[dict]:
    data = json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))
    return data["vectors"]


class TestCanonicalAction(unittest.TestCase):
    def test_canonical_string_matches_corpus(self) -> None:
        for vector in _load_vectors():
            tc = vector["tool_call"]
            with self.subTest(vector=vector["name"]):
                produced = _canonical_action(
                    tool=tc["tool"],
                    action=tc["action"],
                    resource=tc["resource"],
                    mutates_state=tc["mutates_state"],
                    parameters=tc["parameters"],
                )
                self.assertEqual(produced, vector["canonical"])

    def test_hash_matches_sha256_of_canonical(self) -> None:
        for vector in _load_vectors():
            tc = vector["tool_call"]
            expected_hash = hashlib.sha256(
                vector["canonical"].encode("utf-8")
            ).hexdigest()
            with self.subTest(vector=vector["name"]):
                produced_hash = _hash_tool_call(
                    tool=tc["tool"],
                    action=tc["action"],
                    resource=tc["resource"],
                    mutates_state=tc["mutates_state"],
                    parameters=tc["parameters"],
                )
                self.assertEqual(produced_hash, expected_hash)

    def test_non_ascii_is_not_escaped(self) -> None:
        # Regression: Python json.dumps defaults to ensure_ascii=True, which
        # escapes non-ASCII to \uXXXX and diverges from the gateway's raw UTF-8.
        canonical = _canonical_action(
            tool="github",
            action="create_pull_request",
            resource=None,
            mutates_state=True,
            parameters={"title": "Café ☕"},
        )
        self.assertIn("Café ☕", canonical)
        self.assertNotIn("\\u", canonical)

    def test_canonicalize_empty_object(self) -> None:
        """Empty parameters dict must produce a stable canonical string (TASK-0212)."""
        canonical = _canonical_action(
            tool="noop",
            action="ping",
            resource=None,
            mutates_state=False,
            parameters={},
        )
        self.assertIn('"parameters":{}', canonical)
        parsed = json.loads(canonical)
        self.assertEqual(parsed["parameters"], {})

    def test_canonicalize_nested_arrays(self) -> None:
        """Arrays (including nested) must be preserved verbatim — aegis-jcs-1
        only sorts *object* keys, not array elements (TASK-0213)."""
        canonical = _canonical_action(
            tool="deploy",
            action="rollout",
            resource="cluster/prod",
            mutates_state=True,
            parameters={"targets": ["us-east-1", "eu-west-1"], "flags": [1, [2, 3]]},
        )
        parsed = json.loads(canonical)
        self.assertEqual(parsed["parameters"]["targets"], ["us-east-1", "eu-west-1"])
        self.assertEqual(parsed["parameters"]["flags"], [1, [2, 3]])

    def test_canonicalize_null_values(self) -> None:
        """None / JSON null must round-trip correctly and keys must be sorted
        by Unicode code point (TASK-0214)."""
        canonical = _canonical_action(
            tool="github",
            action="create_issue",
            resource=None,
            mutates_state=True,
            parameters={"assignee": None, "milestone": None, "title": "fix"},
        )
        parsed = json.loads(canonical)
        self.assertIsNone(parsed["parameters"]["assignee"])
        self.assertIsNone(parsed["parameters"]["milestone"])
        # Keys sorted: 'assignee' < 'milestone' < 'title'
        self.assertLess(canonical.index('"assignee"'), canonical.index('"milestone"'))
        self.assertLess(canonical.index('"milestone"'), canonical.index('"title"'))


if __name__ == "__main__":
    unittest.main()
