"""Canonicalization edge-case and receipt chain scaling tests.

Covers:
- TASK-0154 (#1000): Unicode parameter handling in canonicalization
- TASK-0155 (#1002): Empty parameters canonicalization
- TASK-0156 (#1001): Nested object canonicalization (3 levels deep)
- TASK-0157 (#1003): Receipt chain with 1000 entries verifies
- TASK-0161 (#1007): async_protect_tool exists and works
- TASK-0162 (#1008): Exponential backoff parameters exist
- TASK-0163 (#1009): Configurable poll timeout (default 5min)
- TASK-0164 (#1010): Configurable max retries for network errors
"""

import math
import unittest

from aegisagent.canon import CANON_VERSION, canonical_hash, canonicalize
from aegisagent.receipts import seal_chain, verify_chain


class TestCanonUnicode(unittest.TestCase):
    """TASK-0154: Unicode parameter handling in canonicalization."""

    def test_cjk_characters_not_escaped(self):
        """CJK characters must appear as raw UTF-8, not \\uXXXX."""
        result = canonicalize({"key": "日本語テスト"})
        self.assertIn("日本語テスト", result)
        self.assertNotIn("\\u", result)

    def test_emoji_preserved(self):
        result = canonicalize({"emoji": "🔒🛡️"})
        self.assertIn("🔒", result)

    def test_mixed_scripts(self):
        """Mixed Latin, Cyrillic, Arabic should all be raw UTF-8."""
        val = {"lat": "hello", "cyr": "Привет", "ara": "مرحبا"}
        result = canonicalize(val)
        self.assertIn("Привет", result)
        self.assertIn("مرحبا", result)

    def test_unicode_hash_deterministic(self):
        """Same unicode input must always produce the same hash."""
        data = {"tool": "translator", "text": "こんにちは世界"}
        h1 = canonical_hash(data)
        h2 = canonical_hash(data)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)  # SHA-256 hex


class TestCanonEmptyParameters(unittest.TestCase):
    """TASK-0155: Empty parameters canonicalization."""

    def test_empty_dict(self):
        result = canonicalize({})
        self.assertEqual(result, "{}")

    def test_empty_list(self):
        result = canonicalize([])
        self.assertEqual(result, "[]")

    def test_empty_string_value(self):
        result = canonicalize({"key": ""})
        self.assertEqual(result, '{"key":""}')

    def test_null_value(self):
        result = canonicalize({"key": None})
        self.assertEqual(result, '{"key":null}')

    def test_empty_nested(self):
        result = canonicalize({"params": {}})
        self.assertEqual(result, '{"params":{}}')

    def test_action_with_empty_parameters(self):
        """Action hash with empty parameters is consistent."""
        data = {
            "tool": "test",
            "action": "read",
            "resource": None,
            "mutates_state": False,
            "parameters": {},
        }
        h = canonical_hash(data)
        self.assertEqual(len(h), 64)
        # Verify idempotency
        self.assertEqual(h, canonical_hash(data))


class TestCanonNestedObjects(unittest.TestCase):
    """TASK-0156: Nested object canonicalization (3 levels deep)."""

    def test_three_levels_sorted(self):
        data = {
            "z_outer": {
                "z_mid": {"z_inner": 1, "a_inner": 2},
                "a_mid": {"value": 3},
            },
            "a_outer": "first",
        }
        result = canonicalize(data)
        # Keys must be sorted at every level
        self.assertIn('"a_outer"', result)
        # a_outer should come before z_outer
        a_pos = result.index('"a_outer"')
        z_pos = result.index('"z_outer"')
        self.assertLess(a_pos, z_pos)
        # Within z_outer, a_mid before z_mid
        a_mid_pos = result.index('"a_mid"')
        z_mid_pos = result.index('"z_mid"')
        self.assertLess(a_mid_pos, z_mid_pos)
        # Within z_mid, a_inner before z_inner
        a_inner_pos = result.index('"a_inner"')
        z_inner_pos = result.index('"z_inner"')
        self.assertLess(a_inner_pos, z_inner_pos)

    def test_deep_nesting_hash_stability(self):
        deep = {"a": {"b": {"c": {"d": {"e": "leaf"}}}}}
        h1 = canonical_hash(deep)
        h2 = canonical_hash(deep)
        self.assertEqual(h1, h2)

    def test_non_finite_float_rejected(self):
        """Non-finite floats must be rejected (aegis-jcs-1 invariant)."""
        with self.assertRaises(ValueError):
            canonicalize({"val": float("nan")})
        with self.assertRaises(ValueError):
            canonicalize({"val": float("inf")})
        with self.assertRaises(ValueError):
            canonicalize({"val": float("-inf")})


class TestReceiptChainScaling(unittest.TestCase):
    """TASK-0157: Receipt chain with 1000 entries verifies."""

    def test_1000_entry_chain_verifies(self):
        bodies = [{"decision": "allow", "index": i} for i in range(1000)]
        chain = seal_chain(bodies)
        self.assertEqual(len(chain), 1000)
        self.assertTrue(verify_chain(chain))

    def test_1000_entry_chain_detects_tamper(self):
        """Tampering any receipt in a 1000-entry chain is detected."""
        bodies = [{"decision": "allow", "index": i} for i in range(1000)]
        chain = seal_chain(bodies)
        # Tamper receipt at index 500
        chain[500]["decision"] = "deny"
        self.assertFalse(verify_chain(chain))


class TestAlreadyImplementedFeatures(unittest.TestCase):
    """Tests confirming features that are already implemented but need Closes tags."""

    def test_async_protect_tool_exists(self):
        """TASK-0161: async_protect_tool decorator exists."""
        from aegisagent.decorator import async_protect_tool

        self.assertTrue(callable(async_protect_tool))

    def test_exponential_backoff_parameters(self):
        """TASK-0162: protect_tool has poll_backoff parameter."""
        import inspect

        from aegisagent.decorator import protect_tool

        sig = inspect.signature(protect_tool)
        params = sig.parameters
        self.assertIn("poll_backoff", params)
        self.assertEqual(params["poll_backoff"].default, 1.5)
        self.assertIn("poll_max_interval", params)
        self.assertEqual(params["poll_max_interval"].default, 10.0)

    def test_configurable_poll_timeout(self):
        """TASK-0163: protect_tool has poll_timeout defaulting to 5 minutes."""
        import inspect

        from aegisagent.decorator import protect_tool

        sig = inspect.signature(protect_tool)
        self.assertIn("poll_timeout", sig.parameters)
        self.assertEqual(sig.parameters["poll_timeout"].default, 300.0)

    def test_configurable_max_retries(self):
        """TASK-0164: retry_on_5xx has configurable max_retries."""
        import inspect

        from aegisagent.client import retry_on_5xx

        sig = inspect.signature(retry_on_5xx)
        self.assertIn("max_retries", sig.parameters)
        self.assertEqual(sig.parameters["max_retries"].default, 3)

    def test_canon_version_constant(self):
        """Verify CANON_VERSION is aegis-jcs-1."""
        self.assertEqual(CANON_VERSION, "aegis-jcs-1")


if __name__ == "__main__":
    unittest.main()
