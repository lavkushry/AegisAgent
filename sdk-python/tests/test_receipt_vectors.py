"""Locks the shared receipt-chain corpus and exercises the verifier CLI.

The corpus (tests/receipt_chain_vectors.json) pins exact receipt_hash values
produced by the Python reference impl. The Rust gateway emitter must reproduce
them byte-for-byte, the same way canonical_action_vectors.json locks action_hash.
"""

import json
import tempfile
import unittest
from pathlib import Path

from aegisagent.canon import CANON_VERSION
from aegisagent.receipts import RECEIPT_HASH_FIELD, verify_chain, verify_receipt
from aegisagent.verify_receipts import main as verify_main

_CORPUS_PATH = (
    Path(__file__).resolve().parents[2] / "tests" / "receipt_chain_vectors.json"
)


def _load_corpus() -> dict:
    return json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))


class TestReceiptCorpus(unittest.TestCase):
    def test_corpus_canon_version(self):
        self.assertEqual(_load_corpus()["canon_version"], CANON_VERSION)

    def test_corpus_chain_verifies(self):
        receipts = _load_corpus()["receipts"]
        self.assertTrue(verify_chain(receipts))
        for receipt in receipts:
            self.assertTrue(verify_receipt(receipt))
            self.assertEqual(len(receipt[RECEIPT_HASH_FIELD]), 64)

    def test_corpus_tamper_is_detected(self):
        receipts = _load_corpus()["receipts"]
        receipts[0]["decision"] = "allow"  # was require_approval
        self.assertFalse(verify_chain(receipts))


class TestVerifierCLI(unittest.TestCase):
    def test_cli_verifies_corpus(self):
        self.assertEqual(verify_main([str(_CORPUS_PATH)]), 0)

    def test_cli_detects_tampered_file(self):
        corpus = _load_corpus()
        corpus["receipts"][1]["note"] = "edited after sealing"
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        ) as handle:
            json.dump(corpus, handle, ensure_ascii=False)
            path = handle.name
        self.assertEqual(verify_main([path]), 1)
        Path(path).unlink()

    def test_cli_rejects_bad_input(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        ) as handle:
            json.dump({"not": "receipts"}, handle)
            path = handle.name
        self.assertEqual(verify_main([path]), 2)
        Path(path).unlink()


if __name__ == "__main__":
    unittest.main()
