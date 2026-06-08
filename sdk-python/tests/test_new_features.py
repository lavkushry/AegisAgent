"""Tests for the new SDK modules: ReceiptAccumulator, evidence pack, CLI, and verify_receipts table.

Covers:
- TASK-0189: Thread-safe receipt accumulator
- TASK-0175: Trust classifier API (set/get)
- TASK-0176: Receipt batch export (JSON lines)
- TASK-0177: Receipt batch export (CSV)
- TASK-0178: Evidence pack generator
- TASK-0179: aegis-verify-receipts CLI table output
- TASK-0180: aegis-export-audit CLI
- TASK-0181: aegis-freeze-agent CLI
- TASK-0182: aegis-status CLI
"""

import csv
import io
import json
import os
import tempfile
import threading
import unittest
import zipfile
from unittest.mock import MagicMock, patch

from aegisagent.accumulator import ReceiptAccumulator
from aegisagent.evidence import create_evidence_pack
from aegisagent.receipts import (
    RECEIPT_HASH_FIELD,
    seal_chain,
    verify_chain,
)
from aegisagent.verify_receipts import _print_table, main as verify_main


class TestReceiptAccumulator(unittest.TestCase):
    """TASK-0189: Thread-safe receipt accumulator."""

    def test_append_returns_sealed_receipt(self):
        acc = ReceiptAccumulator()
        sealed = acc.append({"decision": "allow", "agent_id": "a1"})
        self.assertIn(RECEIPT_HASH_FIELD, sealed)
        self.assertEqual(len(acc), 1)

    def test_chain_returns_snapshot(self):
        acc = ReceiptAccumulator()
        acc.append({"decision": "allow"})
        acc.append({"decision": "deny"})
        chain = acc.chain()
        self.assertEqual(len(chain), 2)
        # Snapshot is a copy — modifying it doesn't change the accumulator
        chain.pop()
        self.assertEqual(len(acc), 2)

    def test_chain_is_verifiable(self):
        acc = ReceiptAccumulator()
        acc.append({"decision": "allow", "agent_id": "a1"})
        acc.append({"decision": "deny", "agent_id": "a1"})
        acc.append({"decision": "require_approval", "agent_id": "a2"})
        self.assertTrue(verify_chain(acc.chain()))

    def test_clear_resets_chain(self):
        acc = ReceiptAccumulator()
        acc.append({"x": 1})
        acc.clear()
        self.assertEqual(len(acc), 0)
        self.assertEqual(acc.chain(), [])

    def test_repr(self):
        acc = ReceiptAccumulator()
        self.assertEqual(repr(acc), "ReceiptAccumulator(len=0)")
        acc.append({"x": 1})
        self.assertEqual(repr(acc), "ReceiptAccumulator(len=1)")

    def test_concurrent_appends_produce_valid_chain(self):
        """Multiple threads appending concurrently should produce a valid chain."""
        acc = ReceiptAccumulator()
        barrier = threading.Barrier(10)

        def worker(idx):
            barrier.wait()
            acc.append({"thread": idx, "decision": "allow"})

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(acc), 10)
        self.assertTrue(verify_chain(acc.chain()))


class TestAccumulatorExport(unittest.TestCase):
    """TASK-0176 (JSONL) and TASK-0177 (CSV) receipt batch export."""

    def setUp(self):
        self.acc = ReceiptAccumulator()
        self.acc.append({"decision": "allow", "agent_id": "a1"})
        self.acc.append({"decision": "deny", "agent_id": "a2"})
        self.tmpdir = tempfile.mkdtemp()

    def test_export_json(self):
        path = os.path.join(self.tmpdir, "receipts.json")
        self.acc.export_json(path)
        with open(path) as f:
            data = json.load(f)
        self.assertEqual(len(data), 2)
        self.assertTrue(verify_chain(data))

    def test_export_jsonl(self):
        path = os.path.join(self.tmpdir, "receipts.jsonl")
        self.acc.export_jsonl(path)
        with open(path) as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 2)
        for line in lines:
            parsed = json.loads(line)
            self.assertIn(RECEIPT_HASH_FIELD, parsed)

    def test_to_jsonl_in_memory(self):
        result = self.acc.to_jsonl()
        lines = result.strip().split("\n")
        self.assertEqual(len(lines), 2)

    def test_export_csv(self):
        path = os.path.join(self.tmpdir, "receipts.csv")
        self.acc.export_csv(path)
        with open(path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        self.assertEqual(len(rows), 2)
        self.assertIn(RECEIPT_HASH_FIELD, rows[0])

    def test_to_csv_in_memory(self):
        result = self.acc.to_csv()
        reader = csv.DictReader(io.StringIO(result))
        rows = list(reader)
        self.assertEqual(len(rows), 2)

    def test_export_empty_csv(self):
        """Empty accumulator should produce empty CSV file."""
        empty = ReceiptAccumulator()
        path = os.path.join(self.tmpdir, "empty.csv")
        empty.export_csv(path)
        with open(path) as f:
            self.assertEqual(f.read(), "")


class TestEvidencePack(unittest.TestCase):
    """TASK-0178: Evidence pack generator."""

    def test_creates_zip_with_all_files(self):
        receipts = seal_chain(
            [
                {"decision": "allow", "agent_id": "a1"},
                {"decision": "deny", "agent_id": "a2"},
            ]
        )
        audit = [{"event_type": "action_authorized", "agent_id": "a1"}]

        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            path = tmp.name

        try:
            create_evidence_pack(
                receipts=receipts,
                output_path=path,
                audit_events=audit,
                metadata={"tenant_id": "t1"},
            )

            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
                self.assertIn("receipts.json", names)
                self.assertIn("receipts.jsonl", names)
                self.assertIn("receipts.csv", names)
                self.assertIn("audit_trail.json", names)
                self.assertIn("manifest.json", names)

                manifest = json.loads(zf.read("manifest.json"))
                self.assertEqual(manifest["receipt_count"], 2)
                self.assertTrue(manifest["chain_verified"])
                self.assertTrue(manifest["has_audit_trail"])
                self.assertEqual(manifest["metadata"]["tenant_id"], "t1")
        finally:
            os.unlink(path)

    def test_without_audit_trail(self):
        receipts = seal_chain([{"decision": "allow"}])

        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            path = tmp.name

        try:
            create_evidence_pack(receipts=receipts, output_path=path)

            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
                self.assertNotIn("audit_trail.json", names)
                manifest = json.loads(zf.read("manifest.json"))
                self.assertFalse(manifest["has_audit_trail"])
        finally:
            os.unlink(path)

    def test_empty_receipts(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            path = tmp.name

        try:
            create_evidence_pack(receipts=[], output_path=path)

            with zipfile.ZipFile(path) as zf:
                manifest = json.loads(zf.read("manifest.json"))
                self.assertEqual(manifest["receipt_count"], 0)
                self.assertTrue(manifest["chain_verified"])
        finally:
            os.unlink(path)


class TestVerifyReceiptsTable(unittest.TestCase):
    """TASK-0179: aegis-verify-receipts --table output."""

    def test_table_flag_prints_header(self):
        receipts = seal_chain(
            [
                {"decision": "allow", "agent_id": "a1"},
                {"decision": "deny", "agent_id": "a2"},
            ]
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump(receipts, tmp)
            tmp_path = tmp.name

        try:
            import io as _io
            import sys as _sys

            captured = _io.StringIO()
            old_stdout = _sys.stdout
            _sys.stdout = captured

            rc = verify_main(["--table", tmp_path])

            _sys.stdout = old_stdout
            output = captured.getvalue()

            self.assertEqual(rc, 0)
            self.assertIn("VERIFIED", output)
            self.assertIn("#", output)
            self.assertIn("OK", output)
        finally:
            os.unlink(tmp_path)

    def test_verify_without_table(self):
        receipts = seal_chain([{"decision": "allow"}])

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump(receipts, tmp)
            tmp_path = tmp.name

        try:
            import io as _io
            import sys as _sys

            captured = _io.StringIO()
            old_stdout = _sys.stdout
            _sys.stdout = captured

            rc = verify_main([tmp_path])

            _sys.stdout = old_stdout
            output = captured.getvalue()

            self.assertEqual(rc, 0)
            self.assertIn("VERIFIED", output)
            # No table header when --table not passed
            self.assertNotIn("#", output.split("VERIFIED")[0])
        finally:
            os.unlink(tmp_path)


class TestTrustClassifierAPI(unittest.TestCase):
    """TASK-0175: Trust classifier API (set_trust_level(), get_trust_level())."""

    def test_set_and_get_trust_level(self):
        from aegisagent.decorator import (
            get_context_trust_level,
            set_context_trust_level,
        )

        set_context_trust_level("trusted_internal")
        self.assertEqual(get_context_trust_level(), "trusted_internal")

        set_context_trust_level("untrusted_external")
        self.assertEqual(get_context_trust_level(), "untrusted_external")

    def test_trust_level_context_manager(self):
        from aegisagent.decorator import (
            get_context_trust_level,
            set_context_trust_level,
            trust_level,
        )

        set_context_trust_level("unknown")
        with trust_level("trusted_internal"):
            self.assertEqual(get_context_trust_level(), "trusted_internal")
        self.assertEqual(get_context_trust_level(), "unknown")

    def test_default_trust_level(self):
        from aegisagent.decorator import get_context_trust_level

        # In a fresh thread, the default should be 'unknown'
        result = {}

        def check():
            result["level"] = get_context_trust_level()

        t = threading.Thread(target=check)
        t.start()
        t.join()
        self.assertEqual(result["level"], "unknown")


class TestCLIStatus(unittest.TestCase):
    """TASK-0182: aegis-status CLI."""

    @patch.dict(os.environ, {"AEGIS_API_KEY": "test_key"})
    @patch("aegisagent.cli.requests.get")
    def test_status_json(self, mock_get):
        from aegisagent.cli import status_main

        health_resp = MagicMock()
        health_resp.status_code = 200
        health_resp.json.return_value = {"status": "healthy", "version": "0.1.0"}

        stats_resp = MagicMock()
        stats_resp.status_code = 200
        stats_resp.json.return_value = {"agents": 5, "decisions": 100}

        mock_get.side_effect = [health_resp, stats_resp]

        import io as _io
        import sys as _sys

        captured = _io.StringIO()
        old_stdout = _sys.stdout
        _sys.stdout = captured

        rc = status_main(["--json"])

        _sys.stdout = old_stdout
        output = captured.getvalue()

        self.assertEqual(rc, 0)
        data = json.loads(output)
        self.assertEqual(data["health"]["status"], "healthy")

    @patch.dict(os.environ, {"AEGIS_API_KEY": "test_key"})
    @patch("aegisagent.cli.requests.get")
    def test_status_text(self, mock_get):
        from aegisagent.cli import status_main

        health_resp = MagicMock()
        health_resp.status_code = 200
        health_resp.json.return_value = {"status": "healthy", "version": "0.1.0"}

        stats_resp = MagicMock()
        stats_resp.status_code = 200
        stats_resp.json.return_value = {"agents": 5}

        mock_get.side_effect = [health_resp, stats_resp]

        import io as _io
        import sys as _sys

        captured = _io.StringIO()
        old_stdout = _sys.stdout
        _sys.stdout = captured

        rc = status_main([])

        _sys.stdout = old_stdout
        output = captured.getvalue()

        self.assertEqual(rc, 0)
        self.assertIn("healthy", output)
        self.assertIn("0.1.0", output)


class TestCLIFreezeAgent(unittest.TestCase):
    """TASK-0181: aegis-freeze-agent CLI."""

    @patch.dict(os.environ, {"AEGIS_API_KEY": "test_key"})
    @patch("aegisagent.cli.requests.post")
    def test_freeze(self, mock_post):
        from aegisagent.cli import freeze_agent_main

        mock_post.return_value = MagicMock(status_code=200)

        import io as _io
        import sys as _sys

        captured = _io.StringIO()
        old_stdout = _sys.stdout
        _sys.stdout = captured

        rc = freeze_agent_main(["agent-42"])

        _sys.stdout = old_stdout
        output = captured.getvalue()

        self.assertEqual(rc, 0)
        self.assertIn("freezed", output.lower().replace("froze", "freezed"))
        mock_post.assert_called_once()
        call_url = mock_post.call_args[0][0]
        self.assertIn("/v1/agents/agent-42/freeze", call_url)

    @patch.dict(os.environ, {"AEGIS_API_KEY": "test_key"})
    @patch("aegisagent.cli.requests.post")
    def test_unfreeze(self, mock_post):
        from aegisagent.cli import freeze_agent_main

        mock_post.return_value = MagicMock(status_code=200)

        import io as _io
        import sys as _sys

        captured = _io.StringIO()
        old_stdout = _sys.stdout
        _sys.stdout = captured

        rc = freeze_agent_main(["--unfreeze", "agent-42"])

        _sys.stdout = old_stdout
        output = captured.getvalue()

        self.assertEqual(rc, 0)
        call_url = mock_post.call_args[0][0]
        self.assertIn("/v1/agents/agent-42/unfreeze", call_url)


class TestCLIExportAudit(unittest.TestCase):
    """TASK-0180: aegis-export-audit CLI."""

    @patch.dict(os.environ, {"AEGIS_API_KEY": "test_key"})
    @patch("aegisagent.cli.requests.get")
    def test_export_stdout(self, mock_get):
        from aegisagent.cli import export_audit_main

        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(
                return_value=[
                    {"event_type": "action_authorized"},
                    {"event_type": "action_denied"},
                ]
            ),
        )

        import io as _io
        import sys as _sys

        captured = _io.StringIO()
        old_stdout = _sys.stdout
        _sys.stdout = captured

        rc = export_audit_main([])

        _sys.stdout = old_stdout
        output = captured.getvalue()

        self.assertEqual(rc, 0)
        data = json.loads(output)
        self.assertEqual(len(data), 2)

    @patch.dict(os.environ, {"AEGIS_API_KEY": "test_key"})
    @patch("aegisagent.cli.requests.get")
    def test_export_jsonl(self, mock_get):
        from aegisagent.cli import export_audit_main

        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(
                return_value=[
                    {"event_type": "action_authorized"},
                ]
            ),
        )

        import io as _io
        import sys as _sys

        captured = _io.StringIO()
        old_stdout = _sys.stdout
        _sys.stdout = captured

        rc = export_audit_main(["--jsonl"])

        _sys.stdout = old_stdout
        output = captured.getvalue()

        self.assertEqual(rc, 0)
        lines = output.strip().split("\n")
        self.assertEqual(len(lines), 1)
        parsed = json.loads(lines[0])
        self.assertEqual(parsed["event_type"], "action_authorized")

    @patch.dict(os.environ, {"AEGIS_API_KEY": "test_key"})
    @patch("aegisagent.cli.requests.get")
    def test_export_to_file(self, mock_get):
        from aegisagent.cli import export_audit_main

        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=[{"event_type": "test"}]),
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            import io as _io
            import sys as _sys

            captured = _io.StringIO()
            old_stdout = _sys.stdout
            _sys.stdout = captured

            rc = export_audit_main(["-o", tmp_path])

            _sys.stdout = old_stdout

            self.assertEqual(rc, 0)
            with open(tmp_path) as f:
                data = json.load(f)
            self.assertEqual(len(data), 1)
        finally:
            os.unlink(tmp_path)


if __name__ == "__main__":
    unittest.main()
