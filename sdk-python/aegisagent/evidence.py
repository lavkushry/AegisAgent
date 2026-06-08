"""Evidence pack generator (TASK-0178).

Creates a self-contained ZIP archive containing receipts (JSON + JSONL),
optional audit trail, and a human-readable manifest.  Intended for SOC 2
evidence collection and EU AI Act Art. 14 compliance audits.

Usage::

    from aegisagent.evidence import create_evidence_pack

    create_evidence_pack(
        receipts=accumulator.chain(),   # or any list[dict]
        output_path="evidence-2026-06-08.zip",
        audit_events=audit_list,        # optional
        metadata={"tenant_id": "t1", "run_id": "run-42"},
    )
"""

import csv
import io
import json
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .receipts import verify_chain


def create_evidence_pack(
    receipts: List[Dict[str, Any]],
    output_path: str,
    audit_events: Optional[List[Dict[str, Any]]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    """Create a ZIP evidence pack at *output_path* and return the path.

    Contents
    --------
    - ``receipts.json``  — full receipt chain as JSON array
    - ``receipts.jsonl`` — one receipt per line (JSON-lines)
    - ``receipts.csv``   — tabular view of the chain
    - ``audit_trail.json`` — (if *audit_events* provided)
    - ``manifest.json``  — metadata + verification summary
    """
    chain_verified = verify_chain(receipts) if receipts else True
    now = datetime.now(timezone.utc).isoformat()

    manifest = {
        "generated_at": now,
        "receipt_count": len(receipts),
        "chain_verified": chain_verified,
        "has_audit_trail": audit_events is not None and len(audit_events) > 0,
        "metadata": metadata or {},
    }

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # receipts.json
        zf.writestr(
            "receipts.json",
            json.dumps(receipts, indent=2, ensure_ascii=False),
        )

        # receipts.jsonl
        jsonl = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in receipts)
        zf.writestr("receipts.jsonl", jsonl)

        # receipts.csv
        if receipts:
            all_keys: set = set()
            for r in receipts:
                all_keys.update(r.keys())
            fields = sorted(all_keys)

            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for receipt in receipts:
                writer.writerow(
                    {
                        k: json.dumps(v) if isinstance(v, (dict, list)) else v
                        for k, v in receipt.items()
                    }
                )
            zf.writestr("receipts.csv", buf.getvalue())
        else:
            zf.writestr("receipts.csv", "")

        # audit_trail.json
        if audit_events:
            zf.writestr(
                "audit_trail.json",
                json.dumps(audit_events, indent=2, ensure_ascii=False),
            )

        # manifest.json
        zf.writestr(
            "manifest.json",
            json.dumps(manifest, indent=2, ensure_ascii=False),
        )

    return output_path
