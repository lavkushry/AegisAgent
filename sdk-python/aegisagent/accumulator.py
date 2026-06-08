"""Thread-safe receipt accumulator (TASK-0189).

Accumulates verifiable action receipts emitted during SDK operation in a
thread-safe collection.  The accumulator seals each incoming receipt into
the chain, maintaining a running ``prev_receipt_hash`` so the chain is
always consistent.

Usage::

    acc = ReceiptAccumulator()
    acc.append({"decision": "allow", "agent_id": "a1", ...})
    acc.append({"decision": "deny",  "agent_id": "a1", ...})
    chain = acc.chain()          # list[dict] — sealed receipts
    acc.export_jsonl("out.jsonl") # streaming JSON-lines export
    acc.clear()                  # reset for next run

The accumulator is designed for a single agent-run lifetime.  It is safe
to call ``append`` from multiple threads (e.g. concurrent tool calls).
"""

import csv
import io
import json
import threading
from typing import Any, Dict, List, Optional

from .receipts import GENESIS_PREV, RECEIPT_HASH_FIELD, seal_receipt


class ReceiptAccumulator:
    """Thread-safe, append-only receipt chain builder.

    Each ``append(body)`` seals the receipt into the chain by hashing it with
    the previous receipt's hash, ensuring a tamper-evident linked list.
    """

    def __init__(self, genesis_prev: str = GENESIS_PREV) -> None:
        self._lock = threading.Lock()
        self._chain: List[Dict[str, Any]] = []
        self._prev_hash: str = genesis_prev
        self._genesis_prev = genesis_prev

    def append(self, receipt_body: Dict[str, Any]) -> Dict[str, Any]:
        """Seal *receipt_body* into the chain and return the sealed receipt.

        Thread-safe: only one thread can extend the chain at a time.
        """
        with self._lock:
            sealed = seal_receipt(receipt_body, self._prev_hash)
            self._chain.append(sealed)
            self._prev_hash = sealed[RECEIPT_HASH_FIELD]
            return sealed

    def chain(self) -> List[Dict[str, Any]]:
        """Return a snapshot (copy) of the current receipt chain."""
        with self._lock:
            return list(self._chain)

    def __len__(self) -> int:
        with self._lock:
            return len(self._chain)

    def __repr__(self) -> str:
        with self._lock:
            return f"ReceiptAccumulator(len={len(self._chain)})"

    def clear(self) -> None:
        """Reset the accumulator (new chain)."""
        with self._lock:
            self._chain.clear()
            self._prev_hash = self._genesis_prev

    def export_json(self, path: str) -> None:
        """Write the chain as a JSON array to *path*."""
        snapshot = self.chain()
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh, indent=2, ensure_ascii=False)

    def export_jsonl(self, path: str) -> None:
        """Write the chain as JSON-lines (one receipt per line) to *path*."""
        snapshot = self.chain()
        with open(path, "w", encoding="utf-8") as fh:
            for receipt in snapshot:
                fh.write(json.dumps(receipt, ensure_ascii=False) + "\n")

    def export_csv(self, path: str, fields: Optional[List[str]] = None) -> None:
        """Write the chain as CSV to *path*.

        *fields* controls column order; defaults to sorted union of all keys.
        """
        snapshot = self.chain()
        if not snapshot:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("")
            return

        if fields is None:
            all_keys: set = set()
            for r in snapshot:
                all_keys.update(r.keys())
            fields = sorted(all_keys)

        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for receipt in snapshot:
                writer.writerow(
                    {
                        k: json.dumps(v) if isinstance(v, (dict, list)) else v
                        for k, v in receipt.items()
                    }
                )

    def to_jsonl(self) -> str:
        """Return the chain as a JSON-lines string (in-memory)."""
        snapshot = self.chain()
        return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in snapshot)

    def to_csv(self, fields: Optional[List[str]] = None) -> str:
        """Return the chain as CSV string (in-memory)."""
        snapshot = self.chain()
        if not snapshot:
            return ""

        if fields is None:
            all_keys: set = set()
            for r in snapshot:
                all_keys.update(r.keys())
            fields = sorted(all_keys)

        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for receipt in snapshot:
            writer.writerow(
                {
                    k: json.dumps(v) if isinstance(v, (dict, list)) else v
                    for k, v in receipt.items()
                }
            )
        return buf.getvalue()
