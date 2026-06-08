"""CLI to verify an AegisAgent action-receipt chain (TASK-0179).

Usage::

    python -m aegisagent.verify_receipts <receipts.json>
    aegis-verify-receipts <receipts.json>
    aegis-verify-receipts --table <receipts.json>

Input is a JSON file that is either a list of receipts, or an object with a
``receipts`` array (the shared corpus format). Exit code 0 = verified,
1 = tampered/broken chain, 2 = bad input. This lets auditors verify receipts
independently of the runtime that produced them.

The ``--table`` flag prints a human-readable table with per-receipt
verification status (TASK-0179 improvement).
"""

import argparse
import json
import sys
from typing import Any, List, Optional, Tuple

from .receipts import (
    PREV_HASH_FIELD,
    RECEIPT_HASH_FIELD,
    compute_receipt_hash,
    verify_chain,
    verify_receipt,
)


def _extract(data: Any) -> List[dict]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("receipts"), list):
        return data["receipts"]
    raise ValueError('expected a JSON list of receipts or {"receipts": [...]}')


def _first_failure(
    receipts: List[dict], genesis_prev: str = ""
) -> Tuple[Optional[int], Optional[str]]:
    prev = genesis_prev
    for index, receipt in enumerate(receipts):
        if not verify_receipt(receipt):
            return index, "hash mismatch (tampered receipt)"
        if receipt.get(PREV_HASH_FIELD) != prev:
            return index, "broken chain link"
        prev = receipt[RECEIPT_HASH_FIELD]
    return None, None


def _print_table(receipts: List[dict]) -> None:
    """Print a human-readable table with per-receipt verification status."""
    # Column widths
    idx_w = max(3, len(str(len(receipts) - 1)) + 1) if receipts else 3
    hash_w = 12  # truncated hash display
    status_w = 10
    agent_w = 16
    decision_w = 16

    # Header
    header = (
        f"{'#':<{idx_w}} "
        f"{'Status':<{status_w}} "
        f"{'Hash':<{hash_w}} "
        f"{'Prev':<{hash_w}} "
        f"{'Agent':<{agent_w}} "
        f"{'Decision':<{decision_w}}"
    )
    print(header)
    print("─" * len(header))

    prev = ""
    for i, receipt in enumerate(receipts):
        stored_hash = receipt.get(RECEIPT_HASH_FIELD, "")
        prev_hash = receipt.get(PREV_HASH_FIELD, "")
        recomputed = compute_receipt_hash(receipt)

        # Determine status
        if stored_hash != recomputed:
            status = "TAMPERED"
        elif prev_hash != prev:
            status = "BROKEN"
        else:
            status = "OK"

        agent_id = receipt.get("agent_id", receipt.get("agent", ""))
        if isinstance(agent_id, dict):
            agent_id = agent_id.get("id", "")
        decision = receipt.get("decision", "")

        trunc_hash = stored_hash[:hash_w] if stored_hash else ""
        trunc_prev = prev_hash[:hash_w] if prev_hash else "(genesis)"

        print(
            f"{i:<{idx_w}} "
            f"{status:<{status_w}} "
            f"{trunc_hash:<{hash_w}} "
            f"{trunc_prev:<{hash_w}} "
            f"{str(agent_id)[:agent_w]:<{agent_w}} "
            f"{str(decision)[:decision_w]:<{decision_w}}"
        )

        prev = stored_hash


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aegis-verify-receipts",
        description="Verify an AegisAgent action-receipt chain.",
    )
    parser.add_argument("path", help="Path to a receipts JSON file")
    parser.add_argument(
        "--table",
        action="store_true",
        help="Print a human-readable table with per-receipt status",
    )
    args = parser.parse_args(argv)

    try:
        with open(args.path, encoding="utf-8") as handle:
            data = json.load(handle)
        receipts = _extract(data)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.table:
        _print_table(receipts)
        print()

    if verify_chain(receipts):
        print(f"VERIFIED: {len(receipts)} receipt(s), chain intact.")
        return 0

    index, reason = _first_failure(receipts)
    print(
        f"TAMPERED: chain failed at receipt index {index} ({reason}).",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
