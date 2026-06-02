"""CLI to verify an AegisAgent action-receipt chain.

Usage::

    python -m aegisagent.verify_receipts <receipts.json>
    aegis-verify-receipts <receipts.json>

Input is a JSON file that is either a list of receipts, or an object with a
``receipts`` array (the shared corpus format). Exit code 0 = verified,
1 = tampered/broken chain, 2 = bad input. This lets auditors verify receipts
independently of the runtime that produced them.
"""

import argparse
import json
import sys
from typing import Any, List, Optional, Tuple

from .receipts import (
    PREV_HASH_FIELD,
    RECEIPT_HASH_FIELD,
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


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aegis-verify-receipts",
        description="Verify an AegisAgent action-receipt chain.",
    )
    parser.add_argument("path", help="Path to a receipts JSON file")
    args = parser.parse_args(argv)

    try:
        with open(args.path, encoding="utf-8") as handle:
            data = json.load(handle)
        receipts = _extract(data)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

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
