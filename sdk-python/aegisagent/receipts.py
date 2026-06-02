"""Verifiable action receipts (open format, scheme ``aegis-jcs-1``).

A receipt is a tamper-evident record of one agent-action decision. Receipts
form a per-tenant hash chain:

    receipt_hash = SHA-256(canonicalize(body))

where ``body`` is every receipt field EXCEPT ``receipt_hash`` and INCLUDES
``prev_receipt_hash``. Because the previous link is inside the hashed body,
altering any field or re-linking the chain is detectable. This module is the
reference verifier; the gateway emits receipts in the same format so auditors
can verify them independently of the runtime. See ``docs/action-receipt-spec.md``.
"""

from typing import Any, Dict, List

from .canon import canonical_hash

#: ``prev_receipt_hash`` value for the first receipt in a chain.
GENESIS_PREV = ""

RECEIPT_HASH_FIELD = "receipt_hash"
PREV_HASH_FIELD = "prev_receipt_hash"


def _body(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """The hashed portion of a receipt: all fields except ``receipt_hash``."""
    return {k: v for k, v in receipt.items() if k != RECEIPT_HASH_FIELD}


def compute_receipt_hash(receipt: Dict[str, Any]) -> str:
    """SHA-256 of the canonical body (all fields except ``receipt_hash``)."""
    return canonical_hash(_body(receipt))


def seal_receipt(
    receipt: Dict[str, Any], prev_receipt_hash: str = GENESIS_PREV
) -> Dict[str, Any]:
    """Return a NEW receipt with ``prev_receipt_hash`` set and ``receipt_hash``
    computed. Does not mutate the input."""
    body = _body(receipt)
    body[PREV_HASH_FIELD] = prev_receipt_hash
    sealed = dict(body)
    sealed[RECEIPT_HASH_FIELD] = canonical_hash(body)
    return sealed


def seal_chain(
    receipts: List[Dict[str, Any]], genesis_prev: str = GENESIS_PREV
) -> List[Dict[str, Any]]:
    """Seal a list of receipt bodies into a linked chain. Returns new dicts."""
    chain: List[Dict[str, Any]] = []
    prev = genesis_prev
    for receipt in receipts:
        sealed = seal_receipt(receipt, prev)
        chain.append(sealed)
        prev = sealed[RECEIPT_HASH_FIELD]
    return chain


def verify_receipt(receipt: Dict[str, Any]) -> bool:
    """True if the receipt's stored ``receipt_hash`` matches its recomputed hash."""
    stored = receipt.get(RECEIPT_HASH_FIELD)
    if not stored:
        return False
    return compute_receipt_hash(receipt) == stored


def verify_chain(
    receipts: List[Dict[str, Any]], genesis_prev: str = GENESIS_PREV
) -> bool:
    """True if every receipt verifies AND each link references the prior
    receipt's hash (the first must reference ``genesis_prev``)."""
    prev = genesis_prev
    for receipt in receipts:
        if not verify_receipt(receipt):
            return False
        if receipt.get(PREV_HASH_FIELD) != prev:
            return False
        prev = receipt[RECEIPT_HASH_FIELD]
    return True
