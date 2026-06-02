"""Shared canonicalization (scheme ``aegis-jcs-1``).

Byte-identical output is required across the Python/TS/Go SDKs and the Rust
gateway, because both ``action_hash`` (approval integrity) and ``receipt_hash``
(verifiable receipts) are SHA-256 over a canonical string. A divergence here
silently breaks the fail-closed guarantees.

Scheme ``aegis-jcs-1``:
- object keys sorted by Unicode code point
- compact separators (no spaces)
- raw UTF-8 (``ensure_ascii=False`` -> no ``\\uXXXX`` escaping of non-ASCII)
- non-finite floats rejected (``allow_nan=False``)

Locked by shared vectors in ``tests/canonical_action_vectors.json`` and the
spec in ``docs/action-receipt-spec.md``.
"""

import hashlib
import json
from typing import Any

CANON_VERSION = "aegis-jcs-1"


def canonicalize(value: Any) -> str:
    """Return the deterministic canonical JSON string for ``value``."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_hex(text: str) -> str:
    """Lowercase hex SHA-256 of ``text`` encoded as UTF-8."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_hash(value: Any) -> str:
    """SHA-256 hex of the canonical serialization of ``value``."""
    return sha256_hex(canonicalize(value))
