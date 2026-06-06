from .canon import CANON_VERSION, canonical_hash, canonicalize, sha256_hex
from .client import AegisClient
from .decorator import (
    async_protect_tool,
    get_context_trust_level,
    protect_tool,
    set_context_trust_level,
)
from .receipts import (
    compute_receipt_hash,
    seal_chain,
    seal_receipt,
    verify_chain,
    verify_receipt,
)

__all__ = [
    "AegisClient",
    "protect_tool",
    "async_protect_tool",
    "set_context_trust_level",
    "get_context_trust_level",
    # canonicalization (scheme aegis-jcs-1)
    "CANON_VERSION",
    "canonicalize",
    "canonical_hash",
    "sha256_hex",
    # verifiable action receipts
    "seal_receipt",
    "seal_chain",
    "compute_receipt_hash",
    "verify_receipt",
    "verify_chain",
]
