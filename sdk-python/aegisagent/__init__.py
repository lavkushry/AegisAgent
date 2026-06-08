from .accumulator import ReceiptAccumulator
from .canon import CANON_VERSION, canonical_hash, canonicalize, sha256_hex
from .client import AegisAsyncClient, AegisClient
from .decorator import (
    async_protect_tool,
    get_context_trust_level,
    protect_tool,
    set_context_trust_level,
    trust_level,
)
from .evidence import create_evidence_pack
from .logging import StructuredJSONFormatter
from .receipts import (
    compute_receipt_hash,
    seal_chain,
    seal_receipt,
    verify_chain,
    verify_receipt,
)

__all__ = [
    "AegisClient",
    "AegisAsyncClient",
    "protect_tool",
    "async_protect_tool",
    "set_context_trust_level",
    "get_context_trust_level",
    "trust_level",
    "StructuredJSONFormatter",
    "ReceiptAccumulator",
    "create_evidence_pack",
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
    "__version__",
]

try:
    from importlib.metadata import version
except ImportError:
    try:
        from importlib_metadata import version  # type: ignore
    except ImportError:
        version = lambda pkg: "0.1.0"

try:
    __version__ = version("aegisagent")
except Exception:
    __version__ = "0.1.0"
