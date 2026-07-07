"""Phase 7.2 (prompt/model capture, SDK side): client-side redaction for
``AegisClient.emit_prompt_event`` / ``emit_model_call_event``.

The gateway's ``POST /v1/ingest/prompt-events`` (Phase 7.1) has no raw-prompt
column at all and rejects a ``redacted_prompt_preview`` that still looks
unredacted (see ``src/src/routes/prompt_capture.py``'s ``UNREDACTED_MARKERS``,
which this list is kept in sync with). This module does the redaction the
gateway expects to have already happened: replace secret-shaped substrings
before truncating to a bounded preview, so a raw sensitive prompt never
leaves the process — by construction, not by configuration.
"""

import re

# Kept in sync with the gateway's UNREDACTED_MARKERS
# (src/src/routes/prompt_capture.py). Deliberately narrow (well-known token
# prefixes) to avoid false positives on ordinary prose.
_SECRET_PATTERNS = [
    re.compile(r"(?i)bearer\s+\S+"),
    re.compile(r"(?i)sk-[a-z0-9_-]+"),
    re.compile(r"(?i)gh[oprsu]_[a-z0-9]+"),
    re.compile(r"(?i)akia[a-z0-9]+"),
    re.compile(r"(?i)xox[bpa]-\S+"),
    re.compile(r"(?is)-----begin.*?-----end[^\n]*-----"),
]

REDACTED = "[REDACTED]"
DEFAULT_MAX_PREVIEW_LEN = 500


def looks_unredacted(text: str) -> bool:
    """True if ``text`` still contains an obvious secret-shaped substring."""
    return any(pattern.search(text) for pattern in _SECRET_PATTERNS)


def redact_preview(text: str, max_len: int = DEFAULT_MAX_PREVIEW_LEN) -> str:
    """Scrub secret-shaped substrings, then truncate to ``max_len``.

    Truncation happens after scrubbing so a secret straddling the truncation
    boundary is still caught.
    """
    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(REDACTED, redacted)
    return redacted[:max_len]
