"""Webhook and Slack callback handling (TASK-0183, TASK-0184).

Provides a lightweight helper for SDK-side approval webhook/callback
handling and HMAC-SHA256 signature verification (Slack style).

Usage::

    from aegisagent.webhooks import verify_slack_signature, WebhookHandler

    # Verify an incoming Slack callback
    if verify_slack_signature(body, timestamp, signature, signing_secret):
        process(body)

    # Register a webhook handler
    handler = WebhookHandler(signing_secret="whsec_...")
    handler.on_approved(lambda approval: print(f"Approved: {approval}"))
    handler.on_rejected(lambda approval: print(f"Rejected: {approval}"))
    handler.handle(raw_body, timestamp, signature)
"""

import hashlib
import hmac
import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("aegisagent")


def verify_slack_signature(
    body: bytes,
    timestamp: str,
    signature: str,
    signing_secret: str,
    *,
    max_age_seconds: int = 300,
) -> bool:
    """Verify a Slack-style HMAC-SHA256 request signature.

    The signature scheme matches Slack's request signing:
    ``v0=HMAC-SHA256(signing_secret, "v0:{timestamp}:{body}")``

    Parameters
    ----------
    body : bytes
        Raw request body bytes.
    timestamp : str
        Unix timestamp string from the ``X-Slack-Request-Timestamp`` header.
    signature : str
        Signature string from the ``X-Slack-Signature`` header (``v0=...``).
    signing_secret : str
        The signing secret for HMAC computation.
    max_age_seconds : int
        Maximum age of the timestamp to prevent replay attacks (default: 300s).

    Returns
    -------
    bool
        True if the signature is valid and the timestamp is fresh.
    """
    if not all([body is not None, timestamp, signature, signing_secret]):
        return False

    # Replay protection: reject old timestamps
    try:
        ts = int(timestamp)
    except (ValueError, TypeError):
        return False

    if abs(time.time() - ts) > max_age_seconds:
        logger.warning("Webhook timestamp too old or too far in the future.")
        return False

    # Compute expected signature
    sig_basestring = f"v0:{timestamp}:{body.decode('utf-8', errors='replace')}"
    expected = (
        "v0="
        + hmac.new(
            signing_secret.encode("utf-8"),
            sig_basestring.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
    )

    return hmac.compare_digest(expected, signature)


class WebhookHandler:
    """Dispatch incoming approval webhook callbacks to registered handlers.

    Parameters
    ----------
    signing_secret : str, optional
        If provided, all incoming requests are verified via Slack-style
        HMAC-SHA256 before dispatching.
    """

    def __init__(self, signing_secret: Optional[str] = None) -> None:
        self._signing_secret = signing_secret
        self._handlers: Dict[str, List[Callable]] = {
            "APPROVED": [],
            "REJECTED": [],
            "EDITED": [],
            "EXPIRED": [],
        }

    def on_approved(self, fn: Callable[[Dict[str, Any]], None]) -> None:
        """Register a handler for APPROVED decisions."""
        self._handlers["APPROVED"].append(fn)

    def on_rejected(self, fn: Callable[[Dict[str, Any]], None]) -> None:
        """Register a handler for REJECTED decisions."""
        self._handlers["REJECTED"].append(fn)

    def on_edited(self, fn: Callable[[Dict[str, Any]], None]) -> None:
        """Register a handler for EDITED (re-parameterized) approvals."""
        self._handlers["EDITED"].append(fn)

    def on_expired(self, fn: Callable[[Dict[str, Any]], None]) -> None:
        """Register a handler for EXPIRED approvals."""
        self._handlers["EXPIRED"].append(fn)

    def handle(
        self,
        raw_body: bytes,
        timestamp: Optional[str] = None,
        signature: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Process an incoming webhook callback.

        If a signing_secret was configured, ``timestamp`` and ``signature``
        are required and will be verified before dispatching.

        Returns the parsed payload dict.

        Raises
        ------
        PermissionError
            If signature verification fails.
        ValueError
            If the payload cannot be parsed or has no ``status`` field.
        """
        # Signature verification
        if self._signing_secret:
            if not timestamp or not signature:
                raise PermissionError(
                    "Webhook signature verification required but timestamp/signature missing."
                )
            if not verify_slack_signature(
                raw_body, timestamp, signature, self._signing_secret
            ):
                raise PermissionError("Webhook signature verification failed.")

        # Parse payload
        try:
            payload = json.loads(raw_body)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"Invalid webhook payload: {e}") from e

        status = payload.get("status")
        if not status:
            raise ValueError("Webhook payload missing 'status' field.")

        # Dispatch to registered handlers
        handlers = self._handlers.get(status, [])
        for handler in handlers:
            try:
                handler(payload)
            except Exception as exc:
                logger.error(f"Webhook handler error for status={status}: {exc}")

        return payload

    def __repr__(self) -> str:
        counts = {k: len(v) for k, v in self._handlers.items() if v}
        return f"WebhookHandler(handlers={counts})"
