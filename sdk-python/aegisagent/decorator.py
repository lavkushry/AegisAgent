import inspect
import logging
import re
import threading
import time
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Optional

from opentelemetry import trace

from .canon import canonicalize, sha256_hex
from .client import AegisClient

logger = logging.getLogger("aegisagent")

# Thread-local storage to pass trust level context along agent run execution
_context_store = threading.local()


def set_context_trust_level(trust_level: str):
    """Sets the source trust level for the current thread context."""
    _context_store.trust_level = trust_level


def get_context_trust_level() -> str:
    """Gets the source trust level for the current thread context (default: 'unknown')."""
    return getattr(_context_store, "trust_level", "unknown")


def _canonical_action(
    tool: str,
    action: str,
    resource: Optional[str],
    mutates_state: bool,
    parameters: dict,
) -> str:
    # Canonicalization (scheme aegis-jcs-1) MUST stay byte-identical with the
    # gateway, or the fail-closed approval guarantee breaks. See canon.py and
    # tests/canonical_action_vectors.json.
    return canonicalize(
        {
            "tool": tool,
            "action": action,
            "resource": resource,
            "mutates_state": mutates_state,
            "parameters": parameters,
        }
    )


def _hash_tool_call(
    tool: str,
    action: str,
    resource: Optional[str],
    mutates_state: bool,
    parameters: dict,
) -> str:
    return sha256_hex(
        _canonical_action(tool, action, resource, mutates_state, parameters)
    )


def _assert_matching_action_hash(source: dict, expected_hash: str, phase: str) -> None:
    action_hash = source.get("action_hash")
    if not action_hash:
        raise PermissionError(
            f"Approval {phase} did not include an action hash. Failing closed."
        )
    if action_hash != expected_hash:
        raise PermissionError(f"Approval {phase} action hash mismatch. Failing closed.")


def _parse_rfc3339(value: Any) -> Optional[datetime]:
    """Parse an RFC 3339 / ISO 8601 timestamp (as emitted by the gateway's
    chrono DateTime<Utc>) into an aware UTC datetime. Returns None if it cannot
    be parsed, so callers can degrade gracefully rather than crash a legit flow.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    # chrono may emit up to 9 fractional digits; datetime.fromisoformat accepts
    # at most 6 before Python 3.11, so truncate the extras.
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _approval_expired(expires_at: Any) -> bool:
    """True if the approval window has passed. Unparseable/missing timestamps
    return False (do not break a legitimate flow; the poll timeout still bounds it)."""
    deadline = _parse_rfc3339(expires_at)
    if deadline is None:
        return False
    return datetime.now(timezone.utc) >= deadline


def protect_tool(
    client: AegisClient,
    tool: str,
    action: str,
    resource_extractor: Optional[Callable[..., str]] = None,
    default_source_trust: Optional[str] = None,
):
    """Decorator to intercept and authorize agent tool functions."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # 1. Resolve trace information from OpenTelemetry context if active
            span = trace.get_current_span()
            span_context = span.get_span_context() if span else None
            trace_id = None
            if span_context and span_context.is_valid:
                trace_id = format(span_context.trace_id, "032x")

            # 2. Extract function parameters dynamically using inspect
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()
            parameters = dict(bound_args.arguments)

            # 3. Resolve resource string if extractor is defined
            resource = None
            if resource_extractor:
                try:
                    resource = resource_extractor(*args, **kwargs)
                except Exception as e:
                    logger.warning(f"Failed to extract resource: {e}")

            # 4. Resolve trust level context
            source_trust = default_source_trust or get_context_trust_level()

            expected_action_hash = _hash_tool_call(
                tool=tool,
                action=action,
                resource=resource,
                mutates_state=True,
                parameters=parameters,
            )

            # 5. Call authorize endpoint
            auth_response = client.authorize(
                tool=tool,
                action=action,
                parameters=parameters,
                resource=resource,
                source_trust=source_trust,
                trace_id=trace_id,
            )

            decision = auth_response.get("decision", "deny")
            reason = auth_response.get("reason", "No reason provided.")

            if decision == "allow":
                logger.debug(f"Action '{tool}.{action}' allowed by policy.")
                return func(*args, **kwargs)

            elif decision == "deny":
                err_msg = f"Action '{tool}.{action}' was DENIED. Reason: {reason}"
                logger.error(err_msg)
                raise PermissionError(err_msg)

            elif decision == "require_approval":
                approval = auth_response.get("approval")
                if not approval:
                    raise PermissionError(
                        f"Action '{tool}.{action}' requires approval but no approval info was returned. Failing closed."
                    )

                _assert_matching_action_hash(approval, expected_action_hash, "response")

                approval_id = approval.get("approval_id")
                expires_at_value = approval.get("expires_at")
                group = approval.get("approver_group", "default")

                # Fail closed if the approval window has already passed.
                if _approval_expired(expires_at_value):
                    raise PermissionError(
                        f"Action '{tool}.{action}' approval already expired "
                        f"(expires_at={expires_at_value}). Failing closed."
                    )
                logger.warning(
                    f"⚠️ Action '{tool}.{action}' PAUSED. Requires approval from group '{group}'.\n"
                    f"Approval ID: {approval_id}\n"
                    f"Reason: {reason}\n"
                    f"Waiting for human reviewer..."
                )

                # Poll gateway for approval decision (timeout after 5 minutes/150 iterations)
                poll_interval = 2.0
                max_polls = 150
                for _ in range(max_polls):
                    time.sleep(poll_interval)
                    status_info = client.get_approval_status(approval_id)
                    if not status_info:
                        continue

                    # Refresh expiry from the latest status and fail closed if the
                    # window has passed, before acting on any decision.
                    expires_at_value = status_info.get("expires_at") or expires_at_value
                    if _approval_expired(expires_at_value):
                        raise PermissionError(
                            f"Action '{tool}.{action}' approval expired before "
                            f"completion (expires_at={expires_at_value}). Failing closed."
                        )

                    status = status_info.get("status")
                    if status == "APPROVED":
                        _assert_matching_action_hash(
                            status_info, expected_action_hash, "status"
                        )
                        # Single-use: atomically consume the approval before
                        # executing, so it cannot be replayed/reused. Fail closed
                        # if the gateway will not hand out the consumption.
                        consumed = client.consume_approval(approval_id)
                        if not consumed:
                            raise PermissionError(
                                f"Action '{tool}.{action}' approval could not be "
                                "consumed (already used/expired). Failing closed."
                            )
                        _assert_matching_action_hash(
                            consumed, expected_action_hash, "consume"
                        )
                        logger.warning(
                            f"✅ Action '{tool}.{action}' APPROVED. Resuming..."
                        )
                        return func(*args, **kwargs)

                    elif status == "REJECTED":
                        reject_reason = status_info.get(
                            "reason", "No reject reason specified."
                        )
                        err_msg = f"❌ Action '{tool}.{action}' REJECTED by reviewer. Reason: {reject_reason}"
                        logger.error(err_msg)
                        raise PermissionError(err_msg)

                    elif status == "EDITED":
                        _assert_matching_action_hash(
                            status_info, expected_action_hash, "status"
                        )
                        # Reviewer edited parameters! Extract edited parameters and invoke function with them
                        edited_call = status_info.get("edited_tool_call")
                        if not edited_call:
                            raise PermissionError(
                                "Action was EDITED but no edited parameters were returned. Failing closed."
                            )

                        edited_params = edited_call.get("parameters", {})
                        logger.warning(
                            f"📝 Action '{tool}.{action}' APPROVED with EDITED parameters: {edited_params}. Resuming..."
                        )

                        # Re-bind arguments using edited parameters
                        new_args = []
                        new_kwargs = {}
                        for param_name, param in sig.parameters.items():
                            if param_name in edited_params:
                                val = edited_params[param_name]
                                if param.kind == inspect.Parameter.POSITIONAL_ONLY:
                                    new_args.append(val)
                                else:
                                    new_kwargs[param_name] = val
                            else:
                                # Fallback to original value
                                if param_name in parameters:
                                    val = parameters[param_name]
                                    if param.kind == inspect.Parameter.POSITIONAL_ONLY:
                                        new_args.append(val)
                                    else:
                                        new_kwargs[param_name] = val

                        return func(*new_args, **new_kwargs)

                raise TimeoutError(
                    f"Action '{tool}.{action}' approval request timed out after 5 minutes."
                )

            else:
                raise PermissionError(
                    f"Unexpected authorization decision: '{decision}'. Failing closed."
                )

        return wrapper

    return decorator
