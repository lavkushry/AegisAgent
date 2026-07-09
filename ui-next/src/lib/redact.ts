/**
 * Display-only secret redaction for console JSON / payload previews.
 * Never rely on this alone for transport security — gateway must still
 * fail-closed; this prevents accidental operator-facing secret leaks
 * (e.g. tool_call.parameters.api_key in Approvals cards).
 */

const REDACTED = "[REDACTED]";

/** Keys that always redact their string/object values when shown in UI. */
const SENSITIVE_KEY =
  /^(api[_-]?key|authorization|auth|bearer|password|passwd|secret|token|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|credential|credentials)$/i;

/** Values that look like live secrets even under innocent keys. */
const SECRET_VALUE =
  /^(sk-live-|sk-test-|ghp_|gho_|xox[baprs]-|Bearer\s+[A-Za-z0-9._-]{16,})/i;

export function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY.test(key.trim());
}

export function looksLikeSecretValue(value: string): boolean {
  return SECRET_VALUE.test(value.trim());
}

/**
 * Deep-clone `value` with secrets replaced by `[REDACTED]`.
 * Pure — never mutates the input.
 */
export function redactSecrets(value: unknown, keyHint = ""): unknown {
  if (value === null || value === undefined) return value;

  if (typeof value === "string") {
    if (isSensitiveKey(keyHint) || looksLikeSecretValue(value)) {
      return REDACTED;
    }
    return value;
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactSecrets(item, keyHint));
  }

  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (isSensitiveKey(k)) {
        out[k] = REDACTED;
      } else {
        out[k] = redactSecrets(v, k);
      }
    }
    return out;
  }

  return value;
}

/** Pretty-print JSON with secrets redacted for operator-facing previews. */
export function redactJsonForDisplay(
  value: unknown,
  space: number | string = 2,
): string {
  try {
    return JSON.stringify(redactSecrets(value), null, space) ?? "";
  } catch {
    return "[unserializable]";
  }
}

export { REDACTED };
