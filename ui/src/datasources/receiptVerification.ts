import type { VerifyResult } from "./types";

function recordOf(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : {};
}

/**
 * Convert gateway verification responses into one fail-closed contract.
 * Success is accepted only when the gateway says so explicitly.
 */
export function normalizeVerification(value: unknown): VerifyResult {
  const data = recordOf(value);
  const error = data.error;
  const brokenRaw = data.broken_at_row ?? data.brokenAtRow;
  const brokenAtRow = typeof brokenRaw === "number" ? brokenRaw : undefined;
  const statusValue = typeof data.status === "string" ? data.status.toLowerCase() : "";
  const explicitFailure =
    data.verified === false ||
    data.ok === false ||
    Boolean(error) ||
    brokenAtRow !== undefined ||
    ["failed", "broken", "tampered", "invalid"].includes(statusValue);
  const explicitSuccess =
    data.verified === true || data.ok === true || statusValue === "verified";
  const head = data.chain_head ?? data.chainHead;
  const gatewayMessage = typeof data.message === "string" ? data.message : undefined;

  if (explicitFailure) {
    return {
      status: "failed",
      ok: false,
      brokenAtRow,
      message: error
        ? `Tamper detected: ${String(error)}`
        : gatewayMessage || "Receipt verification failed or the chain is broken.",
      chainHead: typeof head === "string" ? head : undefined,
    };
  }

  if (explicitSuccess) {
    return {
      status: "verified",
      ok: true,
      message: gatewayMessage || "Receipt cryptographic signature matches the hash chain.",
      chainHead: typeof head === "string" ? head : undefined,
    };
  }

  return {
    status: "unknown",
    ok: false,
    message: gatewayMessage || "The gateway did not explicitly confirm receipt verification.",
    chainHead: typeof head === "string" ? head : undefined,
  };
}
