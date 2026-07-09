import {
  fetchFromGateway,
  type FetchOptions,
} from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";

export interface ReceiptRecord {
  id: string;
  tool?: string;
  receipt_hash?: string;
  prev_receipt_hash?: string;
  action_hash?: string;
  ts?: string;
  created_at?: string;
  agent_id?: string;
  run_id?: string;
  decision?: string;
  source_trust?: string;
}

export type VerifyStatus = "verified" | "failed" | "unknown";

export interface VerifyResult {
  status: VerifyStatus;
  ok: boolean;
  message: string;
  receiptHash?: string;
  recomputedHash?: string;
}

/**
 * Fail-closed: success only when gateway sets verified/ok true explicitly.
 * Mirrors ui/src/datasources/receiptVerification.ts.
 */
export function normalizeVerification(value: unknown): VerifyResult {
  const data =
    typeof value === "object" && value !== null
      ? (value as Record<string, unknown>)
      : {};
  const error = data.error;
  const statusValue =
    typeof data.status === "string" ? data.status.toLowerCase() : "";
  const explicitFailure =
    data.verified === false ||
    data.ok === false ||
    Boolean(error) ||
    ["failed", "broken", "tampered", "invalid"].includes(statusValue);
  const explicitSuccess =
    data.verified === true ||
    data.ok === true ||
    statusValue === "verified";
  const gatewayMessage =
    typeof data.message === "string" ? data.message : undefined;
  const receiptHash =
    typeof data.receipt_hash === "string" ? data.receipt_hash : undefined;
  const recomputedHash =
    typeof data.recomputed_hash === "string"
      ? data.recomputed_hash
      : undefined;

  if (explicitFailure) {
    return {
      status: "failed",
      ok: false,
      message: error
        ? `Tamper detected: ${String(error)}`
        : gatewayMessage || "Receipt verification failed or the chain is broken.",
      receiptHash,
      recomputedHash,
    };
  }

  if (explicitSuccess) {
    return {
      status: "verified",
      ok: true,
      message:
        gatewayMessage ||
        "Receipt hash matches recomputed integrity value.",
      receiptHash,
      recomputedHash,
    };
  }

  return {
    status: "unknown",
    ok: false,
    message:
      gatewayMessage ||
      "The gateway did not explicitly confirm receipt verification.",
    receiptHash,
    recomputedHash,
  };
}

export async function listReceipts(
  opts: FetchOptions,
  limit = 50,
): Promise<ReceiptRecord[]> {
  const raw = await fetchFromGateway<unknown>(
    opts,
    `/v1/receipts?limit=${limit}`,
  );
  return asRecordArray(raw).map((row) => row as unknown as ReceiptRecord);
}

export async function verifyReceipt(
  opts: FetchOptions,
  receiptId: string,
): Promise<VerifyResult> {
  const data = await fetchFromGateway<Record<string, unknown>>(
    opts,
    `/v1/receipts/${encodeURIComponent(receiptId)}/verify`,
  );
  return normalizeVerification(data);
}

export async function verifyReceiptRange(
  opts: FetchOptions,
): Promise<VerifyResult> {
  const data = await fetchFromGateway<Record<string, unknown>>(
    opts,
    "/v1/receipts/verify-range",
    "POST",
    {},
  );
  return normalizeVerification(data);
}
