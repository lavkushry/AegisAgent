/**
 * Verifiable action receipts (scheme `aegis-jcs-1`) — TypeScript verifier.
 *
 * Mirrors `sdk-python/aegisagent/receipts.py` and `sdk-go/aegis/receipts.go`.
 * `receipt_hash = SHA-256(canonicalize(body))` where `body` is every field
 * except `receipt_hash` and includes `prev_receipt_hash`. Cross-language
 * parity is locked by `tests/receipt_chain_vectors.json`.
 */

import { canonicalHash } from "./canon.ts";

/** `prev_receipt_hash` value expected for the first receipt in a chain. */
export const GENESIS_PREV = "";

const RECEIPT_HASH_FIELD = "receipt_hash";
const PREV_HASH_FIELD = "prev_receipt_hash";

export type ReceiptRecord = Record<string, unknown>;

/** Hashed portion of a receipt: all fields except `receipt_hash`. */
export function receiptBody(receipt: ReceiptRecord): ReceiptRecord {
  const body: ReceiptRecord = {};
  for (const [k, v] of Object.entries(receipt)) {
    if (k !== RECEIPT_HASH_FIELD) body[k] = v;
  }
  return body;
}

/** SHA-256 hex of the canonical body (all fields except `receipt_hash`). */
export function computeReceiptHash(receipt: ReceiptRecord): string {
  return canonicalHash(receiptBody(receipt));
}

/**
 * Return a NEW receipt with `prev_receipt_hash` set and `receipt_hash`
 * computed. Does not mutate the input.
 */
export function sealReceipt(
  receipt: ReceiptRecord,
  prevReceiptHash: string = GENESIS_PREV,
): ReceiptRecord {
  const body = receiptBody(receipt);
  body[PREV_HASH_FIELD] = prevReceiptHash;
  const sealed: ReceiptRecord = { ...body };
  sealed[RECEIPT_HASH_FIELD] = canonicalHash(body);
  return sealed;
}

/** Seal a list of receipt bodies into a linked chain. Returns new objects. */
export function sealChain(
  receipts: ReceiptRecord[],
  genesisPrev: string = GENESIS_PREV,
): ReceiptRecord[] {
  const chain: ReceiptRecord[] = [];
  let prev = genesisPrev;
  for (const receipt of receipts) {
    const sealed = sealReceipt(receipt, prev);
    chain.push(sealed);
    prev = String(sealed[RECEIPT_HASH_FIELD] ?? "");
  }
  return chain;
}

/**
 * True if the receipt's stored `receipt_hash` matches its recomputed hash.
 * Missing/empty `receipt_hash` → false (fail closed).
 */
export function verifyReceipt(receipt: ReceiptRecord): boolean {
  const stored = receipt[RECEIPT_HASH_FIELD];
  if (typeof stored !== "string" || stored.length === 0) return false;
  return computeReceiptHash(receipt) === stored;
}

/**
 * True if every receipt verifies AND each link's `prev_receipt_hash` equals
 * the prior receipt's `receipt_hash` (first compared to `genesisPrev`).
 * Empty chain → true.
 */
export function verifyChain(
  receipts: ReceiptRecord[],
  genesisPrev: string = GENESIS_PREV,
): boolean {
  let prev = genesisPrev;
  for (const receipt of receipts) {
    if (!verifyReceipt(receipt)) return false;
    const p = receipt[PREV_HASH_FIELD];
    if (p !== prev) return false;
    prev = String(receipt[RECEIPT_HASH_FIELD] ?? "");
  }
  return true;
}
