/**
 * AegisAgent canonicalization scheme `aegis-jcs-1` (TypeScript).
 *
 * Output MUST be byte-identical to the Go SDK (sdk-go/canon), the Python SDK
 * (sdk-python/aegisagent/canon.py), and the Rust gateway, because both
 * action_hash (approval integrity) and receipt_hash (verifiable receipts) are
 * SHA-256 over this canonical string. A divergence silently breaks the
 * fail-closed guarantee — locked by tests/canonical_action_vectors.json and
 * tests/receipt_chain_vectors.json.
 *
 * Scheme aegis-jcs-1:
 *   - object keys sorted by Unicode code point
 *   - compact separators (no spaces): "," and ":"
 *   - raw UTF-8 — no \uXXXX escaping of non-ASCII
 *   - non-finite numbers (NaN/Infinity) rejected
 *   - null for absent values
 *
 * JS-specific footguns this module handles:
 *   - JSON.stringify does NOT sort keys — we sort recursively.
 *   - Default key sort compares UTF-16 code units; we sort by CODE POINT so
 *     astral-plane keys (emoji) order the same as Python/Go/Rust.
 *   - JSON.stringify(Infinity) === "null" silently — we reject non-finite first.
 *   - No int/float distinction: JSON.stringify(1.0) === "1". Integers are
 *     byte-stable; finite non-integers are NOT yet corpus-locked across SDKs
 *     (prefer integers/strings/bigint for action parameters).
 */
import { createHash } from "node:crypto";

export const CANON_VERSION = "aegis-jcs-1";

/** Deterministic aegis-jcs-1 canonical JSON string for `value`. */
export function canonicalize(value: unknown): string {
  return writeValue(value);
}

/** Lowercase hex SHA-256 of `text` encoded as UTF-8. */
export function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** SHA-256 hex of the canonical serialization of `value`. */
export function canonicalHash(value: unknown): string {
  return sha256Hex(canonicalize(value));
}

function writeValue(v: unknown): string {
  if (v === null || v === undefined) return "null";
  switch (typeof v) {
    case "boolean":
      return v ? "true" : "false";
    case "string":
      // JSON.stringify escaping matches Python json.dumps(ensure_ascii=False):
      // raw non-ASCII (incl. U+2028/U+2029), escapes only " \ and C0 controls.
      return JSON.stringify(v);
    case "number":
      return writeNumber(v);
    case "bigint":
      return v.toString();
    case "object":
      if (Array.isArray(v)) return `[${v.map(writeValue).join(",")}]`;
      return writeObject(v as Record<string, unknown>);
    default:
      throw new Error(`canon: unsupported type ${typeof v} (aegis-jcs-1)`);
  }
}

function writeNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new Error("canon: non-finite number not allowed (aegis-jcs-1)");
  }
  return JSON.stringify(n);
}

function writeObject(o: Record<string, unknown>): string {
  const keys = Object.keys(o).sort(byCodePoint);
  let out = "{";
  for (let i = 0; i < keys.length; i++) {
    if (i > 0) out += ",";
    out += `${JSON.stringify(keys[i])}:${writeValue(o[keys[i]])}`;
  }
  return out + "}";
}

/**
 * Compare by Unicode code point, NOT UTF-16 code unit. Default `<`/Array.sort
 * compares code units, which diverges for astral-plane characters (surrogate
 * pairs) — e.g. an emoji key would sort differently from Python/Go/Rust.
 */
function byCodePoint(a: string, b: string): number {
  const ca = Array.from(a);
  const cb = Array.from(b);
  const n = Math.min(ca.length, cb.length);
  for (let i = 0; i < n; i++) {
    const d = ca[i].codePointAt(0)! - cb[i].codePointAt(0)!;
    if (d !== 0) return d;
  }
  return ca.length - cb.length;
}
