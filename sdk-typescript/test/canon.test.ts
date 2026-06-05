import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalize, canonicalHash } from "../src/canon.ts";

// Shared corpus lives at repo-root /tests; resolve relative to this file so the
// test is independent of the working directory.
const TESTS_DIR = join(import.meta.dirname, "..", "..", "tests");

function loadCorpus(name: string): any {
  return JSON.parse(readFileSync(join(TESTS_DIR, name), "utf8"));
}

// Cross-language contract: the TS canonicalizer MUST reproduce every
// `canonical` string byte-for-byte (this is what guarantees action_hash parity
// with the Go SDK, the Python SDK, and the Rust gateway).
test("canonical action vectors match the shared corpus byte-for-byte", () => {
  const corpus = loadCorpus("canonical_action_vectors.json");
  assert.ok(Array.isArray(corpus.vectors) && corpus.vectors.length > 0, "no vectors");
  for (const vec of corpus.vectors) {
    assert.equal(canonicalize(vec.tool_call), vec.canonical, `vector ${vec.name}`);
  }
});

// End-to-end canonicalizer + SHA-256: for each shared receipt vector,
// SHA-256(canonicalize(body)) — body is every field except receipt_hash — MUST
// equal the pinned receipt_hash.
test("receipt chain vectors reproduce pinned receipt_hash values", () => {
  const corpus = loadCorpus("receipt_chain_vectors.json");
  assert.ok(Array.isArray(corpus.receipts) && corpus.receipts.length > 0, "no receipts");
  for (const rec of corpus.receipts) {
    const { receipt_hash, ...body } = rec;
    assert.equal(canonicalHash(body), receipt_hash, `receipt ${rec.event_id}`);
  }
});

// Fail-closed number rule.
test("non-finite numbers are rejected", () => {
  assert.throws(() => canonicalize({ x: Infinity }));
  assert.throws(() => canonicalize({ x: NaN }));
});
