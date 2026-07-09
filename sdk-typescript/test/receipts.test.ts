import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  computeReceiptHash,
  GENESIS_PREV,
  sealChain,
  verifyChain,
  verifyReceipt,
  type ReceiptRecord,
} from "../src/receipts.ts";

const TESTS_DIR = join(import.meta.dirname, "..", "..", "tests");

function loadCorpus(name: string): { receipts: ReceiptRecord[] } {
  return JSON.parse(readFileSync(join(TESTS_DIR, name), "utf8"));
}

test("receipt chain vectors: recompute matches pinned receipt_hash", () => {
  const corpus = loadCorpus("receipt_chain_vectors.json");
  assert.ok(corpus.receipts.length > 0);
  for (const rec of corpus.receipts) {
    const recomputed = computeReceiptHash(rec);
    assert.equal(recomputed, rec.receipt_hash, `receipt ${rec.event_id}`);
    assert.equal(verifyReceipt(rec), true, `verify ${rec.event_id}`);
  }
});

test("receipt chain vectors: full chain verifies from genesis", () => {
  const corpus = loadCorpus("receipt_chain_vectors.json");
  assert.equal(verifyChain(corpus.receipts, GENESIS_PREV), true);
});

test("tampered receipt_hash fails verifyReceipt", () => {
  const corpus = loadCorpus("receipt_chain_vectors.json");
  const bad = { ...corpus.receipts[0], receipt_hash: "0".repeat(64) };
  assert.equal(verifyReceipt(bad), false);
});

test("broken prev link fails verifyChain", () => {
  const corpus = loadCorpus("receipt_chain_vectors.json");
  const broken = corpus.receipts.map((r, i) =>
    i === 1 ? { ...r, prev_receipt_hash: "deadbeef" } : { ...r },
  );
  assert.equal(verifyChain(broken, GENESIS_PREV), false);
});

test("sealChain produces a verifiable chain", () => {
  const bodies: ReceiptRecord[] = [
    {
      event_id: "a",
      ts: "2026-06-02T12:00:00Z",
      tool: "t",
      action: "x",
      decision: "allow",
      source_trust: "trusted_internal_unsigned",
      action_hash: "aa".repeat(32),
    },
    {
      event_id: "b",
      ts: "2026-06-02T12:00:01Z",
      tool: "t",
      action: "y",
      decision: "allow",
      source_trust: "trusted_internal_unsigned",
      action_hash: "bb".repeat(32),
    },
  ];
  const chain = sealChain(bodies);
  assert.equal(chain.length, 2);
  assert.equal(chain[0].prev_receipt_hash, GENESIS_PREV);
  assert.equal(chain[1].prev_receipt_hash, chain[0].receipt_hash);
  assert.equal(verifyChain(chain), true);
});

test("empty chain verifies", () => {
  assert.equal(verifyChain([]), true);
});
