# AegisAgent Action Receipt — Open Format Spec v0

**Status:** draft v0 · **Date:** 2026-06-02 · **Canon scheme:** `aegis-jcs-1`
**Reference implementation:** `sdk-python/aegisagent/receipts.py` (verifier) · tests: `sdk-python/tests/test_receipts.py`

An **action receipt** is a tamper-evident record of one AI-agent action decision. Receipts are the verifiable evidence layer behind AegisAgent's compliance story (SOC 2 / EU AI Act Article 14) and are designed as an **open format** any gateway can emit and any third party can verify — independently of the runtime that produced them.

---

## 1. Canonicalization (`aegis-jcs-1`)

All hashing is over a canonical JSON string:

- object keys sorted by Unicode code point
- compact separators (no spaces): `,` and `:`
- raw UTF-8 — **no `\uXXXX` escaping** of non-ASCII
- non-finite floats (`NaN`/`Infinity`) are invalid and rejected
- `null` for absent values

This is the same scheme used for `action_hash` (see `tests/canonical_action_vectors.json`). Implementations MUST be byte-identical across languages.

---

## 2. Receipt fields

| Field | Type | Notes |
|---|---|---|
| `event_id` | string | unique receipt id |
| `ts` | string | RFC 3339 UTC timestamp |
| `agent_id` | string | acting agent |
| `user_id` | string\|null | initiating user, if any |
| `run_id` / `trace_id` | string\|null | correlation |
| `tool` / `action` / `resource` | string\|null | the tool call |
| `source_trust` | string | one of the 6 trust levels |
| `decision` | string | `allow` \| `deny` \| `require_approval` \| `rejected_on_swap` \| `approved` \| ... |
| `approver` | string\|null | approver identity, if applicable |
| `action_hash` | string\|null | SHA-256 of the canonical action (approval binding) |
| `executed_hash` | string\|null | hash of what actually executed (for tamper attempts) |
| `input_hash` / `output_hash` | string\|null | hashes, never raw payloads |
| `prev_receipt_hash` | string | link to the previous receipt (`""` for genesis) |
| `receipt_hash` | string | SHA-256 of the canonical body (see §3) |

Additional fields are permitted; they are included in the hash. Secrets MUST NOT appear — store hashes, not raw payloads.

---

## 3. Hash chain

Let `body` = the receipt object **excluding** `receipt_hash` and **including** `prev_receipt_hash`.

```
receipt_hash = SHA-256( canonicalize(body) )          # lowercase hex
```

Because `prev_receipt_hash` is inside the hashed body, both field tampering and re-linking are detectable. The first receipt in a chain uses `prev_receipt_hash = ""` (genesis).

---

## 4. Verification algorithm

A chain `[r0, r1, ...]` is valid iff, walking in order with `prev = ""`:

1. `recompute(r_i) == r_i.receipt_hash`  — integrity of each receipt
2. `r_i.prev_receipt_hash == prev`        — chain linkage
3. set `prev = r_i.receipt_hash`

Any mismatch ⇒ **invalid** (fail closed). Reference: `verify_chain()` / `verify_receipt()`.

---

## 5. Worked example (genesis receipt)

```json
{
  "event_id": "rcpt_svc#482",
  "ts": "2026-06-02T12:00:00Z",
  "agent_id": "coding-agent-prod",
  "user_id": "lavkush",
  "tool": "github", "action": "merge_pull_request", "resource": "payments-service#482",
  "source_trust": "untrusted_external",
  "decision": "rejected_on_swap",
  "approver": "platform-lead",
  "action_hash": "sha256:9af1...", "executed_hash": "sha256:1c20...",
  "prev_receipt_hash": "",
  "receipt_hash": "<SHA-256 of canonicalize(everything above except receipt_hash)>"
}
```

---

## 6. Implementation status (2026-06-02)

- **Done & verified (Python):** format + hash chain + reference verifier (`seal_receipt`, `seal_chain`, `verify_receipt`, `verify_chain`); CLI `aegis-verify-receipts` / `python -m aegisagent.verify_receipts`; shared corpus `tests/receipt_chain_vectors.json` (pins exact `receipt_hash` values). 25/25 SDK tests incl. tamper/broken-link/reorder/non-ASCII/CLI. Canonicalization centralized in `aegisagent/canon.py`.
- **Done, pending `cargo` verification (Rust gateway):** cross-language **parity lock** — `gateway/src/routes.rs::receipt_chain_matches_shared_corpus` reproduces every `receipt_hash` in `tests/receipt_chain_vectors.json` from the gateway's canonicalization (`canonical_value_string` = `aegis-jcs-1`). The Rust test logic was confirmed to reproduce the corpus in Python; serde↔Python canonicalization equivalence is already locked by the action-hash corpus.
- **Next (Rust gateway):** emit a receipt for every decision into an `action_receipts` table (hash-chained per tenant) and expose `GET /v1/receipts/:id/verify`. Enterprise: KMS-backed signing / transparency-log anchoring.
