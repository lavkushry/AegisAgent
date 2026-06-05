# AegisAgent Action Receipt — Open Format Spec v0

**Status:** draft v0 · **Date:** 2026-06-02 · **Extended:** 2026-06-05 (§7, SOC evidence spine) · **Canon scheme:** `aegis-jcs-1`
**Reference implementation:** `sdk-python/aegisagent/receipts.py` (verifier) · tests: `sdk-python/tests/test_receipts.py`
**SOC architecture:** [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md)

An **action receipt** is a tamper-evident record of one AI-agent action decision. Receipts are the verifiable evidence layer behind AegisAgent's compliance story (SOC 2 / EU AI Act Article 14) and are designed as an **open format** any gateway can emit and any third party can verify — independently of the runtime that produced them. They are also the **evidence spine of the integrity-anchored Agent SOC**: every SOC alert and incident references the `receipt_hash` chain covering its events, which is what makes a SOC incident timeline *provable* rather than merely logged (§7). The format below is **locked and byte-exact** — do not change it without bumping the canon scheme and re-pinning the cross-language corpus, or both the fail-closed guarantee and the SOC's evidence integrity break.

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
- **Done, pending `cargo` verification (Rust gateway):**
  - cross-language **parity lock** — `routes.rs::receipt_chain_matches_shared_corpus` reproduces every `receipt_hash` in `tests/receipt_chain_vectors.json` (`canonical_value_string` = `aegis-jcs-1`).
  - **gateway emission** — every `/v1/authorize` decision writes a hash-chained receipt into the `action_receipts` table (`emit_action_receipt`, chained per tenant via `rowid` head); body fields per `routes.rs::receipt_body_value` (excludes `receipt_hash` + volatile `created_at`).
  - **`GET /v1/receipts/:id/verify`** — recomputes the hash and returns `{verified, receipt_hash, recomputed_hash, prev_receipt_hash}`. Test: `authorize_emits_verifiable_receipt`.
- **Next (Rust):** single-use `nonce` + consume step for full replay defense (T-A3). Enterprise: KMS-backed signing / transparency-log anchoring; chain-head selection should move into a transaction to be race-safe under concurrency.

---

## 7. The receipt as the SOC evidence spine

The same hash chain that proves human oversight for compliance is what makes the **integrity-anchored Agent SOC** (see [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md)) different from a generic SIEM: its incident timelines are *provable*, not just recorded.

### 7.1 Receipt ↔ Agent Security Event (ASE)
When the gateway decides, it (1) writes a receipt to the chain and (2) emits an **ASE** onto the async SOC bus. The ASE carries the decision *and* the integrity linkage:

```jsonc
// fields the ASE copies from the receipt for tamper-evident correlation
"integrity": {
  "action_hash":        "sha256:...",   // frozen action (approval binding)
  "decision_id":        "uuid",
  "receipt_hash":       "sha256:...",   // this event's chain link
  "prev_receipt_hash":  "sha256:..."    // previous link
}
```

The SOC never re-hashes payloads or trusts raw logs; it correlates on `receipt_hash`/`prev_receipt_hash`, so a forged or replayed event (T-D5) fails to chain.

### 7.2 Provable incident timelines
A correlated incident stores `evidence_receipts: [receipt_hash, ...]` — the ordered chain links covering its events. An investigator (or auditor) runs the §4 verification over those links; if every `recompute(r_i) == r_i.receipt_hash` and `r_i.prev_receipt_hash == prev`, the timeline is proven untampered. This is the SOC Console's one-click "verify incident."

### 7.3 Chain integrity as a detection
A break in the chain (`tampered` from `/verify`, a missing link, or a re-linking) is itself a **P1 SOC detection** (`receipt-chain-broken`) — evidence tampering (Threat Model T-C1) surfaces as an alert, not just a failed audit.

### 7.4 Redaction (unchanged, reaffirmed for the SOC)
Because the SOC consumes receipts/ASEs, the §2 rule is doubly important: **secrets MUST NOT appear** — store `input_hash`/`output_hash`, never raw payloads. The SOC, its indexer, and the sandboxed RCA narrator therefore never hold plaintext secrets (closes T-D7 exfiltration via the RCA LLM).

> **Invariant:** the receipt chain is simultaneously the compliance evidence *and* the SOC evidence. One tamper-evident structure serves both. Keep it byte-exact (§1) and append-only; it is the single most load-bearing data structure in AegisAgent.
