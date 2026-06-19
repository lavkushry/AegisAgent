# ADR-0003: `aegis-jcs-1` canonicalization scheme for `action_hash`

**Status:** Accepted
**Date:** 2026-02 (retroactive — recorded 2026-06)
**Issue:** [#1197](https://github.com/lavkushry/AegisAgent/issues/1197)

## Context

AegisAgent's first defensible primitive (`AegisAgent_Gap_Reassessment_2026-06.md`
§"Bottom line") is **approval integrity**: a human approval binds to a
SHA-256 hash of the exact frozen action, and the SDK fails closed if a
different/edited/expired action would execute. That guarantee only holds if
four independent implementations — the Python, Go, and TypeScript SDKs, and
the Rust gateway — compute **byte-identical** hashes for the same logical
action. JSON has no single canonical byte representation (key order,
whitespace, number formatting, Unicode escaping all vary by serializer), so
canonicalization has to be specified, not assumed.

## Decision

Define and lock a project-specific scheme, `aegis-jcs-1`, inspired by RFC 8785
(JSON Canonicalization Scheme) but specified precisely enough to remove any
serializer-specific ambiguity across Python/Go/TS/Rust: keys sorted by
Unicode code point, compact separators, raw UTF-8 (never `\uXXXX` escapes),
`null` for an absent resource, and non-finite floats rejected outright rather
than serialized inconsistently. The scheme is implemented once per language
(`canon.py`, `canon/canon.go`, `src/canon.ts`, and the gateway's Rust
equivalent) and locked by a shared byte-equality corpus
(`tests/canonical_action_vectors.json`, `tests/receipt_chain_vectors.json`)
asserted in CI across all four languages (`canonical_action_matches_shared_corpus`,
the Go/TS canon-parity jobs, `corpus-check` in `ci.yml`).

## Consequences

- The fail-closed approval-integrity guarantee is real and testable — any
  accidental divergence between languages is a CI failure, not a
  production incident waiting to happen.
- The scheme is versioned in its own name (`aegis-jcs-1`) specifically so a
  future breaking change becomes `aegis-jcs-2` rather than a silent
  redefinition — old receipts and approvals remain verifiable against the
  scheme version they were created under.
- Every new SDK or language port inherits a hard requirement: reproduce the
  exact canonicalization rules byte-for-byte and pass the shared corpus
  before anything else is "done." This is real, ongoing maintenance cost
  charged against every future language target.
- Because non-finite floats are rejected rather than canonicalized, any tool
  parameter containing `NaN`/`Infinity` fails the action upfront rather than
  hashing inconsistently — a deliberate fail-closed choice, not an oversight.

## Alternatives considered

- **Use RFC 8785 (JCS) directly, unmodified** — close, but RFC 8785 leaves
  some implementation-defined corners (e.g. exact number formatting edge
  cases) that still differ subtly across off-the-shelf language libraries.
  `aegis-jcs-1` pins the specific rules AegisAgent depends on rather than
  trusting four different RFC 8785 implementations to agree byte-for-byte.
- **Hash the raw wire JSON bytes as sent** — simplest, but means a
  semantically identical action with different key order or whitespace
  (e.g. re-serialized by a proxy) produces a different hash, breaking
  approvals for no real security reason.
- **A binary canonical form (e.g. CBOR canonical encoding)** — equally
  rigorous, but loses the human-readability of JSON for debugging approval
  mismatches and receipts, which matters for an evidence/compliance product.

## Revisit when

A fifth language SDK is added (the corpus and byte-equality CI gate need to
extend to it before it ships), or a real-world canonicalization edge case is
found that the current spec doesn't cover (in which case it becomes
`aegis-jcs-2`, never a silent edit to `aegis-jcs-1`).
