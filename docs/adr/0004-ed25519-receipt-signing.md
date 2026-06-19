# ADR-0004: Ed25519 for optional receipt signing

**Status:** Accepted
**Date:** 2026-03 (retroactive — recorded 2026-06)
**Issue:** [#1197](https://github.com/lavkushry/AegisAgent/issues/1197)

## Context

Action receipts form a per-tenant hash chain
(`receipt_hash = SHA-256(canonicalize(body))`, body includes
`prev_receipt_hash`) so tampering or re-linking is detectable
(`docs/action-receipt-spec.md`). That chain proves *internal* consistency —
that the gateway's own stored records weren't edited after the fact — but
doesn't, by itself, let a third party (an auditor, a customer's compliance
tooling) verify that a given receipt was produced by a specific gateway
instance's key, independent of trusting the database. `gateway/src/sign.rs`
adds optional asymmetric signing over `receipt_hash` to close that gap when a
tenant opts in.

## Decision

Use Ed25519 (`ed25519-dalek` crate) for the optional signature, loaded from a
hex-encoded 32-byte secret via an environment variable. The signature
(`signature` field, 64 bytes / 128 hex chars) is **additive** — explicitly
documented as not part of the hashed body — so verification can be checked
independently of the hash chain itself, and the absence of a signature never
weakens the chain's own tamper-evidence.

## Consequences

- Small, fast signatures (64 bytes) and fast verification, with no known
  malleability issues (unlike early ECDSA usage patterns) — cheap enough to
  do per-receipt without a measurable latency cost.
- Aligns with the project's own stated inspiration
  (`AegisAgent_Technical_Design.md` §1: "Sigstore/transparency-log patterns
  inform the integrity primitives") — Sigstore/cosign use Ed25519 (or
  ECDSA P-256) as their default signing scheme, so this is a well-trodden
  choice for transparency-log-style evidence rather than a novel one.
- Key management is currently a single hex secret in an environment
  variable — adequate for self-hosted MVP, but `action-receipt-spec.md`
  itself flags the real next step as "Enterprise: KMS-backed signing" once
  a tenant needs hardware-backed or rotated keys, which Ed25519's
  raw-secret-in-env model doesn't provide on its own.
- Verification (`GET /v1/receipts/:id/verify`) only checks the signature
  against the stored `receipt_hash` — it does not (yet) anchor to an
  external transparency log, so "verifiable" today means "verifiable given
  the gateway's claimed public key," not "verifiable against independent
  public infrastructure."

## Alternatives considered

- **RSA** — much larger keys/signatures for equivalent security margin, and
  slower to verify; no advantage here over Ed25519 for this use case.
- **ECDSA (P-256/secp256k1)** — viable and also used by Sigstore as an
  alternative, but carries well-known nonce-reuse footguns (k-value
  malleability) that Ed25519's deterministic signing scheme avoids by
  construction — a lower-risk default for a signing primitive most
  developers won't be auditing closely.
- **No signing, hash chain only** — simplest, and remains the default
  (signing is opt-in). Rejected as the *only* option because some tenants'
  compliance requirements (SOC 2, EU AI Act Art. 14) call for evidence
  verifiable by a party that doesn't trust the gateway operator's database
  directly.

## Revisit when

A tenant's compliance requirement needs KMS-backed or HSM-backed keys rather
than an environment-variable secret, or transparency-log anchoring
(mentioned as a future enterprise tier in `action-receipt-spec.md`) is
actually built.
