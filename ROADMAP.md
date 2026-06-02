# AegisAgent Roadmap

> Re-anchored 2026-06-02 on the **integrity-layer** wedge. The generic gateway loop is commodity (see [`docs/AegisAgent_Gap_Reassessment_2026-06.md`](docs/AegisAgent_Gap_Reassessment_2026-06.md)); the roadmap prioritizes the differentiators: provable approvals, deterministic provenance gating, verifiable receipts, and layerability.

## MVP launch readiness (done / in progress)

- Local gateway quickstart with Docker Compose. ✅
- Python SDK `@protect_tool` with **fail-closed approval action-hash verification**. ✅
- Default Cedar policy pack: read-only allow, main-merge approval, untrusted-mutation denial. ✅
- GitHub attack demo with audit output. ✅

## Q3 2026 — harden the integrity primitives (the moat)

- **Canonicalization spec v1** (target RFC 8785 JCS) shared across SDK + gateway, with a CI byte-equality gate (the fail-closed guarantee depends on it).
- **Approval Integrity Engine hardening:** expiry enforced fail-closed at the SDK ✅ and (pending `cargo` verify) at the gateway ✅; **still TODO:** single-use nonce + replay rejection, edit→re-hash→re-evaluate confirmation, tamper-attempt receipts.
- **Verifiable action-receipt format v0** (per-tenant hash chain): open spec ✅ ([`docs/action-receipt-spec.md`](docs/action-receipt-spec.md)) + Python reference verifier ✅ (`aegisagent/receipts.py`, 8/8) + CLI ✅ + gateway emission into `action_receipts` + `GET /v1/receipts/:id/verify` ✅ (written, pending `cargo`). **Next:** single-use nonce (replay T-A3); race-safe chain head; enterprise signing.
- **Trust-Provenance Gate:** deterministic 6-level model finalized; classifier integration that can only *tighten*, never loosen.
- Slack approval callback signature verification + approver role lookup.
- The "approve-then-swap blocked" demo as the flagship.

## Q4 2026 — evidence, provenance depth, and reach

- **SOC 2 / EU AI Act Article 14 evidence export** (receipt packs).
- TypeScript SDK (with byte-identical canonicalization).
- MCP manifest signing + drift detection feeding provenance downgrade.
- MCP proxy execution path (beyond authorization).
- OpenTelemetry exporter; `approval_hash_mismatch_total` / `provenance_denials_total` metrics.
- GitHub App integration + PR comments/checks; default anti-confused-deputy policy pack (Invariant Labs class).

## 2027 — standard + layerability

- **Layer-on adapters** so AegisAgent adds integrity on top of existing gateways (Microsoft Agent Governance Toolkit, MintMCP, Pipelock).
- Enterprise: transparency-log / KMS-backed receipt signing; air-gapped mode.
- Memory/RAG provenance + receipts (AgentPoison/PoisonedRAG class).
- Policy bundle versioning + dry-run/simulation.
- Per-tenant rate limiting; SIEM/webhook export; Helm + production hardening.
- Drive adoption of the open action-receipt spec across the ecosystem.

## Explicitly NOT on the roadmap

Full SIEM, full DLP, network egress firewall, model scanning, GRC automation, identity lifecycle management. AegisAgent integrates with these; it does not become them.
