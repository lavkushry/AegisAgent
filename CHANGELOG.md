# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to
adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it
reaches 1.0.

## [Unreleased]

### Added

- **Canonicalization scheme `aegis-jcs-1`** shared byte-identically between the
  Python SDK and the Rust gateway, locked by shared test corpora
  (`tests/canonical_action_vectors.json`, `tests/receipt_chain_vectors.json`).
- **Approval integrity**: action-hash binding with fail-closed SDK enforcement,
  approval expiry (SDK + gateway), and single-use approval consumption
  (`consumed_at` guard + `POST /v1/approvals/:id/consume`) to defeat replay.
- **Verifiable action receipts**: open hash-chained receipt format
  (`docs/action-receipt-spec.md`), Python reference verifier (`aegisagent.receipts`),
  `aegis-verify-receipts` CLI, gateway emission, and `GET /v1/receipts/:id/verify`.
- **Deterministic trust-provenance gating**: 6-level model in the default Cedar
  policy pack; classifiers may only tighten a label, never loosen it.
- **SOC incident deduplication (SOC-005)**: repeat incidents for the same
  `(tenant_id, agent_id, kind)` within a configurable window (default 1 hour,
  `AEGIS_SOC_INCIDENT_DEDUP_WINDOW_SECS`) are merged into the existing open
  `soc_incidents` row (`db::upsert_soc_incident`) instead of creating a new
  one — `source_event_ids` are unioned and `summary`/`opened_at` are bumped to
  the latest occurrence, suppressing duplicate Phase 2 incident notifications.
- Self-contained, zero-setup integrity demo (`examples/integrity_demo.py`).
- OSS project scaffolding: MIT `LICENSE`, `CODE_OF_CONDUCT.md`, issue/PR
  templates, Dependabot, and hardened CI.

### Changed

- Repositioned from "Agent Action Firewall" to the **integrity layer for AI
  agent actions** (see `docs/AegisAgent_Gap_Reassessment_2026-06.md`).
- Documentation re-anchored on the integrity + provenance + verifiable-evidence
  wedge.

### Security

- Fail-closed defaults across unknown agent/tool/MCP server/MCP tool, on hash
  mismatch, on expired/consumed approvals, and on gateway unreachability for
  mutating/high-risk actions.
- Multi-tenant isolation enforced with tenant-scoped, parameterized SQL only.

[Unreleased]: https://github.com/lavkushry/AegisAgent/commits/main
