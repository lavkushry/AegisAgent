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
- Self-contained, zero-setup integrity demo (`examples/integrity_demo.py`).
- OSS project scaffolding: MIT `LICENSE`, `CODE_OF_CONDUCT.md`, issue/PR
  templates, Dependabot, and hardened CI.
- **`aegis_authorize_duration_seconds` Prometheus histogram** (OBS-001, #1154):
  records inline `/v1/authorize` latency with buckets at 5/10/25/50/75/100/250/
  500/1000ms, exposed on `GET /metrics`. Includes a Grafana dashboard template
  (`grafana/dashboards/aegis-authorize-latency.json`) with p50/p95/p99 panels.
- **Counter metrics on `GET /metrics`** (OBS-002, #1155): `aegis_decisions_total{decision}`
  (per `/v1/authorize` outcome), `aegis_alerts_total{rule,severity}` and
  `aegis_incidents_total{kind}` (SOC drain), and `aegis_events_emitted_total` /
  `aegis_events_dropped_total` (SOC event stream health). All labels come from
  small, fixed, deterministic sets (redaction invariant).

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
