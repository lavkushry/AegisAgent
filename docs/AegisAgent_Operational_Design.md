# AegisAgent — Operational Design & Community (June 2026 reset)

**Product:** AegisAgent
**Category:** Agent Action Integrity → Integrity-anchored Agent SOC
**Version:** v0.3 (re-anchored on the integrity-anchored Agent SOC)
**Date:** 2026-06-05
**Owner:** Lavkush Kumar
**Read first:** [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md) · **SOC architecture:** [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md)

> ⚠️ **Reset note (two layers).** v0.1 framed operations around a developer-first "Agent Action Firewall." v0.2 re-anchored on the **integrity layer** and added canonicalization versioning, receipt-chain integrity + signing, approval-channel reliability, and self-hosted-first ops. **v0.3 adds the operational invariants the SOC plane introduces** (§4.5): async isolation of detection from the action path (P0), detection-rule + playbook lifecycle, Active-Response safety, and the RCA-LLM sandbox.

---

## 1. Operating posture

AegisAgent is **developer-first security infrastructure** whose headline value (provable approvals + provenance gating + verifiable receipts, operated as a SOC) is also what compliance buyers pay for. Operations serve three audiences:

- **Developers** — clean OSS, 10-minute self-hosted setup, fail-closed-by-default SDK, readable Cedar policies + detection rules, the open receipt spec.
- **Security/compliance** — tenant isolation, signed receipts, SOC 2 / Article 14 evidence + provable incident records, self-hosting inside their trust boundary.
- **SOC analysts** — a live decision feed, provenance-aware detections, provable incident timelines, and real-time containment.

Market backdrop (see GTM doc): developers adopt agents heavily but distrust output (Stack Overflow 2026: ~84% use, ~29% trust); GitHub workflows are agentic; the Invariant Labs GitHub-MCP issue (a malicious issue leaking private-repo data) is the canonical real-world proof of the confused-deputy threat AegisAgent's provenance gate closes and the SOC correlates.

---

## 2. Community & distribution operations

- **Optimize for OSS trust signals:** clean README, 10-min quickstart, examples, SECURITY.md, CONTRIBUTING.md, transparent ROADMAP, changelog, GitHub stars/issues/discussions.
- **Two open specs are the flywheel.** Publish (1) the verifiable action-receipt format and (2) the **deterministic detection-rule format**, both with reference implementations; invite gateways/SOCs to emit/consume them. Adoption of the *formats* is a leading indicator, tracked alongside stars.
- **Curated MCP security catalog:** classify MCP servers by capability, auth model, credential handling, tool risk, manifest stability — feeds the provenance gate's default trust levels and the SOC's drift detection.
- **Content motion:** lead with the approve-then-swap demo, the Article 14 evidence story, and "Wazuh for AI agents / why your SIEM can't watch your agents" (GTM §14).

**Default GitHub policy (ships in OSS):** treat public issue content as `untrusted_external`; forbid untrusted context from triggering private-repo reads or public/cross-repo writes; require approval for cross-repository data movement — directly mitigating the Invariant Labs class, and surfaced in the SOC as a confused-deputy detection.

---

## 3. Deployment topologies

### 3.1 Self-hosted single binary (first-class — the neutrality wedge)
Rust gateway + SQLite (WAL) + embedded Cedar + local hash-chained receipts + **in-proc SOC** (`tokio::mpsc` bus, deterministic rule engine, local console). Runs inside the customer trust boundary; no prod tool calls leave their network. Target: `docker compose up` → first protected action < 20 min.

### 3.2 SaaS (multi-tenant)
Kubernetes; Postgres; **event bus (Redis Streams → Kafka/NATS); ClickHouse SOC event tier; SOC worker pool (detection/correlation/response)**; OTel collector → Grafana/Prometheus/Loki; Next.js console; hosted Slack/Teams approvals. Tenant isolation on every query (`tenant_id`), incl. SOC tables/indices.

### 3.3 Enterprise / self-managed
Helm chart; external Postgres/Redis; OIDC/SAML; SIEM export; **transparency-log / receipt signing** (KMS-backed); **multi-node SOC + Active-Response**; air-gapped mode; long retention.

---

## 4. Operating the integrity primitives + the SOC (the parts that need new runbooks)

### 4.1 Canonicalization versioning (critical)
The fail-closed guarantee depends on the Go, TS, and Python SDKs and the Rust gateway producing **byte-identical** canonical actions (now verified across all three via the shared corpus). Pin the scheme (`aegis-jcs-1`); a change is a **breaking change** (bump scheme, support old+new during migration, never silently alter hashing); CI gate: cross-language byte-equality on a fixed corpus must pass before release.

### 4.2 Receipt-chain integrity & key management
Per-tenant hash chain; periodic checkpoint (anchor to an append-only/transparency log in enterprise); signing keys (enterprise) in KMS/Vault with a rotation runbook (key ID in receipt); `GET /v1/receipts/:id/verify` monitored — a `tampered` result pages security. **The chain is also the SOC's evidence spine; a chain break is a P1 SOC detection.**

### 4.3 Approval-channel reliability
Slack/Teams callback signatures verified; approver role lookup required; approvals single-use (`consumed_at`), time-boxed (`expires_at`), replay-checked; channel outage → pending + dashboard fallback + auto-deny on timeout. SLO: approval delivery p95 < 5 s.

### 4.4 SDK bypass detection
Agents must not hold raw tool credentials (Token Broker proxies sensitive calls). Detect direct tool use (network policy guidance, proxy-only creds) and **raise it as a SOC event**. A bypassed SDK is an incident.

### 4.5 Operating the SOC plane (new — P0 invariants)
- **Async isolation (P0).** Event emission is fire-and-forget (`tokio::mpsc`, bounded). Under extreme backpressure the emitter **drops + increments a metric**; it MUST NEVER block or slow `/v1/authorize`. Runbook alert: `ase_emit_dropped_total` rising → scale SOC workers, never throttle the gateway. **The SOC failing must never fail the action path open** (Design Law 3).
- **Detection-rule & playbook lifecycle.** Rules/playbooks are versioned config (like Cedar): dry-run/simulate against recent events before activation; canary a new rule in `log_only` before it can trigger Active Response; changelog every rule edit. A rule that would gate on a *score* is rejected in review (Design Law 1).
- **Active-Response safety.** `freeze`/`revoke`/`quarantine` are deterministic, tenant-scoped, **reversible**, audited, and rate-limited (guard against false-freeze DoS — T-D4). Critical responses (revoke) optionally require two-person confirm. Every response emits a receipt.
- **RCA-LLM sandbox.** The only LLM runs **post-incident**, sandboxed, no tools/retrieval, evidence passed as **inert data** (redacted hashes, tenant-scoped), output reviewed before leaving the tenant boundary (closes T-D1 second-order injection and T-D7 exfiltration). No LLM anywhere in detection/correlation/enforcement.
- **Correlation-state hygiene.** Sequence/window state is per-tenant and bounded; restart-safe (durable in SaaS) so attacks spanning a restart aren't lost; ASE events validated against the receipt chain to resist forgery (T-D5).

---

## 5. SLOs

```text
Authorization API p95:        < 150 ms
Policy evaluation p95:        < 75 ms
action_hash compute:          < 5 ms
ASE emit overhead:            < 1 ms, non-blocking (MUST NOT affect authorize latency)
Approval delivery p95:        < 5 s
MCP proxy overhead p95:       < 250 ms
Receipt/audit enqueue success: 99.9%
SOC detection latency (async): < 2 s p95 event->alert
SOC mean-time-to-contain:     < 30 s detection->freeze (auto-containment path)
SaaS availability (MVP):      99.5%  (enterprise target 99.9%)
```

Key metrics (alerting): `approval_hash_mismatch_total` (tamper attempts), `provenance_denials_total`, `receipt_verify_failures_total`, `canonicalization_version_skew`, **`ase_emit_dropped_total` (SOC backpressure), `soc_mttd_seconds`, `soc_mttc_seconds`, `incidents_open`**.

---

## 6. Reliability & fail-closed

| Failure | Behavior |
|---|---|
| Gateway/policy unreachable | SDK fails closed for mutating/high-risk; read-only fail-open only if explicitly configured |
| Approval channel down | Pending + dashboard fallback + auto-deny on timeout |
| Receipt/audit down | Critical actions block until receipt writable; low-risk buffer+retry |
| Hash mismatch / canon skew | FAIL CLOSED; never execute; record tamper/skew event + SOC detection |
| **SOC plane down (bus/workers/console)** | **Action path UNAFFECTED (async by construction); monitoring degrades; events buffer/drop with metric; backfill on recovery** |
| **Active-Response API unreachable** | Containment queued + retried; deny-side safety unaffected (gateway already denied/escalated inline) |

---

## 7. Security operations

Tenant isolation on every query (incl. SOC tables/indices); parameterized SQLx only; default-deny unknown agent/tool/MCP server/MCP tool; **scores never gate; the only LLM is the sandboxed RCA narrator**; secrets redacted from receipts and ASE (hash inputs/outputs); signed releases + SBOM + dependency scan + pinned Actions + image signing + secret scanning. Bind listeners to `127.0.0.1` in dev/test. Run `npx ecc-agentshield scan .` on harness/config per the security_scan runbook.

---

## 8. Support, billing & lifecycle

- **Billing metric:** verified high-risk actions / month + incidents contained (value = controlled, provable actions), not seats. Tiers per GTM §9.
- **Retention tiers:** OSS local-only → Team 7–30d → Startup 90d → Growth 1y → Enterprise custom. (Receipt ledger is cold/immutable; event tier follows retention.)
- **Support:** OSS community (GitHub issues/discussions); paid tiers add SLAs; enterprise adds self-hosted/air-gapped support + evidence-reporting assistance.
- **Policy & rule lifecycle:** versioned Cedar bundles **and** detection-rule/playbook configs; dry-run/simulation; canary (`log_only`) rollout; backward-compatible API versions.

---

## 9. Operational recommendation

Run AegisAgent as a self-hosted-first, OSS-trust-optimized product whose unique operational burdens are **(1) canonicalization stability**, **(2) receipt-chain integrity**, and **(3) the SOC's async isolation + deterministic detection** — the three things that make "provable approvals operated as a SOC" actually hold. If those invariants hold, the compliance value (Article 14 / SOC 2 evidence + provable incident records) is real; if any slips — a canon skew, a tampered chain, a detection that gates on a score, or a SOC that backpressures the action path — the core promise breaks. Treat all three as P0 reliability surfaces.
