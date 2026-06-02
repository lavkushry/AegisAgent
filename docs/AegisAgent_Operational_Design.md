# AegisAgent — Operational Design & Community (June 2026 reset)

**Product:** AegisAgent
**Category:** Agent Action Integrity (integrity + provenance layer for agent actions)
**Version:** v0.2 (re-anchored)
**Date:** 2026-06-02
**Owner:** Lavkush Kumar
**Read first:** [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md)

> ⚠️ **Reset note.** v0.1 framed operations around a developer-first "Agent Action Firewall." This version keeps the operational discipline but re-anchors community/positioning on the **integrity layer** and adds the operational concerns the integrity primitives introduce: canonicalization versioning, receipt-chain integrity + signing-key management, approval-channel reliability, and self-hosted-first operations.

---

## 1. Operating posture

AegisAgent is **developer-first security infrastructure** with a twist: the headline value (provable approvals + provenance gating + verifiable receipts) is also what compliance buyers pay for. So operations must serve two audiences at once:

- **Developers** — clean OSS, 10-minute self-hosted setup, fail-closed-by-default SDK, readable Cedar policies, the open receipt spec.
- **Security/compliance** — tenant isolation, signed receipts, SOC 2 / EU AI Act Article 14 evidence export, self-hosting inside their trust boundary.

Market backdrop (see GTM doc for detail): developers adopt agents heavily but distrust output (Stack Overflow 2026: ~84% use, ~29% trust); GitHub workflows are agentic (Copilot coding agent opens PRs from issues); the Invariant Labs GitHub-MCP issue (a malicious issue leaking private-repo data) is the canonical real-world proof of the confused-deputy threat AegisAgent's provenance gate closes.

---

## 2. Community & distribution operations

- **Optimize for OSS trust signals:** clean README, 10-min quickstart, examples, SECURITY.md, CONTRIBUTING.md, transparent ROADMAP, changelog, GitHub stars/issues/discussions.
- **The open receipt spec is the flywheel.** Publish the verifiable action-receipt format as a public spec + reference verifier; invite gateways (incl. Microsoft toolkit, MintMCP, Pipelock) to emit/consume it. Adoption of the *format* is a leading indicator, tracked alongside stars.
- **Curated MCP security catalog:** classify MCP servers by capability, auth model, credential handling, tool risk, manifest stability — feeds the provenance gate's default trust levels.
- **Content motion:** lead with the approve-then-swap demo and the Article 14 evidence story (topics in GTM §14). Channels: GitHub, HN, Product Hunt, MCP/AI-eng communities, security newsletters.

**Default GitHub policy (ships in OSS):** treat public issue content as `untrusted_external`; forbid untrusted context from triggering private-repo reads or public/cross-repo writes; require approval for cross-repository data movement — directly mitigating the Invariant Labs class of attack.

---

## 3. Deployment topologies

### 3.1 Self-hosted single binary (first-class — the neutrality wedge)
Rust gateway + SQLite (WAL) + embedded Cedar + local hash-chained receipts. Runs inside the customer trust boundary; no prod tool calls leave their network. Target: `docker compose up` → first protected action < 20 min.

### 3.2 SaaS (multi-tenant)
Kubernetes; Postgres; OTel collector → Grafana/Prometheus/Loki; Next.js dashboard; hosted Slack/Teams approvals. Tenant isolation enforced on every query (`tenant_id`), row-level scoping in middleware.

### 3.3 Enterprise / self-managed
Helm chart; external Postgres/Redis; OIDC/SAML; SIEM export; **transparency-log / receipt signing** (KMS-backed); air-gapped mode; long retention.

---

## 4. Operating the integrity primitives (the parts that need new runbooks)

### 4.1 Canonicalization versioning (critical)
The fail-closed guarantee depends on Python/TS/Go SDKs and the Rust gateway producing **byte-identical** canonical actions. Operational rules:
- Pin a canonicalization spec version (target RFC 8785 JCS) in every SDK and the gateway; include `canon_version` in the action envelope.
- A canonicalization change is a **breaking change**: bump `canon_version`, support old+new during a migration window, never silently alter hashing.
- CI gate: cross-language byte-equality test on a fixed corpus must pass before release (a mismatch silently breaks integrity).

### 4.2 Receipt-chain integrity & key management
- Per-tenant hash chain; periodic checkpoint (anchor `receipt_hash` to an append-only/transparency log in enterprise).
- Signing keys (enterprise) in KMS/Vault; rotation runbook preserves verifiability across rotations (key ID in receipt).
- `GET /v1/receipts/:id/verify` is monitored; a `tampered` result pages security.

### 4.3 Approval-channel reliability
- Slack/Teams callback signatures verified; approver role lookup required.
- Approvals are single-use, time-boxed (`expires_at`), replay-checked (nonce).
- Channel outage → approvals stay pending, fallback to dashboard, auto-deny on timeout. SLO: approval delivery p95 < 5s.

### 4.4 SDK bypass detection
Agents must not hold raw tool credentials (Token Broker proxies sensitive calls). Detect direct tool use (network policy guidance, proxy-only creds). A bypassed SDK is treated as an incident.

---

## 5. SLOs

```text
Authorization API p95:        < 150 ms
Policy evaluation p95:        < 75 ms
action_hash compute:          < 5 ms
Approval delivery p95:        < 5 s
MCP proxy overhead p95:       < 250 ms
Receipt/audit enqueue success: 99.9%
SaaS availability (MVP):      99.5%  (enterprise target 99.9%)
```

Key integrity metrics (alerting): `approval_hash_mismatch_total` (tamper attempts), `provenance_denials_total`, `receipt_verify_failures_total`, `canonicalization_version_skew`.

---

## 6. Reliability & fail-closed

| Failure | Behavior |
|---|---|
| Gateway/policy unreachable | SDK fails closed for mutating/high-risk; read-only fail-open only if explicitly configured |
| Approval channel down | Pending + dashboard fallback + auto-deny on timeout |
| Receipt/audit down | Critical actions block until receipt writable; low-risk buffer+retry |
| Hash mismatch / canon skew | FAIL CLOSED; never execute; record tamper/skew event |

---

## 7. Security operations

Tenant isolation on every query; parameterized SQLx only; default-deny unknown agent/tool/MCP server/MCP tool; secrets redacted from receipts (hash inputs/outputs); signed releases + SBOM + dependency scan + pinned Actions + image signing + secret scanning. Bind listeners to `127.0.0.1` in dev/test.

---

## 8. Support, billing & lifecycle

- **Billing metric:** verified high-risk actions / month (value = controlled, provable actions), not seats. Tiers per GTM §9.
- **Retention tiers:** OSS local-only → Team 7–30d → Startup 90d → Growth 1y → Enterprise custom.
- **Support:** OSS community (GitHub issues/discussions); paid tiers add SLAs; enterprise adds self-hosted/air-gapped support + evidence-reporting assistance.
- **Policy lifecycle:** versioned Cedar bundles, dry-run/simulation, canary rollout, backward-compatible API versions.

---

## 9. Operational recommendation

Run AegisAgent as a self-hosted-first, OSS-trust-optimized product whose unique operational burdens are **canonicalization stability** and **receipt-chain integrity** — the two things that make "provable approvals" actually provable. If those operational invariants hold, the compliance value (Article 14 / SOC 2 evidence) is real; if they slip, the core promise breaks. Treat them as P0 reliability surfaces.
