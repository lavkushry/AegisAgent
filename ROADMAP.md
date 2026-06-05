# AegisAgent Roadmap

> Re-anchored **2026-06-05** on the integrity-layer wedge *and* the Agent SOC direction.
>
> Source of truth for *why* the product is shaped this way:
> [`docs/AegisAgent_Gap_Reassessment_2026-06.md`](docs/AegisAgent_Gap_Reassessment_2026-06.md).
> Architecture for the SOC surface:
> [`docs/AegisAgent_Agent_SOC_Design.md`](docs/AegisAgent_Agent_SOC_Design.md).
>
> The generic gateway loop (intercept → policy → allow/deny → audit → approval) is commodity —
> free toolkits and OSS already ship it. The roadmap prioritizes the **two defensible
> differentiators** that form the moat: **(1)** approval integrity (SHA-256 hash-bound, single-use,
> fail-closed) and **(2)** deterministic trust-provenance gating (6 levels as Cedar policy input,
> not a text score). The Agent SOC is the detection/response/evidence plane built **on top of** those
> primitives — it rides the moat, does not widen it.

---

## MVP launch readiness (done / in progress)

- Local gateway quickstart with Docker Compose. ✅
- Python SDK `@protect_tool` with **fail-closed approval action-hash verification**. ✅
- Default Cedar policy pack: read-only allow, main-merge approval, untrusted-mutation denial. ✅
- GitHub attack demo with audit output. ✅

---

## Q3 2026 — harden the integrity primitives (the moat)

These ship before anything else. The Agent SOC phases below are consumers of this foundation;
none of them weaken it.

- **Canonicalization spec v1** (`aegis-jcs-1`, target RFC 8785 JCS) shared across SDK + gateway,
  with a CI byte-equality gate. The fail-closed guarantee is only as strong as this lock.
- **Approval Integrity Engine hardening:** expiry fail-closed at SDK ✅ and gateway; **single-use**
  atomic consume (replay T-A3) ✅ (SDK verified; gateway pending `cargo`); edit → re-hash →
  re-evaluate confirmation; tamper-attempt receipts.
- **Verifiable action-receipt format v0** (per-tenant hash chain): open spec ✅
  ([`docs/action-receipt-spec.md`](docs/action-receipt-spec.md)) · Python reference verifier ✅
  (`aegisagent/receipts.py`, 8/8) · CLI ✅ · gateway emission into `action_receipts` ·
  `GET /v1/receipts/:id/verify` (written, pending `cargo`). **Next:** race-safe chain head
  (transaction); enterprise signing.
- **Trust-Provenance Gate:** deterministic 6-level model finalized; classifier integration that can
  only *tighten*, never loosen a label.
- Slack approval callback signature verification + approver role lookup.
- The "approve-then-swap blocked" demo as the flagship — this is the positioning proof.

---

## Q4 2026 — evidence, provenance depth, and reach

- **SOC 2 / EU AI Act Article 14 evidence export** (receipt packs; Article 14 deadline
  2026-08-02 creates concrete demand).
- TypeScript SDK with byte-identical canonicalization (`aegis-jcs-1` parity test in CI).
- MCP manifest signing + drift detection feeding provenance downgrade.
- MCP proxy execution path (beyond authorization).
- OpenTelemetry exporter; `approval_hash_mismatch_total` / `provenance_denials_total` metrics.
- GitHub App integration + PR comments/checks; default anti-confused-deputy policy pack.
- **Phase 0 (keystone) — Async Agent Security Event emitter:** after every `/v1/authorize`
  decision, emit one immutable ASE event via a non-blocking `tokio::mpsc` channel drained by a
  background task. This does **not** add latency to the <75 ms inline path (Law 3 below). Every
  subsequent SOC phase is a consumer of this one stream and never touches the hot path again.
  Unlocks the entire async detection plane.
- **Phase 1 — Deterministic detection rules:** atomic YAML rules evaluated against ASE events
  (single-event matches for confused-deputy, MCP drift, approval tamper). Cedar decides; scores
  annotate display only. No LLM in this path.
- **Phase 2 — Notify sink:** Slack / webhook consumer on deny + approval events. L1 visibility
  without any dashboard yet.

---

## 2027 H1 — Agent SOC: correlation, response, and the console

*This section rides the moat — it does not widen it.* The detections, alerts, and responses below
are defensible only because they carry `action_hash` and `receipt_hash` as immutable evidence.
A generic SIEM can record; AegisAgent can **prove**. See
[`docs/AegisAgent_Agent_SOC_Design.md §27`](docs/AegisAgent_Agent_SOC_Design.md) for the full
build order rationale and the four design laws that keep the SOC from drifting into commodity.

- **Phase 3 — Correlation engine + incidents:** frequency, sequence, and time-window correlation
  rules (deny-storm, read-sensitive → egress, runaway-agent). Incident model with
  `evidence_receipts` linking each event to its chain position — the incident timeline is provable.
- **Phase 4 — Response control API:** `POST /v1/agents/:id/freeze|revoke` ·
  `POST /v1/mcp/servers/:server_key/quarantine` — tenant-scoped, parameterized, fail-closed. The
  authorize path already reads `agents.status`, so a freeze takes effect on the next action
  automatically. Enables L3 graduated-autonomy containment (reversible, low-blast-radius actions
  may auto-fire; destructive actions stay human-gated).
- **Layer-on adapters:** AegisAgent adds integrity on top of existing gateways (Microsoft Agent
  Governance Toolkit, MintMCP, Pipelock). Sold as interop, not displacement.
- Enterprise: transparency-log / KMS-backed receipt signing; air-gapped mode.

---

## 2027 H2 — SOC console, RCA narrator, and breadth

- **Phase 5 — ClickHouse sink + SOC Console:** live decision feed, incident timeline (each row
  carries its `receipt_hash` — timeline is *provable*, not just recorded), agent risk scoreboard,
  receipt integrity viewer. The console is the daily-use surface; its defensibility is the receipt
  chain beneath it.
- Memory/RAG provenance + receipts (AgentPoison/PoisonedRAG class of threats).
- Policy bundle versioning + dry-run / simulation mode.
- Per-tenant rate limiting; webhook export; Helm + production hardening.
- Drive adoption of the open action-receipt spec across the ecosystem.
- **Phase 6 — RCA narrator (sandboxed LLM, post-incident only):** a single LLM module that
  *summarises* an already-decided, already-closed, already-evidenced incident and writes a
  human-readable markdown report. It has no tools, no path to enforcement, and treats all evidence
  as inert data. This is the **only** LLM in the SOC. It never gates a decision.
- **Phase 7 — Agentless ingestion + behavioural baselining:** ingest GitHub webhooks, OpenAI
  traces, LangSmith, OTel/OTLP, Slack audit logs without requiring SDK installation. Enables value
  before any customer code change. Baselining surfaces anomalous agent behaviour for the
  correlation engine without replacing deterministic rules.

---

## What AegisAgent is NOT — and what the Agent SOC is NOT

AegisAgent is **not** a generic SIEM, DLP, network egress firewall, model scanner, GRC
automation suite, or identity lifecycle manager. The Agent SOC is specifically **not** those
things either — it is a narrow, focused surface on the integrity spine:

> **Monitor / detect / correlate / approve / contain / PROVE agent actions** — and nothing else.

The four design laws that keep the Agent SOC from drifting into a commodity SIEM (from
[`docs/AegisAgent_Agent_SOC_Design.md §2`](docs/AegisAgent_Agent_SOC_Design.md)):

1. **Deterministic policy decides; scores never gate.** Cedar evaluates source trust and
   `mutates_state`. Risk scores are advisory display metadata — never the allow/deny input.
   A number is attacker-gameable; a deterministic provenance gate is not.
2. **The LLM investigates; it never decides, enforces, or reads instructions.** One sandboxed
   LLM narrates closed incidents (Phase 6). No LLM reads live, attacker-controlled evidence —
   that would recreate the very prompt-injection threat the product defends against.
3. **The inline path is sacred; detection is asynchronous.** `POST /v1/authorize` has a <75 ms
   budget. The SOC is purely out-of-band; it is value-add, never a tax on the inline path.
4. **Every moat primitive is preserved end-to-end.** `aegis-jcs-1` stays byte-identical;
   approvals stay hash-bound and single-use; receipts stay hash-chained. The SOC *consumes and
   surfaces* these; it never weakens them.

**AegisAgent integrates with — it does not become — enterprise SIEM, SOAR, and GRC.** Webhook
export and OTel metrics feed existing stacks (Splunk, Datadog, PagerDuty). The integrity
primitives and the verifiable receipt chain are what AegisAgent contributes to those integrations;
the query, correlation, and dashboard infrastructure those tools already own is not duplicated.
A feature that violates one of the four laws above would make AegisAgent a *better generic SIEM*
and therefore a *worse* AegisAgent — those features are out of scope.
