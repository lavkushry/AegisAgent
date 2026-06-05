# SOC Delivery Plan — the PR backlog ("the team of 1000")

> How AegisAgent goes from *inline integrity gateway* (built) to **Agent SOC** (Wazuh/Elastic-grade for
> AI agents). Source of truth: [`docs/AegisAgent_Agent_SOC_Design.md`](../../../docs/AegisAgent_Agent_SOC_Design.md) §27.
> Rule of the road: **one vertical-slice PR at a time, green before the next.** Each PR names an *owner*
> (a `.claude/agents/` subagent), its dependencies, size, and a merge gate. Don't stack unverified Rust.

## Ground truth (scanned 2026-06-05)

**Built & merged on `main`** (inline plane): `/v1/authorize` + Cedar gate, 6-level deterministic
trust-provenance, approval integrity (hash-bound + single-use + expiry), hash-chained receipts + verifier +
CLI, tenant isolation, MCP registration/approval. SDK canonicalizers: Python (full SDK) + Go + TS (`canon`
only), all byte-parity-locked to the shared corpus.

**Not built** (async SOC plane): event stream, detection, correlation, notify, response control, indexer +
console, RCA narrator, agentless. That gap **is** this backlog.

## The four laws every PR must hold (from the design doc §2)
1. **Deterministic policy decides; scores never gate.** Risk score is advisory metadata only.
2. **LLM only narrates closed incidents.** No model reads live/untrusted evidence (no 2nd-order injection).
3. **Inline path stays async-free (<75 ms).** Detection is a *consumer* of the event stream, never inline.
4. **Moat primitives preserved end-to-end** (hash-bound approvals, provenance gating, receipt chain).

---

## Swimlane A — SOC plane · owner: `gateway-dev` (mostly sequential; A0 is the keystone)

| PR | Title | Depends | Size | Merge gate / acceptance |
|----|-------|---------|------|--------------------------|
| **A0** | **Phase 0 — async event emitter** (`events.rs`; `tokio::mpsc` from `/v1/authorize`, background drain) | — | M | `cargo test` green incl. `authorize_emits_security_event`; inline path still non-blocking |
| A1 | Phase 1 — deterministic **detection rule engine** (atomic rules: confused-deputy, manifest drift) | A0 | M | rules match ASE events; unit tests per rule; zero LLM in path |
| A2 | Phase 2 — **notify sink** (Slack/webhook on deny + approval) | A0 | S | redacted payloads; signature on outbound; ret/backoff |
| A3 | Phase 3 — **correlation engine** (freq + sequence + window → incidents) | A1 | L | deny-storm / exfil-sequence / runaway tests; stateful, async |
| A4 | Phase 4 — **response control API** (`freeze`/`revoke`/`quarantine` + responder) | A0 | M | flips `agents.status`/`mcp_servers.status`; fail-closed (unknown→deny); tenant-scoped |
| A5 | Phase 5a — **event indexer** (`security_events` table + query API `GET /v1/alerts`,`/v1/incidents`) | A0 | M | parameterized + tenant-bound; index on `tenant_id`; pagination |
| A6 | Phase 5b — **SOC Console** (live feed + incident timeline; wire `dashboard-mock.html` to real API) | A5 | M | reads real endpoints; no secrets client-side |
| A7 | Phase 6 — **RCA narrator** (sandboxed LLM, *post-incident only*, Law 2) | A3 | M | runs only on closed incidents; isolated; output is narration, never a gate |
| A8 | Phase 7 — **agentless ingestion + behavioural baselining** | A5 | L | collector `POST /v1/ingest/agentless`; baseline → provenance signal only |

## Swimlane B — SDK parity & canon hardening · owner: `sdk-dev` (parallel to A)

| PR | Title | Depends | Size | Merge gate / acceptance |
|----|-------|---------|------|--------------------------|
| B1 | **Go SDK client + `protect`** (fail-closed: hash-mismatch / expiry / unreachable → refuse) | — | M | mirrors `decorator.py` semantics; unit tests w/ mocked gateway |
| B2 | **TS SDK client + decorator** (fail-closed) | — | M | same semantics; `node --test` green |
| B3 | **CI canon byte-parity gate** (Go+TS+Py+Rust all assert the shared corpus, blocking) | — | S | one workflow; red on any divergence (protects fail-closed) |
| B4 | **Float corpus + RFC 8785 number formatting** hardening | B3 | S | non-finite rejected; shared float vectors; all 4 langs agree |

## Swimlane C — policy & threat · owner: `security-auditor` (parallel)

| PR | Title | Depends | Size | Merge gate / acceptance |
|----|-------|---------|------|--------------------------|
| C1 | **Anti-confused-deputy default policy pack** (Invariant Labs class) + Cedar tests | — | M | mutating + `untrusted_external`/`malicious_suspected`/`unknown` → deny; tests in `policy.rs` |
| C2 | **T-D hardening** (attacks on the SOC): tamper-attempt receipts + race-safe chain head (txn) | A0 | M | concurrent-append test; tamper emits its own receipt |
| C3 | **MCP manifest signing + drift → provenance downgrade** | — | M | drift detected → label tightened, never loosened |

## Swimlane D — docs / ops · owner: `docs-agent` + `ops` (parallel)

| PR | Title | Depends | Size | Merge gate / acceptance |
|----|-------|---------|------|--------------------------|
| D1 | **Reconcile `ROADMAP.md`** with SOC-on-moat (it predates the pivot; says "no SIEM") | — | S | roadmap matches design doc; "not a SIEM" reframed as "rides the moat" |
| D2 | **OTel exporter + metrics** (`approval_hash_mismatch_total`, `provenance_denials_total`) | A0 | M | spans on handlers; metrics scrapeable |
| D3 | **Helm / prod hardening + SIEM/webhook export** | A5 | L | `helm lint` green; egress allowlist; no `0.0.0.0` outside prod charts |

---

## Critical path (the order that actually unblocks the product)
**A0 → A1 → A3 → A7** (emit → detect → correlate → explain) is the SOC spine.
**A4** (containment) and **A5/A6** (visibility) branch off A0/A5 and deliver demoable value early.
B-, C-, D-lanes run in parallel from day one (no dependency on A).

## Cadence
RED → GREEN → fmt → clippy → PR → review (`pr-reviewer` / `security-auditor`) → merge → next.
After each merge, `memory-keeper` records what shipped; `docs-agent` updates the site if behaviour changed.
