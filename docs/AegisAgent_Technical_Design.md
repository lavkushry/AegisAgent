# AegisAgent — In-Depth Technical Design (June 2026 reset)

**Product:** AegisAgent
**Category:** Agent Action Integrity → Integrity-anchored Agent SOC
**Version:** v0.3 (re-anchored on the integrity-anchored Agent SOC)
**Date:** 2026-06-05
**Founder:** Lavkush Kumar
**Read first:** [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md) · **SOC architecture:** [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md)

> ⚠️ **Reset note (two layers).** v0.1 designed a generic "Agent Action Firewall" (intercept → policy → allow/deny → approval → audit). That loop is now commodity, so it is **table stakes**. v0.2 elevated three components to the center: **Approval Integrity Engine (§4.3)**, **Trust-Provenance Gate (§4.4)**, **Verifiable Action Receipts (§4.5)**. **v0.3 adds the async SOC plane (§4.10)** — the detection/correlation/response/console layer that consumes the receipt+provenance stream — governed by the two-plane principle (§2) and the four design laws (§13). The SOC rides the moat; it does not replace it, and it never enters the synchronous action path.

---

## 0. Research foundation

Patterns drawn from: Cedar (Rust-native ABAC engine), OpenTelemetry (vendor-neutral telemetry), LangGraph / OpenAI Agents SDK human-in-the-loop, AgentDojo & InjecAgent (tool-use injection benchmarks), Wazuh (decode→rules→alert→active-response pipeline, adapted for agents), MITRE ATLAS + OWASP LLM Top 10 (detection taxonomy), and the June-2026 competitor field. RFC 8785 (JSON Canonicalization Scheme) and Sigstore/transparency-log patterns inform the integrity primitives.

---

## 1. Technical thesis

> **AegisAgent is the enforcement point that makes an agent-action decision *provable* — the human-approved action is the executed action (bound by hash, enforced fail-closed at the SDK), and the authorization is gated on the deterministic trust level of the triggering content — and then operates an async SOC on the resulting verifiable evidence.**

The baseline gateway answers "is it allowed?" The defensible engineering answers three harder questions:
1. **Integrity:** can we cryptographically prove the executed action == the approved action?
2. **Provenance:** can an untrusted source ever drive a privileged action? (Deterministically — not via a text classifier.)
3. **Operability:** can a SOC detect, correlate, contain, and *prove* what agents did — without weakening 1–2, slowing the action path, or becoming a new injection surface?

---

## 2. System overview & the two-plane principle

```text
INLINE PLANE (synchronous, <75 ms — the action path)
  User / Application
          v
  AI Agent Runtime (LangGraph / OpenAI Agents SDK / CrewAI / AutoGen / custom)
          v
  AegisAgent SDK (Go / TS / Python)  ── canonicalizes action, enforces FAIL-CLOSED on hash mismatch
          v
  AegisAgent Gateway (Rust + Axum + Tokio)        [standalone OR layered on an existing gateway]
     ┌─────────────────────┬─────────────────────────┐
     │ Identity Resolver    │ Trust-Provenance Gate    │  (deterministic 6-level source labels)
     │ Policy Engine (Cedar)│ Risk Engine (advisory)   │
     │ Approval Integrity   │ Receipt + Audit Writer   │  (freeze→hash→bind→fail-closed; hash-chained receipts)
     │ MCP Gateway          │ Tool Proxy               │
     └──────────┬──────────┴─────────────────────────┘
          v     │ emit Agent Security Event (fire-and-forget, tokio::mpsc — non-blocking)
  External Tools / MCP                ╲
                                       ╲ (async; never in the action path)
ASYNC SOC PLANE (out-of-band — the monitoring/response plane)
  Event Bus → Normalizer → Detection (deterministic) → Correlation → Alert
                                                                  → { Response Engine → Gateway control API,
                                                                      Indexer, Notify (Slack/webhook),
                                                                      RCA narrator (sandboxed LLM) }
                                                                  → SOC Console
```

Decision and enforcement are separated (Cedar model). Two crucial structural facts:
1. **The SDK is inside the trust boundary** and performs the final fail-closed check, so a compromised agent process cannot execute an unapproved action even if it reaches the gateway's approval.
2. **The SOC is a strictly asynchronous consumer.** The authorize handler emits an event after deciding; emission is fire-and-forget. The SOC can be slow, restart, or fail entirely — the action path is unaffected (Design Law 3).

---

## 3. Scope

**MVP:** protect a coding agent on GitHub + Slack + one MCP server, *with provable integrity*, **and emit the SOC event stream (Phase 0 keystone)**. Headline components (§4.3–4.5) are the differentiators; the SOC plane (§4.10) is the phased product surface; the rest (registry, policy, risk, MCP gateway, audit) are table stakes.

**Out of scope:** a **generic** SIEM/DLP/CNAPP, model scanning, GRC automation, identity lifecycle, LLM auto-remediation that reasons over attacker content. The SOC we build is **integrity-anchored** (deterministic detection on verifiable evidence), not a log-ingesting SIEM.

---

## 4. Component design

### 4.1 AegisAgent SDK (Go + TS shipped · Python reference)

Responsibilities: register agent metadata; wrap tool functions; **compute the canonical action and `action_hash`**; send `/v1/authorize`; pause on `require_approval`; **before executing, re-fetch the approval, consume it (single-use), and refuse to run unless the about-to-execute `action_hash` == the approved `action_hash`**; attach provenance labels; emit OTel spans.

```python
from aegisagent import AegisClient, protect_tool

aegis = AegisClient(api_key="aegis_xxx", agent_id="coding-agent-prod", environment="production")

@protect_tool(client=aegis, tool="github", action="merge_pull_request", risk="high")
def merge_pull_request(repo: str, pr_number: int, branch: str):
    # The decorator canonicalizes {tool, action, resource, parameters}, computes action_hash,
    # authorizes, and (if approved) consumes + verifies the approved hash == this call's hash before running.
    return github.merge_pull_request(repo=repo, pr_number=pr_number, branch=branch)
```

**Fail-closed contract (normative):** the SDK MUST NOT execute if (a) the gateway is unreachable for a mutating/high-risk action, (b) the approval status is not `approved`, (c) the approved `action_hash` ≠ the recomputed hash, (d) the approval is expired/replayed, or (e) the single-use approval cannot be atomically consumed (409).

> **SDK status (2026-06-05):** **Go** (`sdk-go`) and **TS** (`sdk-typescript`) ship the verified `aegis-jcs-1` canonicalizer — byte-parity with the shared corpus, `go test` + `node:test` green; their HTTP client + `@protect_tool`-equivalent decorator are next. **Python** (`sdk-python`) is the complete reference SDK (`@protect_tool` + receipts verifier, 25/25) and the canonicalization oracle. The Rust gateway shares the scheme.

### 4.2 Runtime Gateway (Rust + Axum)

Authenticates SDK requests; resolves tenant/agent/user/session; normalizes the tool call; invokes Trust-Provenance Gate → Policy Engine → Risk Engine; creates approvals; writes receipts/audit; **emits the Agent Security Event (async)**; returns decision. Stateless, horizontally scalable. SQLite (MVP) → Postgres (scale) via SQLx (WAL, busy-timeout). Embedded Cedar for sub-ms decisions.

### 4.3 Approval Integrity Engine — **headline (moat #1)**

**Goal:** an approval is valid for exactly one action — the one shown to the human — and nothing else.

**Canonical action.** `{tool, action, resource, mutates_state, parameters}` serialized with a deterministic scheme so the Go, TS, and Python SDKs and the Rust gateway produce identical bytes (now verified byte-identical via the shared corpus). `action_hash = SHA-256(canonical_action)`.

> **Implemented (scheme `aegis-jcs-1`):** keys sorted by Unicode code point, compact separators, **raw UTF-8 (no `\uXXXX`)**, `null` for absent resource, reject non-finite floats. Locked by [`tests/canonical_action_vectors.json`](https://github.com/lavkushry/AegisAgent/blob/main/tests/canonical_action_vectors.json), asserted by both a Python test and a Rust test (`gateway/src/routes.rs::canonical_action_matches_shared_corpus`) — byte-equality across languages guaranteed transitively.

**Binding.** On `require_approval`, the gateway persists an approval row bound to `action_hash`, the canonical action, approver group, and expiry. The Slack/dashboard card renders the canonical action so the human approves *that*.

**Edit = new action.** Edited parameters → new canonical action → new `action_hash` → mandatory re-evaluation. An old approval never covers edited bytes.

**Fail-closed enforcement.** `GET /v1/approvals/:id` returns the bound `action_hash`. The SDK recomputes the hash, consumes the approval (single-use, atomic), and refuses on mismatch/expiry/replay.

> **Implementation status (2026-06-05).** *Done & verified (Python):* `action_hash` binding; SDK fails closed on hash mismatch, expiry, and un-consumable approval. *Done, pending `cargo` verification (Rust):* gateway-side expiry (`get_approval`→`EXPIRED`; `approve`→409), single-use `consumed_at` + atomic `db::consume_approval` + `POST /v1/approvals/:id/consume`, cross-language corpus parity. *Pending:* race-safe chain head (transaction); enterprise signing.

**Threats closed:** approve-then-swap, post-approval tampering, replay/reuse, render-vs-bytes (OWASP "approval manipulation" — T-A). Every such event is also emitted to the SOC as a high-severity detection.

### 4.4 Trust-Provenance Gate — **headline (moat #2)**

**Goal:** make "where did the triggering content come from" a deterministic, first-class authorization input — not a probabilistic text score.

**Six levels:** `trusted_internal_signed`, `trusted_internal_unsigned`, `semi_trusted_customer`, `untrusted_external`, `malicious_suspected`, `unknown`.

**Propagation.** A run carries the lowest trust level of any content it consumed. The label is a Cedar context attribute (`context.source_trust`).

**Determinism rule (normative):** classifiers may only *lower* trust (tighten), never *raise* it. A deterministic `forbid` for `mutates_state && untrusted_external` cannot be overridden by a "looks benign" score. **This is also Design Law 1 for the SOC: detection scores never re-open a deterministic gate.**

```cedar
forbid (principal, action == Action::"tool_call", resource)
when {
    context.mutates_state == true &&
    (context.trust_level == "untrusted_external" || context.trust_level == "malicious_suspected" || context.trust_level == "unknown")
};

@decision("require_approval")
@approver_group("security-reviewers")
permit (principal, action == Action::"tool_call", resource)
when {
    context.mutates_state == true && context.trust_level == "semi_trusted_customer"
};
```

**MCP manifest drift** feeds this gate: a tool whose manifest hash ≠ pinned hash is treated as reduced provenance; the SOC raises drift detection `AEG-4002`.

### 4.5 Verifiable Action Receipts — **headline (moat #3) + the SOC evidence spine**

**Goal:** every protected action yields tamper-evident, independently verifiable evidence — usable as SOC 2 / Article 14 evidence *and* as the SOC's immutable cold tier.

**Receipt fields:** `id, tenant_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash`.

**Tamper evidence.** Receipts form a per-tenant hash chain: `receipt_hash = SHA-256(canonicalize(body))` where `body` includes `prev_receipt_hash` (field edits and re-linking both detectable). Optional Sigstore-style transparency-log/signing in enterprise mode. Open format ([`docs/action-receipt-spec.md`](action-receipt-spec.md)). **In the SOC, every alert and incident references the `receipt_hash` chain covering its events — which is what makes incident timelines *provable* (Design Law 4).**

> **Implementation status (2026-06-05).** *Done & verified (Python):* open format + hash-chain reference verifier (`aegisagent/receipts.py`) + CLI + shared corpus. *Done, pending `cargo`:* parity lock, per-decision emission into `action_receipts` (`emit_action_receipt`), `GET /v1/receipts/:id/verify`. *Next:* race-safe chain head; enterprise signing/anchoring.

### 4.6 Policy Engine (Cedar) — table stakes
Native Cedar; `action_hash` and `source_trust` first-class context; `@decision("require_approval")` yields the third state. OPA/Rego adapter optional later.

### 4.7 Risk Engine — table stakes (advisory only)
Enriches/routes for display; **does not override `forbid` and never gates** (Design Law 1). Inputs: action risk, environment, resource sensitivity, `source_trust` penalty, MCP trust penalty, reversibility, approval history. Produces `risk_score`/`risk_level` as metadata the SOC sorts and colors on.

### 4.8 MCP Gateway — table stakes
Register/discover/approve/disable tools; pin + hash manifests; drift detection → provenance signal + SOC alert; deny unknown tools; authorize every MCP tool call; session-aware routing; audit.

### 4.9 Layer-on adapters
Run AegisAgent in front of (or as a callout from) an existing gateway (Microsoft toolkit, MintMCP, Pipelock): the existing gateway does discovery/routing/baseline policy; AegisAgent adds the integrity engine + provenance gate + receipts + the SOC. Distribution by complementarity, not displacement.

### 4.10 Agent SOC plane (async) — **the product surface (see [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md))**

All components below are **out-of-band consumers** of the event stream; none sits in the action path.

- **4.10.1 Event emitter (Phase 0 keystone).** After the gateway decides, it builds an **Agent Security Event (ASE)** and `tx.send()`s it to a `tokio::mpsc` channel drained by a background task (same async pattern as audit writes). Non-blocking; <1 ms; failure degrades the SOC, never the action. The ASE carries the decision *and* the integrity fields (`action_hash`, `receipt_hash`) so downstream evidence is tamper-evident.
- **4.10.2 Normalizer (decoder).** Reshapes the ASE into a flat typed event, enriching new signals (`data_access`, `destination`, `manifest_hash`). Reuses `canon.py` semantics.
- **4.10.3 Detection engine (deterministic).** Declarative YAML rules → matchers. **Atomic** rules (single event, e.g. `confused-deputy-mutation` AEG-1002) and the input to correlation. No LLM, no score gates (Design Laws 1–2). Each rule carries a `level` (0–15) and ATLAS/OWASP tags.
- **4.10.4 Correlation engine (stateful).** Per-`agent_id`/`run_id` frequency/sequence/window matching (deny-storm AEG-2010, read-sensitive→exfil AEG-3007). Opens **incidents**; timelines are provable because each event carries a `receipt_hash`.
- **4.10.5 Response engine (Active Response).** Deterministic `verdict → action` mapping → calls the gateway control API (`freeze`/`revoke`/`quarantine`). Tenant-scoped, fail-closed, reversible, audited.
- **4.10.6 RCA narrator (the only LLM).** Runs **only** on a closed, evidenced incident; sandboxed; no tools; evidence passed as **inert data**; output is a human-read markdown report that cannot change any decision (Design Law 2 — closes second-order injection T-D1).
- **4.10.7 Indexer + Console.** Hot event tier (SQLite now → ClickHouse when aggregation volume warrants) + SOC Console (live feed, approval queue, incident timeline, receipt-integrity viewer).

---

## 5. Data model (SQLite MVP → Postgres scale; all tenant-scoped)

Core tables (tenant-isolated, parameterized): `tenants, users, agents, tools, tool_actions, mcp_servers, mcp_tools, policies, decisions, approvals, audit_events, action_receipts`. **Integrity columns** (live in `approvals`/`action_receipts` today):

```sql
-- approvals: bind to the frozen action
--   original_call_hash  TEXT  -- SHA-256 of canonical action (action_hash)
--   original_skill_call TEXT  -- exact bytes shown to approver
--   consumed_at         DATETIME  -- single-use / replay defense (atomic consume)
--   expires_at          DATETIME

-- action_receipts: verifiable, hash-chained evidence (and SOC cold tier)
--   prev_receipt_hash TEXT NOT NULL, receipt_hash TEXT NOT NULL, action_hash TEXT, source_trust TEXT NOT NULL ...
```

**SOC tables (new, async plane):**

```sql
CREATE TABLE agent_security_events (         -- the ASE stream (hot tier)
  id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id),
  ts TIMESTAMPTZ NOT NULL, event_type TEXT NOT NULL,
  agent_id UUID, user_id TEXT, run_id TEXT, trace_id TEXT,
  tool TEXT, action TEXT, resource TEXT, mutates_state BOOLEAN,
  data_access TEXT, destination TEXT,         -- NEW signals for exfil detection
  source_trust TEXT NOT NULL, decision TEXT NOT NULL,
  risk_score INTEGER, manifest_hash TEXT,     -- risk_score advisory only
  action_hash TEXT, receipt_hash TEXT,        -- integrity linkage (tamper-evident)
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_ase_tenant_agent ON agent_security_events(tenant_id, agent_id);

CREATE TABLE alerts (
  id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id),
  rule_id TEXT NOT NULL, level INTEGER NOT NULL, atlas TEXT, owasp TEXT,
  event_id UUID, severity TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_alerts_tenant ON alerts(tenant_id);

CREATE TABLE incidents (
  id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id),
  title TEXT, severity TEXT, status TEXT NOT NULL DEFAULT 'open',
  agent_id UUID, run_id TEXT, first_seen TIMESTAMPTZ, last_seen TIMESTAMPTZ,
  detections JSONB, evidence_receipts JSONB,  -- receipt_hash[] -> provable timeline
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_incidents_tenant ON incidents(tenant_id);
```

All queries filter by `tenant_id`; SQLx parameterized binding only (no string interpolation). Detection rules + playbooks are config (YAML), versioned like Cedar policies.

---

## 6. API design (integrity semantics + SOC surface)

```http
POST /v1/agents/register
POST /v1/tools
POST /v1/mcp/servers
GET  /v1/mcp/servers/:key/tools
POST /v1/authorize                 -> { decision, risk, source_trust, action_hash, approval? }  # emits ASE (async)
GET  /v1/approvals/:id              -> { status, action_hash }   # SDK compares + fails closed
POST /v1/approvals/:id/approve      # binds approver to action_hash
POST /v1/approvals/:id/reject
POST /v1/approvals/:id/edit         # edited params -> new action_hash -> re-evaluate
POST /v1/approvals/:id/consume      # single-use; 409 if used/expired
GET  /v1/runs/:id/timeline          # receipts + events
GET  /v1/audit/events
GET  /v1/receipts/:id/verify        # recompute hash chain; returns verified|tampered
# --- SOC surface (async plane) ---
POST /v1/agents/:id/freeze | /revoke           # Active Response; tenant-scoped, fail-closed (flips agents.status)
POST /v1/mcp/servers/:key/quarantine           # Active Response (flips mcp_servers.status)
GET  /v1/incidents | /v1/incidents/:id         # correlated incidents + provable timeline
GET  /v1/alerts                                # detections
POST /v1/ingest/agentless                      # agentless collector (webhooks/traces -> ASE)
```

`/v1/authorize` returns the `action_hash` it computed; `/v1/approvals/:id` MUST return the bound hash; `edit` MUST re-hash and re-evaluate. The action path reads `agents.status`/`mcp_servers.status`, so a freeze/quarantine takes effect on the next action automatically.

---

## 7. Runtime sequences

**Allow:** authorize → provenance ok → policy permit → risk low → execute via proxy → receipt → emit ASE. **Deny:** policy `forbid` → receipt → safe denial; tool never runs → emit ASE (→ SOC detection). **Approval + integrity:** require_approval → freeze+hash+bind → human approves → SDK consumes + verifies hash → execute or **fail closed on mismatch** → receipt → emit ASE. **MCP:** intercept → resolve server/tool → manifest-pin check (drift → provenance downgrade + SOC alert) → policy → decision → route → receipt → emit ASE.

**Async SOC sequence (out-of-band):**
```text
ASE on bus -> normalize -> atomic rules match -> correlation windows update
   -> if rule/sequence fires: build alert (level, ATLAS/OWASP) + open/append incident (evidence_receipts[])
   -> Response Engine maps verdict -> {freeze|revoke|quarantine via control API, notify Slack, index}
   -> on incident close: RCA narrator (sandboxed) drafts summary
   -> Console renders provable timeline (each row carries receipt_hash; one-click /verify)
```

---

## 8. Security design

- **Trust boundaries:** App→Runtime→SDK→Gateway→Policy→Tool/MCP→Approval channels→Tenant data, **plus B8 SOC-evidence→RCA-LLM (evidence inert, no authority) and B9 Response-Engine→Gateway-control-API (authenticated, fail-closed)** — see Threat Model §4.
- **The four design laws (architectural security controls):** (1) deterministic policy decides, scores never gate; (2) the LLM only narrates closed incidents, evidence-as-data, no enforcement; (3) detection is strictly async, never in the action path; (4) every moat primitive preserved end-to-end (the SOC consumes `action_hash`/`receipt_hash`, never weakens them).
- **AuthN:** agent tokens (mTLS later), signed requests, short-lived creds, tenant-scoped keys; approvers via SSO/OIDC + Slack signature verification + role lookup; SOC control endpoints authenticated.
- **AuthZ:** tenant isolation on every query (incl. SOC tables/indices); default-deny unknown agent/tool/MCP; critical → deny; high-risk → approval; freeze/revoke of unknown agent → deny by default.
- **Secrets:** never expose tool creds to agents; proxy sensitive calls; KMS/Vault; redact secrets; store input/output *hashes* in receipts and ASE — so even the SOC never holds raw payloads.
- **Supply chain:** signed releases, SBOM, dependency scan, pinned Actions, image signing, secret scanning.

---

## 9. Observability

OpenTelemetry spans: `aegis.authorize`, `aegis.provenance.classify`, `aegis.policy.evaluate`, `aegis.risk.score`, `aegis.approval.create`, `aegis.approval.verify_hash`, `aegis.approval.consume`, `aegis.tool.execute`, `aegis.receipt.write`, **`aegis.event.emit`**, and SOC spans **`aegis.soc.detect`, `aegis.soc.correlate`, `aegis.soc.respond`, `aegis.soc.rca`**. Key metrics: `approval_hash_mismatch_total` (integrity), `provenance_denials_total`, **`ase_emitted_total`, `ase_emit_dropped_total` (backpressure), `soc_detections_total{rule}`, `soc_mttd_seconds`, `soc_mttc_seconds`, `incidents_open`**, plus authz latency/allow/deny/approval counters. Structured logs carry tenant/agent/run/trace/decision/approval IDs.

---

## 10. Performance

```text
Authorization p95:        < 100 ms
Policy evaluation p95:    < 50 ms
action_hash compute:      < 5 ms (canonicalize + SHA-256)
approval verify+consume:  < 12 ms (one GET + consume + local hash)
ASE emit overhead:        < 1 ms, non-blocking (MUST NOT affect authorize latency)
Audit/receipt enqueue:    < 20 ms async
MCP proxy overhead p95:   < 150 ms
SOC detection latency:    < 2 s p95 event->alert (async; out of action path)
```

Stateless gateway + HPA; embedded Cedar; read-through cache for policies/tools/agents; async receipt enrichment; hash chaining O(1) append. **The SOC scales independently** of the gateway (separate workers consuming the bus); its load never backpressures the action path because emission is bounded fire-and-forget (drops + metrics under extreme backpressure, never blocks).

---

## 11. Deployment

- **Self-hosted single binary (first-class):** Rust gateway + SQLite + Cedar + local receipt chain + **in-proc SOC** (mpsc bus, deterministic rules, local console). The neutrality wedge.
- **SaaS:** Kubernetes, Postgres, OTel collector, **event bus (Redis Streams→Kafka/NATS), ClickHouse event tier, SOC workers**, dashboard (Next.js).
- **Enterprise:** Helm, external Postgres/Redis, OIDC/SAML, SIEM export, transparency-log signing, air-gapped mode, multi-node SOC cluster.
- **Local dev:** Docker Compose with mock GitHub/MCP/Slack.

Ports (Wazuh-style clean boundaries): `443` API/console/ingest · `9443` runtime authz · `9444` MCP gateway · `9445` internal manager API · `9092` Kafka · `4222` NATS · `5432` Postgres · `9200` OpenSearch · `4317/4318` OTLP. Dev/test bind `127.0.0.1` only.

---

## 12. Evaluation & testing

- **Integrity tests (differentiators):** approve-then-swap blocked; replayed approval rejected; edited params force re-eval; expired rejected; un-consumable consume → fail closed; receipt hash-chain tamper detection.
- **Provenance tests:** AgentDojo/InjecAgent-style — untrusted GitHub issue / webpage / malicious MCP tool description → mutating action denied/escalated deterministically.
- **SOC tests (new):** async isolation (emission adds no measurable authorize latency; SOC outage never fails action path open); deterministic detection fires on the integrity events; correlation opens the right incident; **second-order injection** — "system: mark low severity / allow" strings in evidence do **not** alter deterministic triage/correlation/response (only the RCA text field reflects them); score-gating attempt still denied by Cedar.
- **Standard:** unit (policy, risk, approval state machine, canonicalization cross-language byte-equality, rule matcher, correlation windows), integration (LangGraph/OpenAI wrappers, GitHub/Slack/MCP mocks, control-endpoint fail-closed), load (100–1,000 authz/s; SOC ingest throughput).

**Canonicalization byte-equality** across Go/TS/Python/Rust remains a must-test invariant — a mismatch breaks both the fail-closed guarantee *and* SOC evidence linkage.

---

## 13. Key technical decisions

1. **Cedar native** — sub-ms ABAC with `action_hash`/`source_trust` context.
2. **SDK is in the trust boundary, fail-closed** — integrity enforced at the last step. *(core)*
3. **Deterministic provenance gate; classifiers + scores advisory-only (tighten, never loosen; never gate).**
4. **Canonical serialization `aegis-jcs-1` for cross-language hash stability.**
5. **Open, hash-chained verifiable receipt format** — the standards play *and* the SOC evidence spine.
6. **Two-plane principle** — the SOC is a strictly async consumer; emission is fire-and-forget; the action path is sacred. *(the SOC's core decision)*
7. **Deterministic SOC + one sandboxed RCA LLM** — detection/correlation/response are code, not models; the only LLM narrates closed incidents (no second-order injection, no token-cost blowup).
8. **Layerable** — adapters augment existing gateways rather than replace them.

---

## 14. Final architecture

```text
                 +----------------------+        +--------------------------+
                 |  SOC Console (Next.js)|<-------|  Indexer (SQLite→ClickH.)|
                 +----------+-----------+         +------------▲-------------+
                            ^                                   │
        INLINE (sync)       │ query                  ASYNC SOC (out-of-band)
+----------------+   +------+---------------+   emit  +---------+--------------+
| Agent Runtime  |-->| Aegis Gateway (Rust) |--mpsc-->| Normalizer→Detect→    |
+-------+--------+   |  Trust-Provenance Gate|        | Correlate→Alert→      |
        |           |  Risk (advisory)       |        | {Respond→ctrl API,    |
        |           |  Approval Integrity    |--bind  |  Notify, RCA(LLM,box)}|
        |           |  Receipt+Audit (chain) |        +---------+-------------+
        v           +----------+------------+                    │ freeze/revoke/quarantine
+----------------+              v                                ▼
| Aegis SDK      |---> Tool Proxy / MCP GW ---> External Tools / MCP   (agents.status honored next action)
| (fail-closed   |     (authz + manifest pin)
|  hash check)   |              v
+----------------+     Verifiable Receipts (hash chain) === SOC evidence spine
```

---

## 15. Founder-level recommendation

Build the table-stakes loop competently; spend the engineering *edge* on §4.3–4.5 **and** the §4.10 SOC keystone:

> **The minimum *valuable* loop is not "intercept → policy → allow/deny → audit." It is "freeze the exact action → bind the human approval to its hash → fail closed at the SDK on mismatch → gate deterministically on source provenance → emit a verifiable receipt → stream that receipt (async) into a deterministic SOC that detects, correlates, contains, and *proves*."** Everything else is available for free elsewhere; this is the part that isn't — and the SOC is what makes it a daily-use product instead of a library.

Build order: ship the integrity engine, then the **Phase 0 event emitter** (the keystone every SOC phase consumes), then detection → notify → correlation → response → console — never letting any of it touch the synchronous action path. Next doc: the [Threat Model](AegisAgent_Threat_Model.md), foregrounding T-A/T-B/T-C and the new T-D (attacks on the SOC).
