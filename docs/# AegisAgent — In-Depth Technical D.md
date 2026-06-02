# AegisAgent — In-Depth Technical Design (June 2026 reset)

**Product:** AegisAgent
**Category:** Agent Action Integrity (integrity + provenance layer for agent actions)
**Version:** v0.2 (re-anchored)
**Date:** 2026-06-02
**Founder:** Lavkush Kumar
**Read first:** [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md)

> ⚠️ **Reset note.** v0.1 designed a generic "Agent Action Firewall" (intercept → policy → allow/deny → approval → audit). That loop is now commodity (free Microsoft toolkit + OSS + SaaS), so it is **table stakes** here, not the design's reason to exist. This version preserves the still-valid architecture and elevates three components to the center: **(§4.3) Approval Integrity Engine**, **(§4.4) Trust-Provenance Gate**, and **(§4.5) Verifiable Action Receipts** — the parts competitors decide but don't *prove*.

---

## 0. Research foundation

Patterns drawn from: Cedar (Rust-native ABAC engine), OpenTelemetry (vendor-neutral telemetry), LangGraph / OpenAI Agents SDK human-in-the-loop (pause/resume on tool calls), AgentDojo & InjecAgent (tool-use injection benchmarks), and the June-2026 competitor field (Microsoft Agent Governance Toolkit, Pipelock, MintMCP, Operant). RFC 8785 (JSON Canonicalization Scheme) and Sigstore/transparency-log patterns inform the integrity primitives.

---

## 1. Technical thesis

> **AegisAgent is the enforcement point that makes an agent-action decision *provable*: the human-approved action is the executed action (bound by hash, enforced fail-closed at the SDK), and the authorization decision is gated on the deterministic trust level of the content that triggered it.**

The baseline gateway answers "is it allowed?" The defensible engineering answers two harder questions:
1. **Integrity:** can we cryptographically prove the executed action == the approved action?
2. **Provenance:** can an untrusted source ever drive a privileged action? (Deterministically — not via a text classifier.)

---

## 2. System overview

```text
User / Application
        v
AI Agent Runtime (LangGraph / OpenAI Agents SDK / CrewAI / AutoGen / custom)
        v
AegisAgent SDK (Python / TS / Go)  ── canonicalizes action, enforces FAIL-CLOSED on hash mismatch
        v
AegisAgent Gateway (Rust + Axum + Tokio)        [standalone OR layered on an existing gateway]
   ┌─────────────────────┬─────────────────────────┐
   │ Identity Resolver    │ Trust-Provenance Gate    │  (deterministic 6-level source labels)
   │ Policy Engine (Cedar)│ Risk Engine              │
   │ Approval Integrity   │ Receipt + Audit Writer   │  (freeze→hash→bind→fail-closed; verifiable receipts)
   │ MCP Gateway          │ Tool Proxy               │
   └─────────────────────┴─────────────────────────┘
        v
External Tools / MCP Servers (GitHub / Slack / AWS / DB / Stripe / K8s / filesystem)
```

Decision and enforcement are separated (Cedar model). The crucial addition: **the SDK is inside the trust boundary** and performs the final fail-closed check, because a compromised agent process must not be able to execute an unapproved action even if it reaches the gateway's approval.

---

## 3. Scope

**MVP:** protect a coding agent on GitHub + Slack + one MCP server, *with provable integrity*. Headline components below (§4.3–4.5) are the differentiators; the rest (registry, policy, risk, MCP gateway, audit) are table stakes built to a solid standard.

**Out of scope:** full SIEM/DLP/CNAPP, model scanning, GRC automation, identity lifecycle, automatic remediation.

---

## 4. Component design

### 4.1 AegisAgent SDK (Python/TS/Go)

Responsibilities: register agent metadata; wrap tool functions; **compute the canonical action and `action_hash`**; send `/v1/authorize`; pause on `require_approval`; **before executing, re-fetch the approval and refuse to run unless the about-to-execute `action_hash` == the approved `action_hash`**; attach provenance labels; emit OTel spans.

```python
from aegisagent import AegisClient, protect_tool

aegis = AegisClient(api_key="aegis_xxx", agent_id="coding-agent-prod", environment="production")

@protect_tool(client=aegis, tool="github", action="merge_pull_request", risk="high")
def merge_pull_request(repo: str, pr_number: int, branch: str):
    # The decorator canonicalizes {tool, action, resource, parameters}, computes action_hash,
    # authorizes, and (if approved) verifies the approved hash == this call's hash before running.
    return github.merge_pull_request(repo=repo, pr_number=pr_number, branch=branch)
```

**Fail-closed contract (normative):** the SDK MUST NOT execute if (a) the gateway is unreachable for a mutating/high-risk action, (b) the approval status is not `approved`, (c) the approved `action_hash` ≠ the recomputed hash, or (d) the approval is expired/replayed.

### 4.2 Runtime Gateway (Rust + Axum)

Authenticates SDK requests; resolves tenant/agent/user/session; normalizes the tool call; invokes Trust-Provenance Gate → Policy Engine → Risk Engine; creates approvals; writes receipts/audit; returns decision. Stateless, horizontally scalable. SQLite (MVP) → Postgres (scale) via SQLx (WAL, busy-timeout). Embedded Cedar for sub-ms decisions.

### 4.3 Approval Integrity Engine — **headline**

**Goal:** an approval is valid for exactly one action — the one that was shown to the human — and nothing else.

**Canonical action.** The action is `{tool, action, resource, mutates_state, parameters}` serialized with a deterministic scheme so the Python/TS/Go SDKs and the Rust gateway all produce identical bytes. `action_hash = SHA-256(canonical_action)`.

> **Implemented (scheme `aegis-jcs-1`):** keys sorted by Unicode code point, compact separators, **raw UTF-8 (no `\uXXXX` escaping)**, `null` for absent resource. Locked by a shared corpus at [`tests/canonical_action_vectors.json`](../tests/canonical_action_vectors.json) that both a Python test (`sdk-python/tests/test_canonical_action.py`) and a Rust test (`gateway/src/routes.rs::canonical_action_matches_shared_corpus`) assert against — byte-equality across languages is guaranteed transitively. This closed a real divergence: the SDK previously used Python's default `ensure_ascii=True`, escaping non-ASCII and mismatching the gateway's raw UTF-8 → fail-closed on any legitimate non-ASCII action. Full RFC 8785 number-formatting compliance (float edge cases) is a follow-up; current vectors cover strings/unicode/int/bool/null/nested.

**Binding.** When policy returns `require_approval`, the gateway persists an approval row bound to `action_hash`, the canonical action, approver group, and an expiry. The Slack/dashboard card renders the canonical action so the human approves *that*.

**Edit = new action.** An edited parameter set yields a new canonical action → new `action_hash` → mandatory re-evaluation (a fresh decision, possibly a fresh approval). An old approval never covers edited bytes.

**Fail-closed enforcement.** `GET /v1/approvals/:id` returns the bound `action_hash`. The SDK recomputes the hash of the action it is about to execute and refuses on mismatch. Approvals are single-use, expiring, and replay-checked (nonce + `decided_at` + `expires_at`).

> **Implementation status (2026-06-02).** *Done & verified (Python):* `action_hash` binding on approvals; SDK fails closed on hash mismatch and on expiry — it refuses to execute an approval whose `expires_at` has passed even if `APPROVED` with a matching hash (`sdk-python/tests/test_approval_expiry.py`, `test_sdk.py`; 11/11). *Done, pending `cargo` verification (Rust gateway):* **gateway-side expiry enforcement** as defense-in-depth — `get_approval` reports `EXPIRED` for a pending past-window approval, and `approve_approval` returns `409` for an expired or already-decided approval (`approval_is_expired`; tests `approval_is_expired_detects_past_window`, `expired_approval_is_reported_and_cannot_be_approved`). *Pending:* **single-use `nonce`** column + consume-on-use to fully close replay (T-A3); **verifiable hash-chained receipts** (T-C).

**Threats closed:** approve-then-swap, parameter tampering post-approval, replay/reuse, render-vs-bytes mismatch (OWASP "approval manipulation").

```text
Sequence:
  authorize -> require_approval -> persist {action_hash, canonical_action, expiry, nonce}
  human approves (sees canonical_action) -> approval bound to action_hash
  SDK pre-exec: recompute hash(about_to_run) == approved action_hash ? execute : FAIL CLOSED + tamper-attempt receipt
```

### 4.4 Trust-Provenance Gate — **headline**

**Goal:** make "where did the triggering content come from" a deterministic, first-class authorization input — not a probabilistic text score.

**Six levels:** `trusted_internal_signed`, `trusted_internal_unsigned`, `semi_trusted_customer`, `untrusted_external`, `malicious_suspected`, `unknown`.

**Propagation.** A run carries the lowest trust level of any content it consumed (e.g., reading an external GitHub issue stamps the run `untrusted_external`). The label is a Cedar context attribute (`context.source_trust` / `principal.source_trust`).

**Determinism rule (normative):** classifiers (regex/LLM/LlamaFirewall-style) may only *lower* trust (tighten), never *raise* it. A deterministic `forbid` for `mutates_state && untrusted_external` cannot be overridden by a "looks benign" score.

```cedar
// Deterministic: deny mutating actions triggered by untrusted/suspected sources
forbid (principal, action == Action::"tool_call", resource)
when {
    resource.mutates_state == true &&
    (context.source_trust == "untrusted_external" || context.source_trust == "malicious_suspected")
};

// Escalate to approval for unknown/customer provenance on mutating actions
@decision("require_approval")
@approver_group("security-reviewers")
permit (principal, action == Action::"tool_call", resource)
when {
    resource.mutates_state == true &&
    (context.source_trust == "semi_trusted_customer" || context.source_trust == "unknown")
};
```

**MCP manifest drift** feeds this gate: a tool whose manifest hash ≠ the pinned hash is treated as reduced provenance (`unknown`/`malicious_suspected`).

### 4.5 Verifiable Action Receipts — **headline**

**Goal:** every protected action yields tamper-evident, independently verifiable evidence suitable for SOC 2 / EU AI Act Article 14.

**Receipt fields:** `event_id, tenant_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, risk, decision, matched_policy_ids, approver, action_hash, input_hash, output_hash, prev_receipt_hash, receipt_hash`.

**Tamper evidence.** Receipts form a per-tenant hash chain (`receipt_hash = SHA-256(receipt_body || prev_receipt_hash)`); optional Sigstore-style transparency-log / signing in enterprise mode. The format is **open and documented** (the standards play — see Vision §7 Phase 2). Exportable via OTel/webhook to SIEM.

```json
{
  "event_id": "rcpt_01JABC",
  "ts": "2026-06-02T12:00:00Z",
  "agent_id": "coding-agent-prod",
  "user_id": "lavkush",
  "tool": "github", "action": "merge_pull_request", "resource": "payments-service#482",
  "source_trust": "untrusted_external",
  "decision": "require_approval -> rejected_on_swap",
  "approver": "platform-lead",
  "action_hash": "sha256:9af1...",   "executed_hash": "sha256:1c20...",
  "result": "blocked_hash_mismatch",
  "prev_receipt_hash": "sha256:77ab...", "receipt_hash": "sha256:b3e9..."
}
```

### 4.6 Policy Engine (Cedar) — table stakes
Native Cedar; `action_hash` and `source_trust` are first-class context. `@decision("require_approval")` annotation yields the third decision state. OPA/Rego adapter optional later.

### 4.7 Risk Engine — table stakes
Enriches/routes (does not override `forbid`). Inputs: action risk, environment, resource sensitivity, `source_trust` penalty, MCP trust penalty, reversibility/blast radius, approval history. Routes score → allow / allow+log / require_approval / require_approval+notify / deny.

### 4.8 MCP Gateway — table stakes
Register/discover/approve/disable tools; pin + hash manifests; drift detection → provenance signal; deny unknown tools; authorize every MCP tool call; session-aware routing; audit.

### 4.9 Layer-on adapters
Run AegisAgent in front of (or as a callout from) an existing gateway (Microsoft toolkit, MintMCP, Pipelock): the existing gateway does discovery/routing/baseline policy; AegisAgent adds the integrity engine + provenance gate + receipts. Distribution by complementarity, not displacement.

---

## 5. Data model (SQLite MVP → Postgres scale; all tenant-scoped)

Core tables (unchanged, tenant-isolated, parameterized): `tenants, users, agents, tools, tool_actions, mcp_servers, mcp_tools, policies, decisions, approvals, audit_events, context_labels`. **Integrity-relevant columns:**

```sql
-- approvals: bind to the frozen action
ALTER TABLE approvals ADD COLUMN action_hash TEXT NOT NULL;        -- SHA-256 of canonical action
ALTER TABLE approvals ADD COLUMN canonical_action JSONB NOT NULL;  -- exact bytes shown to approver
ALTER TABLE approvals ADD COLUMN nonce TEXT NOT NULL;              -- single-use / replay defense
ALTER TABLE approvals ADD COLUMN expires_at TIMESTAMPTZ;

-- action_receipts: verifiable, hash-chained evidence
CREATE TABLE action_receipts (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  decision_id UUID REFERENCES decisions(id),
  agent_id UUID, user_id TEXT, run_id TEXT, trace_id TEXT,
  tool TEXT, action TEXT, resource TEXT,
  source_trust TEXT NOT NULL,
  decision TEXT NOT NULL, approver TEXT,
  action_hash TEXT, executed_hash TEXT, input_hash TEXT, output_hash TEXT,
  prev_receipt_hash TEXT, receipt_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_action_receipts_tenant ON action_receipts(tenant_id);
```

All queries filter by `tenant_id`; SQLx parameterized binding only (no string interpolation).

---

## 6. API design (surface unchanged; integrity semantics normative)

```http
POST /v1/agents/register
POST /v1/tools
POST /v1/mcp/servers
GET  /v1/mcp/servers/:key/tools
POST /v1/authorize                 -> { decision, risk, source_trust, action_hash, approval? }
GET  /v1/approvals/:id              -> { status, action_hash }   # SDK compares + fails closed
POST /v1/approvals/:id/approve      # binds approver to action_hash
POST /v1/approvals/:id/reject
POST /v1/approvals/:id/edit         # edited params -> new action_hash -> re-evaluate
GET  /v1/runs/:id/timeline          # receipts + events
GET  /v1/audit/events
GET  /v1/receipts/:id/verify        # recompute hash chain; returns verified|tampered
```

`/v1/authorize` returns the `action_hash` it computed; `/v1/approvals/:id` MUST return the bound hash; `edit` MUST re-hash and re-evaluate.

---

## 7. Runtime sequences

**Allow:** authorize → provenance ok → policy permit → risk low → execute via proxy → receipt. **Deny:** policy `forbid` (e.g., mutating + untrusted) → receipt → safe denial; tool never runs. **Approval + integrity:** require_approval → freeze+hash+bind → human approves → SDK verifies hash → execute or **fail closed on mismatch** → receipt. **MCP:** intercept → resolve server/tool → manifest-pin check (drift → provenance downgrade) → policy → decision → route → receipt.

---

## 8. Security design

- **Trust boundaries:** App→Runtime→SDK→Gateway→Policy→Tool/MCP→Approval channels→Tenant data. The SDK and the `action_hash` check are explicitly in-boundary.
- **AuthN:** agent tokens (mTLS later), signed requests, short-lived creds, tenant-scoped keys; approvers via SSO/OIDC + Slack signature verification + approver role lookup.
- **AuthZ:** tenant isolation on every query; default-deny unknown agent/tool/MCP server/MCP tool; critical → deny; high-risk → approval.
- **Approval-callback integrity:** verify Slack/Teams/dashboard signatures; bind approver identity + role to the `action_hash`.
- **Secrets:** never expose tool credentials to agents; proxy sensitive calls; KMS/Vault; redact secrets; hash inputs/outputs in receipts.
- **Supply chain:** signed releases, SBOM, dependency scan, pinned Actions, image signing, secret scanning.

---

## 9. Observability

OpenTelemetry spans: `aegis.authorize`, `aegis.provenance.classify`, `aegis.policy.evaluate`, `aegis.risk.score`, `aegis.approval.create`, `aegis.approval.verify_hash`, `aegis.tool.execute`, `aegis.receipt.write`. Metrics include `approval_hash_mismatch_total` (the key integrity metric), `provenance_denials_total`, plus authz latency / allow / deny / approval counters. Structured logs carry tenant/agent/run/trace/decision/approval IDs.

---

## 10. Performance

```text
Authorization p95:        < 100 ms
Policy evaluation p95:    < 50 ms
action_hash compute:      < 5 ms (canonicalize + SHA-256)
approval verify (SDK):    < 10 ms (one GET + local hash)
Audit/receipt enqueue:    < 20 ms async
MCP proxy overhead p95:   < 150 ms
```

Stateless gateway + HPA; embedded Cedar; read-through cache for policies/tools/agents; async receipt enrichment; hash chaining is O(1) append.

---

## 11. Deployment

- **Self-hosted single binary (first-class):** Rust gateway + SQLite + Cedar + local receipt chain. The neutrality wedge — runs inside the customer trust boundary.
- **SaaS:** Kubernetes, Postgres, OTel collector, dashboard (Next.js).
- **Enterprise:** Helm, external Postgres/Redis, OIDC/SAML, SIEM export, transparency-log signing, air-gapped mode.
- **Local dev:** Docker Compose with mock GitHub/MCP/Slack.

---

## 12. Evaluation & testing

- **Integrity tests (the differentiators):** approve-then-swap blocked; replayed approval rejected; edited params force re-eval; expired approval rejected; receipt hash-chain tamper detection.
- **Provenance tests:** AgentDojo/InjecAgent-style — untrusted GitHub issue / webpage / malicious MCP tool description → mutating action is denied/escalated deterministically.
- **Standard:** unit (policy, risk, approval state machine, canonicalization cross-language byte-equality), integration (LangGraph/OpenAI wrappers, GitHub/Slack/MCP mocks), load (100–1,000 authz/s).

**Canonicalization byte-equality** across Python/TS/Go/Rust is a must-test invariant — a mismatch there would break the fail-closed guarantee.

---

## 13. Key technical decisions

1. **Cedar native** — sub-ms ABAC with `action_hash`/`source_trust` context. (table stakes, but right)
2. **SDK is in the trust boundary, fail-closed** — integrity is enforced at the last step, not merely decided upstream. *(the core decision)*
3. **Deterministic provenance gate; classifiers advisory-only (tighten, never loosen).**
4. **Canonical serialization (RFC 8785) for cross-language hash stability.**
5. **Open, hash-chained verifiable receipt format** — the standards play.
6. **Layerable** — adapters to augment existing gateways rather than replace them.

---

## 14. Final architecture

```text
                 +----------------------+
                 |  Dashboard (Next.js) |
                 +----------+-----------+
                            v
+----------------+   +----------------------+   +------------------+
| Agent Runtime  |-->| Aegis Gateway (Rust) |-->| Policy (Cedar)   |
+-------+--------+   |  Trust-Provenance Gate|   +------------------+
        |           |  Risk Engine          |
        |           |  Approval Integrity    |--(freeze->hash->bind->verify)
        |           |  Receipt + Audit       |
        v           +----------+------------+
+----------------+              v
| Aegis SDK      |---> Tool Proxy / MCP GW ---> External Tools / MCP
| (fail-closed   |     (authz + manifest pin)
|  hash check)   |
+----------------+              v
                     Verifiable Receipts (hash chain / OTel export)
```

---

## 15. Founder-level recommendation

Build the table-stakes loop competently, but spend the engineering *edge* on §4.3–4.5:

> **The minimum *valuable* loop is not "intercept → policy → allow/deny → audit." It is "freeze the exact action → bind the human approval to its hash → fail closed at the SDK on mismatch → gate deterministically on source provenance → emit a verifiable receipt."** Everything else is available for free elsewhere; this is the part that isn't.

Next doc: the [Threat Model](AegisAgent_Threat_Model.md), foregrounding approve-then-swap, replay, render-vs-bytes, confused-deputy-via-provenance, and receipt tampering.
