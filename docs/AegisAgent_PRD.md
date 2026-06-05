# AegisAgent — Product Requirements Document (June 2026 reset)

**Product:** AegisAgent
**Category:** Agent Action Integrity → Integrity-anchored Agent SOC
**Version:** v0.3 (re-anchored on the integrity-anchored Agent SOC)
**Date:** 2026-06-05
**Owner:** Lavkush Kumar
**Read first:** [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md) · **Architecture:** [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md)

> ⚠️ **Reset note (two layers).** v0.1 specified an "Agent Action Firewall" (inventory + action-level authz + approval + audit). By June 2026 that loop is commodity (free Microsoft toolkit + OSS + SaaS). v0.2 re-prioritized the two defensible differentiators to headline status: (1) frozen-action approval integrity with a fail-closed SDK, (2) deterministic trust-provenance gating — plus verifiable action receipts. **v0.3 adds the product surface those primitives are delivered through: an integrity-anchored Agent SOC** (async detect → correlate → alert → respond, riding the receipt/provenance spine). The MVP is still the integrity engine; the SOC is the phased headline surface (see §6.4). The four design laws (§13.2) keep the SOC from drifting into a commodity SIEM.

---

## 1. Executive summary

AegisAgent is the **integrity layer for AI agent actions**, delivered as an **integrity-anchored Agent SOC.** It sits at the tool-call boundary (standalone or layered onto an existing gateway) and guarantees two things competitors decide but don't *prove*:

1. **The human-approved action is the action that executes** — the exact action is frozen, SHA-256 hashed, and the approval is bound to that hash; the SDK fails closed on any mismatch (defends approve-then-swap, replay, render-vs-bytes — OWASP "approval manipulation").
2. **Untrusted-origin content cannot drive a privileged action** — a deterministic 6-level source-trust label is a first-class policy input (defends the confused-deputy / indirect-prompt-injection path — AgentDojo, InjecAgent).

Every protected action emits a **verifiable, hash-chained action receipt** suitable as SOC 2 / EU AI Act Article 14 evidence — and that receipt stream feeds a **SOC** that detects, correlates, alerts, and contains, with every alert backed by tamper-evident evidence. The product is **open, self-hostable, and framework-neutral.**

Market context: developers adopt AI agents heavily but distrust output (Stack Overflow 2026: ~84% use, ~29% trust); GitHub workflows are now agentic; NSA MCP guidance (May 2026) warns of dynamic-invocation risk. The baseline gateway market answered "decide"; AegisAgent answers "prove" — and "operate a SOC on that proof."

---

## 2. Product vision

> **Make the approval trustworthy. Trust the source, not the text. Run the SOC on the proof.**

AI risk moved from text → action; in 2026 it moved again from "can we decide?" → "can we prove the decision held, and operate on that proof?" AegisAgent makes every high-risk action *provably* the approved one, from a known source, with exportable evidence — and turns that evidence into a SOC.

---

## 3. Problem statement

> **A market of gateways can now allow/deny/approve agent actions, but the approval is not cryptographically bound to the executed action, authorization is blind to the trigger's source trust, and no SOC detects or responds to agent threats on provable evidence. Teams operate under controls that can be silently bypassed (approve-then-swap, replay, confused deputy), incidents that are never correlated, and no way to prove human oversight to auditors.**

See [`AegisAgent_Problem_Definition.md`](AegisAgent_Problem_Definition.md) for full treatment. This PRD specifies the product that closes that integrity gap and operates the SOC on it.

---

## 4. Goals and non-goals

### 4.1 Goals
1. **Guarantee approval integrity** — approved action == executed action, enforced at the SDK, provable after the fact.
2. **Gate on provenance deterministically** — source-trust as a Cedar input; untrusted origin cannot drive mutating actions without escalation.
3. **Emit verifiable evidence** — open, hash-chained action-receipt format, exportable; maps to Article 14 / SOC 2.
4. **Operate an integrity-anchored SOC** — async detection, correlation, alerting, and Active-Response on the receipt/provenance stream; deterministic detection; one sandboxed LLM for RCA only.
5. **Be neutral and layerable** — self-hostable single binary; runs standalone or in front of an existing gateway.
6. **Keep the baseline at table-stakes quality** — inventory, action-level authz, MCP governance, audit, developer DX.

### 4.2 Non-goals (MVP)
A **generic** SIEM, full DLP, network egress firewall, model scanning, GRC suite, generic chatbot moderation, identity lifecycle management, "agentic" LLM remediation that reasons over attacker content. AegisAgent integrates with these; it is not them. **Clarification:** we *do* build a SOC — an **integrity-anchored** one whose detections ride verifiable evidence and deterministic provenance. We do **not** ingest arbitrary logs or score text to decide.

---

## 5. Target users and personas

| Persona | Core need (integrity-anchored) |
|---|---|
| **AI / agent engineer** | SDK that fails closed automatically; readable Cedar policies; local dry-run; clear deny reasons |
| **Platform / DevOps** | Self-hostable gateway; GitHub/Slack/MCP integration; metrics; reliability; a freeze switch |
| **Security engineer** | Provable approvals; deterministic provenance gating; default-deny; secure defaults |
| **SOC analyst** | Live decision feed; provenance-aware detections; **provable** incident timelines; real-time containment |
| **Compliance / auditor** | Verifiable action receipts; approval chain-of-custody; provable incident record; Article 14 / SOC 2 export |
| **Economic buyer (CTO/VP Eng/CISO)** | Prove safe agent rollout to customers and regulators; monitor and contain the fleet |

---

## 6. MVP scope

### 6.1 Theme

# Protect a coding agent on GitHub + Slack + MCP — with provable integrity, then watch it in the SOC

The MVP must prove this loop end-to-end:

```text
Agent proposes action
→ AegisAgent classifies trigger source trust (deterministic)
→ Cedar policy evaluates (source_trust + action risk + resource)
→ if approval needed: freeze EXACT action → SHA-256 → bind approval to hash
→ SDK executes ONLY if about-to-run hash == approved hash, else FAIL CLOSED
→ verifiable, hash-chained action receipt + audit timeline written
→ (async, non-blocking) the decision is emitted as an Agent Security Event into the SOC
```

### 6.2 Headline features (the differentiators)

#### Feature H1 — Approval Integrity Engine
- Canonical serialization of the tool call → `action_hash = SHA-256(canonical_action)` (scheme `aegis-jcs-1`).
- Approval record binds `action_hash` + approver + decision + timestamp; **single-use** (atomic consume).
- Editing parameters yields a new hash and forces re-evaluation.
- SDK **fails closed** if the hash it is about to execute ≠ approved hash; rejects expired/replayed/un-consumable approvals.

**Acceptance:**
```text
Given an approval was granted for action A (hash Ha),
when the agent attempts to execute action B (hash Hb != Ha) under that approval,
then the SDK refuses to execute and writes a tamper-attempt audit event + SOC detection.
```

#### Feature H2 — Trust-Provenance Gate
- Six deterministic source-trust levels as a first-class Cedar context input.
- Mutating action + `untrusted_external`/`malicious_suspected` → deny or escalate, regardless of text.
- Optional classifier may tighten but never loosen a deterministic rule.

**Acceptance:**
```text
Given an agent read a GitHub issue from an external contributor (untrusted_external),
when it later attempts a mutating action in the same run,
then AegisAgent denies or requires approval based on provenance, not on text sentiment,
and the SOC raises a confused-deputy detection.
```

#### Feature H3 — Verifiable Action Receipts
- Open, documented, **hash-chained** receipt: agent, user, tool, action, resource, `source_trust`, risk, decision, approver, `action_hash`, `prev_receipt_hash`, `receipt_hash`, timestamp.
- Exportable via OpenTelemetry/webhook; designed as Article 14 / SOC 2 evidence; the SOC's cold evidence tier.

**Acceptance:**
```text
Given any protected action completes (allow/deny/approved),
when an auditor exports the receipt,
then it cryptographically links approver -> action_hash -> source_trust -> result,
and chains to the previous receipt (tamper-evident).
```

### 6.3 Table-stakes features (required, not differentiating)

- **Agent registry** — identity, owner, environment, risk tier, status (active/disabled/frozen/quarantined), token issuance.
- **Tool action registry** — per-action risk + mutation flag (GitHub first).
- **Runtime authorization API** — `allow | deny | require_approval | log_only | quarantine`, with reason + matched policy IDs; default-deny unknowns.
- **Cedar policy engine** — with `action_hash` and `source_trust` as native context.
- **Slack approval workflow** — signature-verified callbacks, approver role lookup, approve/reject/edit/escalate.
- **MCP Gateway Lite** — register/discover/approve/disable tools, manifest hashing + drift detection (drift → provenance escalation), deny unknown tools, log calls.
- **Audit timeline** — event chain linked by run/trace ID.

### 6.4 SOC surface (phased headline — see [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md) §27)

The SOC is built in phases on top of the integrity engine; **Phase 0 is the MVP keystone** (everything else consumes it):

| Phase | Deliverable | Headline value |
|---|---|---|
| **0 (MVP)** | Non-blocking event emitter in `/v1/authorize` → Agent Security Event stream | enables the entire SOC without touching the <75 ms path |
| 1 | Deterministic atomic detection rules (confused-deputy, drift) | first detections, all provenance-anchored |
| 2 | Notify sink (Slack/webhook) on deny + approval | L1 automation; instant visibility |
| 3 | Correlation engine (freq/sequence/window) + incidents | provable, correlated incident timelines |
| 4 | Active-Response control API (freeze/revoke/quarantine) | real-time containment |
| 5 | Event indexer (ClickHouse) + SOC Console | the dashboard |
| 6 | RCA narrator (sandboxed LLM, post-incident only) | human-readable RCAs |

**SOC feature S1 — Provable incident timeline:** every incident references the `receipt_hash` chain covering its events; one-click `/verify` proves the timeline is untampered.

**Acceptance:**
```text
Given a correlated incident (untrusted issue -> sensitive read -> external write),
when an analyst opens its timeline and clicks verify,
then each row's receipt_hash chains cleanly and the timeline is proven tamper-free.
```

---

## 7. Functional requirements

(Agent / tool / MCP management, authorization, approval workflow, audit, context trust — as in v0.1, retained.) Key additions/changes:

- **Approval workflow MUST** bind every approval to `action_hash`, support expiry, re-evaluate edits, be **single-use** (atomic consume), and the **SDK MUST fail closed** on hash mismatch / replay / expiry.
- **Context trust MUST** be deterministic and policy-visible; classifiers are advisory only and may not downgrade a label.
- **Receipts MUST** be emitted for every protected action in the open format and be independently verifiable (hash chain).
- **The authorize handler MUST** emit an Agent Security Event asynchronously (non-blocking) after deciding; emission failure MUST NOT add latency to or block the decision (the SOC degrades, the action path does not).
- **Detection MUST** be deterministic (rule-based); risk/anomaly scores are advisory metadata and **MUST NOT** gate authorization.
- **Any LLM in the SOC MUST** be limited to summarizing already-closed, already-evidenced incidents, sandboxed, with evidence passed as inert data and no tool/enforcement authority.
- **Active-Response control endpoints MUST** be tenant-scoped, parameterized, and fail-closed (freezing/revoking an unknown agent denies by default).
- **Deployment MUST** support a fully self-hosted single-binary mode with local-only receipt storage.

---

## 8. Non-functional requirements

```text
Authorization API p95 latency:  < 150 ms
Policy evaluation p95 latency:  < 75 ms
action_hash compute overhead:   < 5 ms (canonical serialize + SHA-256)
Event emission overhead:        < 1 ms, non-blocking (MUST NOT affect authorize latency)
Slack approval creation p95:    < 5 s
Audit/receipt enqueue success:  99.9%
MCP proxy overhead p95:         < 250 ms
SOC detection latency (async):  < 2 s p95 from event to alert (out-of-band; not in action path)

Fail-closed: high-risk actions fail closed if policy/audit/approval is unavailable
             SDK fails closed on any hash mismatch, replay, or unreachable gateway (configurable for read-only)
             SOC degradation NEVER fails the action path open (async by construction)
Security defaults: unknown agent/tool/MCP server/MCP tool -> deny; critical -> deny;
                   high-risk -> require approval; approval callbacks signature-verified;
                   secrets redacted; tenant data isolated by tenant_id; scores never gate
```

---

## 9. API requirements (integrity semantics + SOC surface)

```http
POST /v1/agents                                  # register agent
POST /v1/tools                                   # register tool + actions
POST /v1/mcp/servers                             # register MCP server
GET  /v1/mcp/servers/:key/tools                  # manifest
POST /v1/authorize                               # returns decision + action_hash + source_trust; emits ASE (async)
GET  /v1/approvals/:id                            # returns status + bound action_hash (SDK verifies)
POST /v1/approvals/:id/approve|reject|edit        # approve binds to action_hash; edit re-hashes + re-evaluates
POST /v1/approvals/:id/consume                    # single-use; 409 if used/expired
GET  /v1/runs/:id/timeline                        # receipts + events
GET  /v1/audit/events
GET  /v1/receipts/:id/verify                      # recomputes receipt hash; returns verified
# --- SOC surface (phased) ---
POST /v1/agents/:id/freeze | /revoke              # Active Response; tenant-scoped, fail-closed
POST /v1/mcp/servers/:key/quarantine              # Active Response
GET  /v1/incidents | /v1/incidents/:id            # correlated incidents + provable timelines
GET  /v1/alerts                                   # detections
POST /v1/ingest/agentless                         # agentless collector (webhooks/traces -> ASE)
```

The `GET /v1/approvals/:id` response **MUST** include the bound `action_hash`; the SDK **MUST** compare it to the action it is about to execute and fail closed on mismatch.

---

## 10. Data requirements

Core entities: `tenant, user, agent, tool, tool_action, mcp_server, mcp_tool, policy, decision, approval (incl. action_hash, consumed_at), audit_event, context_label, action_receipt (hash-chained)`. **SOC entities:** `agent_security_event (ASE), alert, incident (with evidence_receipts[]), detection_rule, playbook`. Retention tiers: OSS local-only → Team 7–30d → Startup 90d → Growth 1y → Enterprise custom. Event-analytics tier (ClickHouse) added when aggregation volume warrants; receipt ledger is cold/immutable.

---

## 11. Success metrics

- **Integrity:** # approve-then-swap / replay attempts blocked by hash mismatch; % protected actions with a verifiable receipt; # untrusted-provenance mutations escalated/denied.
- **SOC:** mean-time-to-detect (event→alert, async); mean-time-to-contain (detection→freeze); # incidents correlated from multi-step runs; % incident timelines provable via receipt chain; detection precision (deterministic rules → ~0 false-positive on provenance gates).
- **Activation:** time-to-first-protected-action < 20 min; % completing GitHub+Slack; % running the approve-then-swap demo; % reaching a first correlated incident in the console.
- **Community:** GitHub stars/forks; adoption of the open receipt format; layer-on adapter installs.
- **Business:** design partners (compliance-driven), pilot→paid, MRR, retention.

---

## 12. Competitive differentiation requirements

AegisAgent must clearly NOT be sold as "another gateway" or "another SIEM." Differentiation from the June-2026 field:

| Competitor class | They provide | AegisAgent adds (the reason to adopt) |
|---|---|---|
| Free OSS toolkit (Microsoft) | The whole baseline loop, free | Frozen-action approval binding + fail-closed SDK; deterministic provenance gate; neutral/non-ecosystem |
| OSS firewall (Pipelock) | Egress/DLP + signed receipts | Cedar action-authz + TOCTOU-safe human approvals |
| SaaS gateways (MintMCP/Operant/Peta) | Turnkey gateway, RBAC, audit | Provable approval integrity as the product; self-hostable; open receipt standard |
| Identity governance | Who the agent is | Whether *this* approval is bound to *this* action |
| **Generic SIEM/SOC** | **Log collection + text-scoring detection + dashboards** | **Provenance-anchored deterministic detection + provable (hash-chained) incident timelines + an SDK-enforced containment loop — "the SOC that can prove what agents did"** |

**Positioning rule:** lead with the approve-then-swap demo, the provable incident timeline, and the Article 14 evidence story; offer layer-on adapters so AegisAgent augments, not replaces, an existing gateway.

---

## 13. Risks and mitigations

### 13.1 Product risks
| Risk | Mitigation |
|---|---|
| SDK bypass (agent calls tool directly) | Token broker / proxy-only credentials; SDK in trust boundary fails closed; detect direct tool use as a SOC event |
| Integrity primitive copied by incumbent | Ship first; publish open receipt spec; win standard + community |
| Free Microsoft OSS resets price floor | OSS core genuinely better at integrity; monetize ops + evidence + SOC |
| Approval fatigue | Risk-based gating; auto-allow low-risk; dedupe |
| Buyer education ("TOCTOU on approvals"?) | Demo-led; tie to compliance deadline |
| **Scope creep into a generic SIEM** | Hold the design laws (§13.2); no headline feature that doesn't ride the receipt/provenance spine |

### 13.2 SOC design laws (mitigations baked into architecture)
1. **Deterministic policy decides; scores never gate.** (Closes score-gating manipulation.)
2. **The LLM investigates; it never decides, enforces, or reads instructions.** (Closes second-order prompt injection inside the SOC.)
3. **The inline action path stays <75 ms; detection is asynchronous.** (The SOC is never a latency tax or a fail-open path.)
4. **Every moat primitive is preserved end-to-end.** (The SOC consumes `action_hash`/`receipt_hash`; never weakens them.)

---

## 14. Open questions

1. Canonical serialization spec for `action_hash` — locked as `aegis-jcs-1`; confirm cross-language byte-equality in CI for every SDK.
2. Should the verifiable receipt use a Merkle/transparency log (Sigstore-style) for enterprise tamper evidence?
3. OSS core: include hosted-equivalent Slack approvals, or self-hosted webhook only?
4. First layer-on adapter target: Microsoft toolkit, or a SaaS gateway?
5. Event-bus choice for the SOC at scale: start in-proc `tokio::mpsc` → Redis Streams → Kafka/NATS at what thresholds?
6. Correlation-engine state store: in-memory windows vs. durable (for restart-safe sequence detection)?

---

## 15. MVP release definition

AegisAgent MVP is ready when it can demonstrate:

```text
A coding agent reads a malicious GitHub issue.
AegisAgent classifies the trigger as untrusted_external (deterministic) -> require_approval.
The EXACT merge action is frozen + SHA-256 hashed; the Slack approval binds to that hash.
The agent attempts to execute a SWAPPED action under the approval -> SDK fails closed (hash mismatch). Nothing runs.
A verifiable, hash-chained action receipt is exported (agent/user/tool/resource/source_trust/approver/action_hash/result).
Unknown MCP tools are denied by default.
The decision is emitted (async) as an Agent Security Event -- the SOC keystone (Phase 0).
```

The **SOC milestone** (Phase 3): the same attack appears in the console as one **correlated, provable** incident timeline, with a one-click receipt-chain verify and a containment (freeze) action.

---

## 16. Final recommendation

Build AegisAgent as:

# **The open, neutral integrity layer for AI agent actions — operated as an integrity-anchored Agent SOC**

MVP focus:
```text
Approval-integrity engine + trust-provenance gate + verifiable receipts
+ (table stakes) GitHub + Slack + MCP Gateway Lite + Cedar policies + audit timeline
+ Phase 0 SOC keystone (async event emitter)
+ one layer-on adapter
```

First public promise:
> **Install AegisAgent in 10 minutes. Every high-risk agent action is frozen, hashed, and bound to its approval — an attempted swap simply won't execute — and every decision flows into a SOC that can *prove* what your agents did.**

Strongest message:
> **Make the approval trustworthy. Trust the source, not the text. Run the SOC on the proof.**
