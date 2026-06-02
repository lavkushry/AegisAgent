# AegisAgent — Product Requirements Document (June 2026 reset)

**Product:** AegisAgent
**Category:** Agent Action Integrity (integrity + provenance layer for agent actions)
**Version:** v0.2 (re-anchored)
**Date:** 2026-06-02
**Owner:** Lavkush Kumar
**Read first:** [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md)

> ⚠️ **Reset note.** v0.1 specified an "Agent Action Firewall" whose headline features were inventory + action-level authz + approval + audit. By June 2026 that loop is commodity (free Microsoft toolkit + OSS + SaaS). This version keeps the still-valid functional spec but **re-prioritizes the two defensible differentiators to headline status**: (1) frozen-action approval integrity with a fail-closed SDK, (2) deterministic trust-provenance gating — plus verifiable action receipts. Everything else is table stakes.

---

## 1. Executive summary

AegisAgent is the **integrity layer for AI agent actions.** It sits at the tool-call boundary (standalone or layered onto an existing gateway) and guarantees two things competitors decide but don't *prove*:

1. **The human-approved action is the action that executes** — the exact action is frozen, SHA-256 hashed, and the approval is bound to that hash; the SDK fails closed on any mismatch (defends approve-then-swap, replay, render-vs-bytes — OWASP "approval manipulation").
2. **Untrusted-origin content cannot drive a privileged action** — a deterministic 6-level source-trust label is a first-class policy input (defends the confused-deputy / indirect-prompt-injection path — AgentDojo, InjecAgent).

Every protected action emits a **verifiable action receipt** suitable as SOC 2 / EU AI Act Article 14 evidence. The product is **open, self-hostable, and framework-neutral.**

Market context: developers adopt AI agents heavily but distrust output (Stack Overflow 2026: ~84% use, ~29% trust); GitHub workflows are now agentic (Copilot coding agent opens PRs from issues); NSA MCP guidance (May 2026) warns of dynamic-invocation and trust-boundary risk. The baseline gateway market answered "decide"; AegisAgent answers "prove."

---

## 2. Product vision

> **Make the approval trustworthy. Trust the source, not the text.**

AI risk moved from text → action; in 2026 it moved again from "can we decide?" → "can we prove the decision held?" AegisAgent makes every high-risk action *provably* the approved one, from a known source, with exportable evidence.

---

## 3. Problem statement

> **A market of gateways can now allow/deny/approve agent actions, but the approval is not cryptographically bound to the executed action and authorization is blind to the trigger's source trust. Teams operate under controls that can be silently bypassed (approve-then-swap, replay, confused deputy) and cannot prove human oversight to auditors.**

See [Problem Definition](#) doc for full treatment. This PRD specifies the product that closes that integrity gap.

---

## 4. Goals and non-goals

### 4.1 Goals
1. **Guarantee approval integrity** — approved action == executed action, enforced at the SDK, provable after the fact.
2. **Gate on provenance deterministically** — source-trust as a Cedar input; untrusted origin cannot drive mutating actions without escalation.
3. **Emit verifiable evidence** — open action-receipt format, exportable to SIEM; maps to Article 14 / SOC 2.
4. **Be neutral and layerable** — self-hostable single binary; runs standalone or in front of an existing gateway.
5. **Keep the baseline at table-stakes quality** — inventory, action-level authz, MCP governance, audit, developer DX.

### 4.2 Non-goals (MVP)
Full SIEM, full DLP, network egress firewall, model scanning, GRC suite, generic chatbot moderation, identity lifecycle management, automated remediation. AegisAgent integrates with these; it is not them.

---

## 5. Target users and personas

| Persona | Core need (integrity-anchored) |
|---|---|
| **AI / agent engineer** | SDK that fails closed automatically; readable Cedar policies; local dry-run; clear deny reasons |
| **Platform / DevOps** | Self-hostable gateway; GitHub/Slack/MCP integration; metrics; reliability |
| **Security engineer** | Provable approvals; deterministic provenance gating; default-deny; secure defaults |
| **Compliance / auditor** | Verifiable action receipts; approval chain-of-custody; Article 14 / SOC 2 export |
| **Economic buyer (CTO/VP Eng/CISO)** | Prove safe agent rollout to customers and regulators |

---

## 6. MVP scope

### 6.1 Theme

# Protect a coding agent on GitHub + Slack + MCP — with provable integrity

The MVP must prove this loop end-to-end:

```text
Agent proposes action
→ AegisAgent classifies trigger source trust (deterministic)
→ Cedar policy evaluates (source_trust + action risk + resource)
→ if approval needed: freeze EXACT action → SHA-256 → bind approval to hash
→ SDK executes ONLY if about-to-run hash == approved hash, else FAIL CLOSED
→ verifiable action receipt + audit timeline written
```

### 6.2 Headline features (the differentiators)

#### Feature H1 — Approval Integrity Engine
- Canonical serialization of the tool call → `action_hash = SHA-256(canonical_action)`.
- Approval record binds `action_hash` + approver + decision + timestamp.
- Editing parameters yields a new hash and forces re-evaluation.
- SDK **fails closed** if the hash it is about to execute ≠ approved hash; rejects expired/replayed approvals.

**Acceptance:**
```text
Given an approval was granted for action A (hash Ha),
when the agent attempts to execute action B (hash Hb != Ha) under that approval,
then the SDK refuses to execute and writes a tamper-attempt audit event.
```

#### Feature H2 — Trust-Provenance Gate
- Six deterministic source-trust levels as a first-class Cedar context input.
- Mutating action + `untrusted_external`/`malicious_suspected` → deny or escalate, regardless of text.
- Optional classifier may tighten but never loosen a deterministic rule.

**Acceptance:**
```text
Given an agent read a GitHub issue from an external contributor (untrusted_external),
when it later attempts a mutating action in the same run,
then AegisAgent denies or requires approval based on provenance, not on text sentiment.
```

#### Feature H3 — Verifiable Action Receipts
- Open, documented receipt: agent, user, tool, action, resource, `source_trust`, risk, decision, approver, `action_hash`, input/output hashes, timestamp.
- Exportable via OpenTelemetry/webhook; designed as Article 14 / SOC 2 evidence.

**Acceptance:**
```text
Given any protected action completes (allow/deny/approved),
when an auditor exports the receipt,
then it cryptographically links approver -> action_hash -> source_trust -> result.
```

### 6.3 Table-stakes features (required, not differentiating)

- **Agent registry** — identity, owner, environment, risk tier, status (active/disabled/quarantined), token issuance.
- **Tool action registry** — per-action risk + mutation flag (GitHub first: read_issue/read_file/create_branch/create_pull_request/comment_on_pr/merge_pull_request/delete_branch/change_codeowners).
- **Runtime authorization API** — `allow | deny | require_approval | log_only | quarantine`, with reason + matched policy IDs; default-deny unknowns.
- **Cedar policy engine** — with `action_hash` and `source_trust` as native context.
- **Slack approval workflow** — signature-verified callbacks, approver role lookup, approve/reject/edit/escalate.
- **MCP Gateway Lite** — register/discover/approve/disable tools, manifest hashing + drift detection (drift → provenance escalation), deny unknown tools, log calls.
- **Audit timeline** — event chain linked by run/trace ID.

---

## 7. Functional requirements

(Agent / tool / MCP management, authorization, approval workflow, audit, context trust — as in v0.1, retained.) Key additions/changes:

- **Approval workflow MUST** bind every approval to `action_hash`, support expiry, re-evaluate edits, and the **SDK MUST fail closed** on hash mismatch. *(was implied; now mandatory headline behavior)*
- **Context trust MUST** be deterministic and policy-visible; classifiers are advisory only and may not downgrade a label.
- **Receipts MUST** be emitted for every protected action in the open format and be independently verifiable (hash chain).
- **Deployment MUST** support a fully self-hosted single-binary mode with local-only receipt storage.

---

## 8. Non-functional requirements

```text
Authorization API p95 latency:  < 150 ms
Policy evaluation p95 latency:  < 75 ms
action_hash compute overhead:   < 5 ms (canonical serialize + SHA-256)
Slack approval creation p95:    < 5 s
Audit/receipt enqueue success:  99.9%
MCP proxy overhead p95:         < 250 ms

Fail-closed: high-risk actions fail closed if policy/audit/approval is unavailable
             SDK fails closed on any hash mismatch or unreachable gateway (configurable for read-only)
Security defaults: unknown agent/tool/MCP server/MCP tool -> deny; critical -> deny;
                   high-risk -> require approval; approval callbacks signature-verified;
                   secrets redacted; tenant data isolated by tenant_id
```

---

## 9. API requirements (unchanged surface; integrity semantics clarified)

```http
POST /v1/agents                                  # register agent
POST /v1/tools                                   # register tool + actions
POST /v1/mcp/servers                             # register MCP server
GET  /v1/mcp/servers/:key/tools                  # manifest
POST /v1/authorize                               # returns decision + action_hash + source_trust
GET  /v1/approvals/:id                            # returns status + action_hash (SDK verifies)
POST /v1/approvals/:id/approve|reject|edit        # approve binds to action_hash; edit re-hashes + re-evaluates
GET  /v1/runs/:id/timeline                        # receipts + events
GET  /v1/audit/events
```

The `GET /v1/approvals/:id` response **MUST** include the bound `action_hash`; the SDK **MUST** compare it to the action it is about to execute and fail closed on mismatch.

---

## 10. Data requirements

Core entities: `tenant, user, agent, tool, tool_action, mcp_server, mcp_tool, policy, decision, approval (incl. action_hash), audit_event, context_label, action_receipt`. Retention tiers: OSS local-only → Team 7–30d → Startup 90d → Growth 1y → Enterprise custom.

---

## 11. Success metrics

- **Integrity:** # approve-then-swap / replay attempts blocked by hash mismatch; % protected actions with a verifiable receipt; # untrusted-provenance mutations escalated/denied.
- **Activation:** time-to-first-protected-action < 20 min; % completing GitHub+Slack; % running the approve-then-swap demo.
- **Community:** GitHub stars/forks; adoption of the open receipt format; layer-on adapter installs.
- **Business:** design partners (compliance-driven), pilot→paid, MRR, retention.

---

## 12. Competitive differentiation requirements

AegisAgent must clearly NOT be sold as "another gateway." Differentiation from the June-2026 field:

| Competitor class | They provide | AegisAgent adds (the reason to adopt) |
|---|---|---|
| Free OSS toolkit (Microsoft) | The whole baseline loop, free | Frozen-action approval binding + fail-closed SDK; deterministic provenance gate; neutral/non-ecosystem |
| OSS firewall (Pipelock) | Egress/DLP + signed receipts | Cedar action-authz + TOCTOU-safe human approvals |
| SaaS gateways (MintMCP/Operant/Peta) | Turnkey gateway, RBAC, audit | Provable approval integrity as the product; self-hostable; open receipt standard |
| Identity governance | Who the agent is | Whether *this* approval is bound to *this* action |

**Positioning rule:** lead with the approve-then-swap demo and the Article 14 evidence story; offer layer-on adapters so AegisAgent augments, not replaces, an existing gateway.

---

## 13. Risks and mitigations

| Risk | Mitigation |
|---|---|
| SDK bypass (agent calls tool directly) | Token broker / proxy-only credentials; SDK is in trust boundary and fails closed; detect direct tool use |
| Integrity primitive copied by incumbent | Ship first; publish open receipt spec; win standard + community |
| Free Microsoft OSS resets price floor | OSS core genuinely better at integrity; monetize ops + evidence |
| Approval fatigue | Risk-based gating; auto-allow low-risk; dedupe |
| Buyer education ("TOCTOU on approvals"?) | Demo-led; tie to compliance deadline |

---

## 14. Open questions

1. Canonical serialization spec for `action_hash` — JSON Canonicalization Scheme (RFC 8785) or custom? (must be stable across SDK languages)
2. Should the verifiable receipt use a Merkle log / transparency log (Sigstore-style) for tamper evidence?
3. OSS core: include hosted-equivalent Slack approvals, or self-hosted webhook only?
4. First layer-on adapter target: Microsoft toolkit, or a SaaS gateway?
5. Receipt signing key management in self-hosted mode (KMS optional)?

---

## 15. MVP release definition

AegisAgent MVP is ready when it can demonstrate:

```text
A coding agent reads a malicious GitHub issue.
AegisAgent classifies the trigger as untrusted_external (deterministic) -> require_approval.
The EXACT merge action is frozen + SHA-256 hashed; the Slack approval binds to that hash.
The agent attempts to execute a SWAPPED action under the approval -> SDK fails closed (hash mismatch). Nothing runs.
A verifiable action receipt is exported (agent/user/tool/resource/source_trust/approver/action_hash/result).
Unknown MCP tools are denied by default.
```

---

## 16. Final recommendation

Build AegisAgent as:

# **The open, neutral integrity layer for AI agent actions**

MVP focus:
```text
Approval-integrity engine + trust-provenance gate + verifiable receipts
+ (table stakes) GitHub + Slack + MCP Gateway Lite + Cedar policies + audit timeline
+ one layer-on adapter
```

First public promise:
> **Install AegisAgent in 10 minutes. Every high-risk agent action is frozen, hashed, and bound to its approval — and an attempted swap simply won't execute. Export a verifiable receipt for every decision.**

Strongest message:
> **Make the approval trustworthy. Trust the source, not the text.**
