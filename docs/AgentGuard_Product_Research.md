# AegisAgent (fka AgentGuard): Agent Action Integrity Layer — Product Research

**Author:** Lavkush Kumar
**Original draft:** 2026-05-29 · **Reset:** 2026-06-02
**Working title:** AegisAgent — Integrity Layer for AI Agent Actions
**Read first:** [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md)

> ⚠️ **Reset note.** The original draft positioned this as an "MCP and tool-use firewall" and recommended building agent inventory + runtime authorization + approval + audit as the wedge. By June 2026 that wedge is occupied (free Microsoft Agent Governance Toolkit + OSS Pipelock + funded SaaS). This version re-anchors on the **integrity + provenance** gap that survives. The research matrix in §4 remains valid and unchanged in substance.

---

## 1. Executive summary

AegisAgent is the **integrity layer for AI agent actions.** The baseline runtime-authorization loop (intercept → policy → allow/deny → audit → approval) is now commodity. AegisAgent's reason to exist is the two things that loop does *not* guarantee:

1. **Approval integrity** — the human "yes" is cryptographically bound to a frozen, hashed representation of the exact action, and the SDK fails closed if a different action is about to execute (defends approve-then-swap, replay, render-vs-bytes).
2. **Trust-provenance gating** — authorization is gated deterministically on *where the triggering content came from* (six trust levels), not on a probabilistic text score (defends the confused-deputy / indirect-prompt-injection path).

Plus the adoption properties: **open, self-hostable, framework-neutral, layerable onto any existing gateway.**

---

## 2. Product idea

### 2.1 Name & one-liner

**AegisAgent.**

> The open, neutral integrity layer for AI agent actions: provably-correct human approvals and deterministic trust-provenance gating, with verifiable action receipts.

### 2.2 Target users

**Buyer:** Head of Security / AI Platform Lead / VP Eng at teams shipping mutating agents, especially under SOC 2 or EU AI Act Article 14.

**ICP:** teams that *already run or plan* a gateway and need the integrity + evidence the gateway doesn't provide; regulated SaaS; security-conscious AI-native startups.

### 2.3 The questions AegisAgent uniquely answers

```text
Did the agent execute the exact action a human approved? (prove it)
Can an old approval be replayed, or a benign one swapped for a dangerous one?
Did this privileged action originate from untrusted content?
Can we hand an auditor a tamper-evident receipt binding approver + action + source trust?
```

Gateways answer "is it allowed?" AegisAgent answers "is the decision provably honored, and provenance-aware?"

---

## 3. Product modules (re-prioritized)

### 3.1 Approval Integrity Engine — **headline**
- Freeze the exact tool call (canonical serialization) and compute `action_hash = SHA-256(canonical_action)`.
- Bind the approval record to `action_hash` + approver identity + decision + timestamp.
- Re-evaluate on any edit (edited params → new hash → fresh decision).
- SDK **fails closed** if the about-to-execute hash ≠ approved hash; reject replayed/expired approvals.

### 3.2 Trust-Provenance Gate — **headline**
- Six deterministic trust levels: `trusted_internal_signed`, `trusted_internal_unsigned`, `semi_trusted_customer`, `untrusted_external`, `malicious_suspected`, `unknown`.
- First-class Cedar context input. Mutating action + untrusted/suspected source → deny or escalate, independent of text content.
- Optional classifier *feeds* the label but never relaxes a stricter deterministic rule.

### 3.3 Verifiable Action Receipts — **headline**
- Tamper-evident record: agent, user, tool, action, resource, `source_trust`, risk, decision, approver, `action_hash`, input/output hashes, timestamp.
- Open, documented format; designed as SOC 2 / EU AI Act Article 14 evidence; exportable to SIEM via OpenTelemetry.

### 3.4 Cedar policy-as-code (table stakes) — with `action_hash` + `source_trust` as native context.
### 3.5 MCP + non-MCP authorization (table stakes) — manifest pinning/drift as a provenance signal.
### 3.6 Layer-on adapters — run standalone OR in front of / alongside an existing gateway (incl. Microsoft toolkit).
### 3.7 Agent registry / inventory (table stakes).

---

## 4. Research matrix (validated — unchanged)

| Area | Source | Key finding | Implication for the integrity wedge |
|---|---|---|---|
| Landscape | *Agentic AI Security: Threats, Defenses, Evaluation, Open Challenges* | Planning + tool use + memory + autonomy create new risk classes | Multi-layer control needed; integrity is the under-served layer |
| Prompt injection | **AgentDojo** (97 tasks, 629 tests) | Tool output hijacks tool-using agents | Benchmark the trust-provenance gate against it |
| Indirect injection | **InjecAgent** (1,054 cases; ReAct GPT-4 vulnerable ~24%) | External content triggers sensitive calls | Provenance gating, not text scoring, is the deterministic defense |
| Access control | **SEAgent / MAC framework** | Privilege escalation = action beyond least privilege; ABAC + info-flow | ABAC/Cedar with source-trust as an attribute |
| MCP security | *MCP: Landscape, Threats, Future* | Lifecycle + 16 threat scenarios | Manifest pinning as provenance; drift → escalate |
| Memory/RAG | **AgentPoison**, **PoisonedRAG** | ≥80% / 90% ASR with tiny poison rates | Provenance + receipts extend to memory/RAG writes (later) |
| Runtime guardrails | **LlamaFirewall** | Guardrails belong on the execution path | AegisAgent enforces at the tool-call boundary, fail-closed |
| Standards | **OWASP AI Agent Security** | Least privilege, explicit authz, **approval integrity**, audit | "Approval manipulation" is the named gap AegisAgent closes |
| Authz boundary | **arXiv:2603.20953** *Before the Tool Call* (2026) | No security-grade authz standard at the tool boundary | Verifiable receipts/approval binding can become that standard |

---

## 5. Architecture

```text
User / App
   v
AI Agent Runtime (LangGraph / CrewAI / AutoGen / OpenAI Agents SDK / custom)
   v
AegisAgent SDK  ── computes canonical action, enforces fail-closed on hash mismatch
   v
AegisAgent Gateway (Rust + Axum + Cedar + SQLite/Postgres)   [standalone OR layered on an existing gateway]
   ├─ Trust-Provenance Gate     (6-level source classification -> Cedar context)
   ├─ Policy Engine (Cedar)     (action_hash + source_trust as native inputs)
   ├─ Approval Integrity Engine (freeze -> SHA-256 -> bind -> re-eval on edit)
   ├─ Approval Delivery         (Slack / Teams / dashboard, signature-verified)
   ├─ Verifiable Receipt + Audit pipeline (OTel export)
   v
Tools / APIs / MCP servers (GitHub, Slack, AWS, DB, Stripe, Jira, files, vector DB)
```

**Key design decision:** the SDK is part of the trust boundary. The gateway can be bypassed by a compromised agent process, so the *SDK itself* refuses to execute an action whose hash isn't the approved one — integrity is enforced at the last possible step, not just decided upstream.

---

## 6. Technology stack (unchanged, still correct)

Rust + Axum gateway (memory-safe, sub-ms policy decisions); Cedar policy engine (native `action_hash`/`source_trust` context); Python + TypeScript SDKs; SQLite (MVP) → Postgres (SaaS); ClickHouse later for receipt volume; OpenTelemetry + Grafana; WorkOS/Clerk for enterprise SSO later; Vault/KMS for secrets. Single self-hostable binary is a first-class requirement (neutrality wedge).

### 6.1 Decision example
```json
{
  "decision": "deny",
  "reason": "Mutating action triggered by untrusted_external content; deterministic provenance gate",
  "source_trust": "untrusted_external",
  "matched_policy": "forbid-mutate-from-untrusted",
  "action_hash": "sha256:..."
}
```

---

## 7. MVP scope (re-anchored)

**Goal:** protect one mutating workflow end-to-end *with provable integrity* — a coding/support agent on GitHub + Slack + one MCP server.

**MVP features:**
1. Cedar policy engine with `action_hash` + `source_trust` context. ✅ (built)
2. Approval Integrity Engine: freeze + SHA-256 + bind + re-eval; SDK fail-closed. ✅ (built)
3. Trust-Provenance Gate: 6 levels as policy input. ✅ (built)
4. Verifiable action-receipt format + audit pipeline.
5. Slack approval with signature verification + approver role lookup. *(gap)*
6. MCP manifest pinning/drift as provenance signal. ✅ (governance built; runtime proxy pending)
7. One layer-on adapter (sit in front of an existing gateway).

**Non-goals:** SIEM, DLP, network egress firewall, model scanning, red-team platform, identity lifecycle.

---

## 8. Competitive differentiation (honest)

Against the June-2026 field (full matrix in reassessment doc): the baseline loop is matched everywhere, including free OSS. AegisAgent differentiates **only** on:
1. **Frozen-action approval binding + fail-closed SDK** (TOCTOU-resistant) — not found in the surveyed field.
2. **Deterministic trust-provenance gating** — vs probabilistic text scoring.
3. **Open verifiable action-receipt format** — interoperable evidence standard.
4. **Vendor-neutral, self-hostable, layerable.**

This is a *feature-grade* edge defended by being first, correct, open, and neutral — not a category moat. (See reassessment §7 risk assessment.)

---

## 9. 90-day execution plan

- **Days 1–15 — validate the integrity gap.** Show 15–20 teams an approve-then-swap / confused-deputy bypass of a stock gateway; confirm they'd pay to close it. Publish: *"Your AI agent approval gate is lying to you: TOCTOU on human-in-the-loop."*
- **Days 16–45 — harden primitives.** Canonical serialization + `action_hash` binding; SDK fail-closed; 6-level provenance gate; receipt format v0; one layer-on adapter.
- **Days 46–70 — benchmark + demo.** AgentDojo/InjecAgent for the provenance gate; build the GitHub-issue → provenance-deny → approve-then-swap-blocked → verifiable-receipt demo.
- **Days 71–90 — design partners.** 3–5 teams under SOC 2 / Art.14 pressure; publish the open receipt spec for community feedback.

---

## 10. Pricing hypothesis (reframed by free OSS)

| Plan | Price | Value |
|---|---:|---|
| OSS Core | Free | Self-hosted gateway, frozen-action approvals, provenance gate, local receipts |
| Startup | $299–$999/mo | Hosted approvals, SSO, SIEM/OTel export, receipt retention |
| Enterprise | $3K–$10K+/mo | Self-hosted/air-gapped support, Art.14/SOC 2 evidence reporting, retention, SLAs |

First milestone: $25K–$40K MRR via design partners under compliance pressure.

---

## 11. Final recommendation

Build AegisAgent as the **open, neutral integrity layer** — provable approvals + provenance gating + verifiable receipts — that *layers onto* the now-commodity gateway market rather than competing to be the gateway. Lead every conversation with the approve-then-swap demo and the Article 14 evidence story.
