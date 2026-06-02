# AegisAgent — Go-To-Market (GTM) Document (June 2026 reset)

**Product:** AegisAgent
**Category:** Agent Action Integrity (the integrity + provenance layer for agent actions)
**Version:** v0.2 (re-anchored)
**Date:** 2026-06-02
**Owner:** Lavkush Kumar
**Read first:** [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md)

> ⚠️ **Reset note.** v0.1 went to market as the "Agent Action Firewall." That category is now occupied (free Microsoft Agent Governance Toolkit + OSS Pipelock + funded SaaS like MintMCP/Operant/Peta). Going to market as "another gateway" is a losing motion. This version sells the **integrity layer**: provably-correct human approvals + deterministic provenance gating + verifiable receipts — open, self-hostable, and **layerable onto the gateway a team already runs.**

---

## 1. Executive GTM thesis

Do not sell a gateway. Sell **the thing every gateway leaves missing.**

> **AegisAgent is the integrity layer for AI agent actions. It cryptographically binds every human approval to the exact action that executes (no approve-then-swap, no replay) and gates authorization on whether the trigger came from a trusted source — then hands you a verifiable receipt for SOC 2 and EU AI Act Article 14. Open, self-hostable, and it layers onto the gateway you already run.**

The motion is **interop, not displacement.** "Already have MintMCP / the Microsoft toolkit / Pipelock? Good — AegisAgent makes its approvals provable."

---

## 2. Market context

- **Size/growth:** agentic AI security ≈ USD 1.65B (2026) → 13.52B (2032), ~42% CAGR; SMEs fastest-growing (MarketsandMarkets). Mordor: USD 2.43B (2026) → 9.63B (2031), 31.71% CAGR.
- **The category commoditized in 2026.** Free OSS (Microsoft toolkit, Pipelock) + ~6 funded gateways now do intercept→policy→allow/deny→audit→approval. Broad positioning gets swallowed.
- **Compliance is the new buying trigger.** EU AI Act **Article 14 (human oversight)** deadline **Aug 2, 2026**; SOC 2 / NIST AI RMF expect *provable* oversight + audit. This rewards AegisAgent's exact wedge (verifiable approvals + receipts) over generic blocking.
- **The standard is open.** arXiv:2603.20953 (Mar 2026): no security-grade authz standard at the tool boundary — room to set the *integrity/receipt* standard.

---

## 3. Category strategy

### 3.1 Avoid
"AI security platform," "AI governance platform," **and now also "MCP gateway" / "Agent Action Firewall"** — all crowded, some free.

### 3.2 Own (a sub-layer, not the category)

# Agent Action Integrity

> The layer that makes agent-action controls *provable* (approved action == executed action) and *provenance-aware* (untrusted sources can't drive privileged actions), with verifiable evidence.

### 3.3 Narrative
```text
Gateways DECIDE whether an agent action is allowed.
AegisAgent PROVES the decision was honored — and refuses to let untrusted sources drive it.
```

---

## 4. Ideal customer profile

### 4.1 Primary ICP — compliance-pressured teams shipping mutating agents
Teams putting **high-blast-radius** agent actions into production (merge/deploy, IAM, refunds, data export) **and** facing SOC 2 / EU AI Act Article 14. They often *already run a gateway* and have discovered it doesn't make approvals provable.

Why: acute, time-boxed pain (Aug 2 2026); clear budget line (compliance); fast to adopt; value evidence artifacts.

### 4.2 Secondary ICP — security/platform teams at 100–1,000-person SaaS
Understand policy-as-code, audit, approvals; will not route prod tool calls through a third-party cloud → value **self-hostable + neutral**.

### 4.3 Tertiary ICP — regulated enterprise design partners
Fintech, healthcare, legal, insurance. Longer cycles, real budget, strongest need for chain-of-custody.

---

## 5. Buyer personas

| Role | Primary concern (integrity-anchored) |
|---|---|
| **Economic buyer** (CISO/CTO/VP Eng) | "Can we *prove* human oversight of agent actions to auditors and customers?" |
| **Technical buyer** (Security architect/Platform lead) | "Can an agent execute a different action than the one approved? Can untrusted content drive a privileged call? Can I self-host?" |
| **Champion** (AI/security engineer) | "Can I get fail-closed integrity + receipts without rewriting my agent or routing through someone's cloud?" |

---

## 6. Beachhead use case & killer demo

### 6.1 First use case
Secure mutating coding-agent actions on **GitHub + Slack + MCP** with provable integrity.

### 6.2 Killer demo (the whole pitch in 90 seconds)
```text
1. Malicious GitHub issue tries to hijack a coding agent into a risky merge / secret read.
2. AegisAgent classifies the trigger as untrusted_external (DETERMINISTIC) -> require_approval.
3. The EXACT action is frozen + SHA-256 hashed; the Slack approval binds to that hash.
4. Attacker performs approve-then-swap: a different action is submitted under the approval.
5. SDK FAILS CLOSED on hash mismatch. Nothing executes.
6. A verifiable action receipt is exported -> SOC 2 / Article 14 evidence.
```
This demos two things no competitor shows on stage: a *blocked approve-then-swap* and a *provenance-driven denial.*

---

## 7. Positioning

**Short:** *AegisAgent is the integrity layer for AI agent actions.*

**Long:** *AegisAgent binds every human approval to the exact action that executes, gates authorization on the trust level of the triggering content, and emits verifiable action receipts for SOC 2 / EU AI Act Article 14 — open, self-hostable, and layerable onto any existing gateway.*

### Differentiation (June 2026 field)

| Alternative | What it does | AegisAgent difference |
|---|---|---|
| Microsoft Agent Governance Toolkit (free) | Whole baseline loop, Cedar/OPA, MCP, approvals, audit | Frozen-action approval binding + fail-closed SDK; deterministic provenance gate; neutral (non-MSFT) |
| Pipelock (OSS) | Egress/DLP/SSRF + signed receipts | Cedar action-authz + TOCTOU-safe human approvals (not just network egress) |
| MintMCP / Operant / Peta (SaaS) | Turnkey gateway, RBAC, audit, SOC 2 | Provable approval integrity as the product; self-hostable; open receipt standard; layers onto them |
| ConductorOne / Entra Agent ID | Agent identity + JIT access | Whether *this* approval is bound to *this* action |
| Prompt-injection classifiers | Score text | Deterministic source-provenance gating |

---

## 8. Competitive landscape (June 2026)

The full head-to-head matrix lives in the reassessment doc §5. Summary: the baseline is matched everywhere including free OSS. AegisAgent competes only on the two **bold** rows of that matrix (frozen-action approval binding; deterministic provenance gating) plus neutrality/self-hosting and an open receipt format. We **integrate with**, not displace, the rest.

---

## 9. Pricing & packaging (reframed by free OSS)

Free Microsoft OSS resets the floor: paid value is **operations + evidence**, not the loop.

| Plan | Price | Included |
|---|---:|---|
| OSS Core | Free | Self-hosted gateway, Cedar policies, **frozen-action approval binding**, **provenance gate**, local receipts |
| Team | $99–$299/mo | Hosted approvals (Slack/Teams), receipt retention, policy library |
| Startup | $499–$999/mo | Multi-tenant, SSO, SIEM/OTel export, **SOC 2 evidence packs** |
| Growth | $1.5K–$3K/mo | Longer retention, **Article 14 evidence reporting**, policy templates, multiple teams |
| Enterprise | $15K+/yr | Self-hosted/air-gapped support, custom retention, SLAs |

**Primary metric:** protected/verified high-risk actions per month (value = controlled, provable actions). Avoid seat-only pricing.

---

## 10. Distribution strategy

1. **Founder-led design partners (compliance-driven).** Target 20–30 conversations → 5 pilots → 2–3 paid. Offer: 60-day pilot + Article 14 / SOC 2 evidence output + roadmap influence.
2. **Open-source + open standard.** OSS: gateway, SDKs (Python/TS), policy templates, MCP gateway lite, **and the verifiable action-receipt spec.** Keep paid: hosted approvals, SSO, SIEM export, retention, evidence reporting, enterprise support. The open *receipt spec* is the distribution flywheel.
3. **Layer-on adapters.** Ship adapters that add integrity on top of Microsoft toolkit / MintMCP / Pipelock. Distribution through complementarity.
4. **Content + partners.** Educate on TOCTOU-on-approvals and provenance gating; partner with compliance consultants, MSSPs, agent frameworks.

---

## 11. Sales motion

Founder-led, demo-first. Open with the failure, not a deck:
```text
Does your current gateway guarantee the agent executed the EXACT action a human approved?
Have you tested approve-then-swap? Can untrusted content drive a privileged call?
Can you hand an auditor a receipt that proves it for Article 14?
```

**Discovery questions:** which mutating agents are in prod? do you already run a gateway? does it bind approvals to the executed action? is source-trust a policy input or a text score? Article 14 / SOC 2 timeline? self-hosting required?

**Qualified if (≥3):** mutating prod agents; already running or evaluating a gateway; compliance deadline (Art.14/SOC 2); write access / external messaging; cannot currently prove approval-to-action binding; refuse third-party-cloud routing.

**Proof of value (2 weeks):** layer AegisAgent onto their setup → demonstrate a blocked approve-then-swap + a provenance denial → export verifiable receipts.

---

## 12. Messaging framework

**Hero:**
```text
Make the approval trustworthy.

AegisAgent is the integrity layer for AI agent actions. Every high-risk action is frozen,
hashed, and bound to its approval — an attempted swap simply won't execute. Every decision
knows whether the trigger was trusted. Export a verifiable receipt for SOC 2 and EU AI Act.
Open, self-hostable, layers onto your existing gateway.
```

**One-sentence pitch:** *AegisAgent proves the agent executed the exact action a human approved, from a trusted source — and gives you the receipt.*

**Differentiation pitch:**
```text
Gateways decide. Classifiers guess. AegisAgent proves — and trusts the source, not the text.
```

---

## 13. Launch plan (120 days)

- **0–30 — validate the integrity gap.** Interview 30 compliance-pressured teams; publish *"Your AI agent approval gate is lying to you: TOCTOU on human-in-the-loop."* Landing page + approve-then-swap demo video. Draft the open receipt spec.
- **31–75 — private beta + adapters.** Onboard 5 partners; layer onto their gateway; produce Article 14 / SOC 2 evidence; collect before/after.
- **76–120 — public launch.** GitHub, HN, Product Hunt, LinkedIn, MCP/AI-eng communities, security newsletters. Launch asset: *"AegisAgent OSS: make your agent approvals provable — and publish the verifiable action-receipt spec."*

---

## 14. Content strategy (12 weeks)

1. "Your AI agent approval gate is lying to you (TOCTOU on HITL)."
2. "Approve-then-swap: a confused-deputy attack on agent approvals."
3. "Trust the source, not the text: deterministic provenance gating."
4. "A verifiable action receipt format for agent actions."
5. "EU AI Act Article 14 for AI agents: what 'provable human oversight' actually requires."
6. "Layering integrity onto the Microsoft Agent Governance Toolkit."
7. "Why we hash the frozen action (canonicalization + RFC 8785)."
8. "SOC 2 evidence for autonomous agent actions."
9. "Self-hosting agent authorization: why security teams won't route prod through your cloud."
10. "AgentDojo/InjecAgent vs a deterministic provenance gate."
11. "MCP manifest drift as a provenance signal."
12. "Open standards beat lock-in in agent security."

---

## 15. Metrics

- **Pre-revenue:** buyer interviews, receipt-spec feedback, GitHub stars, demo calls, design partners.
- **Product-led:** verified high-risk actions, approve-then-swap attempts blocked, provenance escalations, receipts exported, layer-on adapter installs.
- **Sales:** qualified opps (compliance-driven), pilot→paid, ACV, cycle length, MRR.
- **Outcome:** % high-risk actions with verifiable receipt; mean approval response time; time-to-Article-14-evidence.

---

## 16. GTM risks & mitigations

| Risk | Mitigation |
|---|---|
| "Another agent security tool" fatigue | Refuse platform framing; one sharp claim (provable approvals + provenance); demo-led |
| Free Microsoft OSS | Be neutral + better at integrity; ship layer-on adapter *for* it; open receipt standard |
| Integrity primitives copied | Ship first, own the receipt spec + community |
| Buyer education cost | Tie to Article 14 deadline; lead with approve-then-swap demo |
| MCP volatility | Support MCP and non-MCP tool calls |

---

## 17. Final GTM recommendation

Go to market as:

# **AegisAgent — the open integrity layer for AI agent actions**

**ICP:** compliance-pressured teams shipping mutating agents (SOC 2 / EU AI Act Article 14). **Use case:** make agent approvals provable + gate on provenance, layered onto an existing gateway. **Motion:** founder-led design partners + open-source + open receipt spec + layer-on adapters. **Pricing:** free OSS core; paid = hosted ops + compliance evidence.

Best message:
> **Make the approval trustworthy. Trust the source, not the text.**
