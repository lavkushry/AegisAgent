# AegisAgent — Go-To-Market (GTM) Document (June 2026 reset)

**Product:** AegisAgent
**Category:** Agent Action Integrity → Integrity-anchored Agent SOC
**Version:** v0.3 (re-anchored on the integrity-anchored Agent SOC)
**Date:** 2026-06-05
**Owner:** Lavkush Kumar
**Read first:** [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md) · **SOC architecture:** [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md)

> ⚠️ **Reset note (two layers).** v0.1 went to market as the "Agent Action Firewall" — now a crowded/free category. v0.2 sold the **integrity layer**: provable approvals + provenance gating + verifiable receipts, layerable onto any gateway. **v0.3 adds the product surface that closes the deal: an integrity-anchored Agent SOC** — *"detect, contain, and prove every agent action."* We do **not** sell a generic SIEM; we sell the SOC that can *prove* what agents did, riding the receipt + provenance spine.

---

## 1. Executive GTM thesis

Do not sell a gateway. Do not sell a generic SIEM. Sell **the thing every gateway leaves missing, operated as the SOC every SIEM can't be for agents.**

> **AegisAgent is the integrity layer for AI agent actions, delivered as an integrity-anchored Agent SOC. It cryptographically binds every human approval to the exact action that executes (no approve-then-swap, no replay), gates authorization on whether the trigger came from a trusted source, and streams every verifiable receipt into a SOC that detects, correlates, contains, and *proves* — for SOC 2 and EU AI Act Article 14. Open, self-hostable, and it layers onto the gateway you already run.**

The motion is **interop, not displacement.** "Already have MintMCP / the Microsoft toolkit / Pipelock? Good — AegisAgent makes its approvals provable and gives you the SOC that proves what your agents did."

---

## 2. Market context

- **Size/growth:** agentic AI security ≈ USD 1.65B (2026) → 13.52B (2032), ~42% CAGR; SMEs fastest-growing (MarketsandMarkets). Mordor: USD 2.43B (2026) → 9.63B (2031), 31.71% CAGR.
- **The category commoditized in 2026.** Free OSS (Microsoft toolkit, Pipelock) + ~6 funded gateways do intercept→policy→allow/deny→audit→approval. Broad positioning gets swallowed.
- **Compliance is the buying trigger.** EU AI Act **Article 14** deadline **Aug 2, 2026**; SOC 2 / NIST AI RMF expect *provable* oversight, audit, **and monitoring** — rewarding verifiable approvals + receipts + a provable-incident SOC.
- **Operational pull (new):** teams with growing agent fleets need a detect/correlate/contain plane; their existing SIEM can't monitor agents (provenance-blind, integrity-blind, proof-less).
- **The standard is open.** arXiv:2603.20953 (Mar 2026): no security-grade authz standard at the tool boundary — room to set the *integrity/receipt* standard and the SOC that consumes it.

---

## 3. Category strategy

### 3.1 Avoid
"AI security platform," "AI governance platform," "MCP gateway" / "Agent Action Firewall," **and "generic SIEM/SOC"** — crowded, some free, and (for SIEM) a poor fit for agents.

### 3.2 Own (a sub-layer + its operating surface)

# Agent Action Integrity → the Integrity-anchored Agent SOC

> The layer that makes agent-action controls *provable* (approved action == executed action) and *provenance-aware* (untrusted sources can't drive privileged actions) — operated as the SOC that **detects, contains, and proves** every agent action.

### 3.3 Narrative
```text
Gateways DECIDE whether an agent action is allowed.
Generic SIEMs LOG it (and score the text, and miss the attack).
AegisAgent PROVES the decision was honored, refuses to let untrusted sources drive it,
           and runs the SOC that detects, contains, and proves — on tamper-evident evidence.
```

---

## 4. Ideal customer profile

### 4.1 Primary ICP — compliance-pressured teams shipping mutating agents
High-blast-radius actions (merge/deploy, IAM, refunds, data export) **and** SOC 2 / EU AI Act Article 14. Often *already run a gateway* and discovered it doesn't make approvals provable — and that they have no way to monitor or prove agent incidents. Acute, time-boxed pain (Aug 2 2026); clear budget line; values evidence + monitoring.

### 4.2 Secondary ICP — security/platform teams at 100–1,000-person SaaS
Policy-as-code, audit, approvals fluent; growing agent fleet; won't route prod tool calls through a third-party cloud → value **self-hostable + neutral + a fleet SOC view**.

### 4.3 Tertiary ICP — regulated enterprise design partners
Fintech, healthcare, legal, insurance. Longer cycles, real budget, strongest need for chain-of-custody + provable incident records.

---

## 5. Buyer personas

| Role | Primary concern (integrity-anchored) |
|---|---|
| **Economic buyer** (CISO/CTO/VP Eng) | "Can we *prove* human oversight of agent actions — and detect/contain incidents — for auditors and customers?" |
| **Technical buyer** (Security architect/Platform lead) | "Can an agent execute a different action than approved? Can untrusted content drive a privileged call? Can I correlate + contain incidents? Can I self-host?" |
| **SOC analyst** | "Can I watch the agent fleet, get provenance-aware detections, and prove the incident timeline?" |
| **Champion** (AI/security engineer) | "Fail-closed integrity + receipts + a SOC, without rewriting my agent or routing through someone's cloud?" |

---

## 6. Beachhead use case & killer demo

### 6.1 First use case
Secure mutating coding-agent actions on **GitHub + Slack + MCP** with provable integrity — and watch them in the SOC.

### 6.2 Killer demo (the whole pitch in 90 seconds)
```text
1. Malicious GitHub issue tries to hijack a coding agent into a risky merge / secret read.
2. AegisAgent classifies the trigger as untrusted_external (DETERMINISTIC) -> require_approval.
3. The EXACT action is frozen + SHA-256 hashed; the Slack approval binds to that hash.
4. Attacker performs approve-then-swap: a different action is submitted under the approval.
5. SDK FAILS CLOSED on hash mismatch. Nothing executes.
6. A verifiable, hash-chained action receipt is exported -> SOC 2 / Article 14 evidence.
7. In the SOC: issue-read -> merge-attempt correlate into ONE incident with a PROVABLE timeline
   (each row carries its receipt_hash; one-click verify); one-click freeze; auto-drafted RCA.
```
This demos three things no competitor shows on stage: a *blocked approve-then-swap*, a *provenance-driven denial*, and a *provable, correlated incident timeline*.

---

## 7. Positioning

**Short:** *AegisAgent is the integrity layer for AI agent actions — the SOC that can prove what your agents did.*

**Long:** *AegisAgent binds every human approval to the exact action that executes, gates authorization on the trust level of the triggering content, emits verifiable hash-chained receipts, and operates a deterministic SOC that detects, correlates, and contains agent threats on that tamper-evident evidence — for SOC 2 / EU AI Act Article 14. Open, self-hostable, layerable onto any existing gateway.*

### Differentiation (June 2026 field)

| Alternative | What it does | AegisAgent difference |
|---|---|---|
| Microsoft Agent Governance Toolkit (free) | Whole baseline loop, Cedar/OPA, MCP, approvals, audit | Frozen-action approval binding + fail-closed SDK; deterministic provenance gate; integrity-anchored SOC; neutral |
| Pipelock (OSS) | Egress/DLP/SSRF + signed receipts | Cedar action-authz + TOCTOU-safe approvals + correlation/incident SOC |
| MintMCP / Operant / Peta (SaaS) | Turnkey gateway, RBAC, audit, SOC 2 | Provable approval integrity + provable-timeline SOC as the product; self-hostable; layers onto them |
| ConductorOne / Entra Agent ID | Agent identity + JIT access | Whether *this* approval is bound to *this* action |
| Prompt-injection classifiers | Score text | Deterministic source-provenance gating |
| **Generic SIEM/SOC (Splunk/Sentinel/Wazuh)** | **Log collection + text-scoring + SOAR** | **Agent-native, provenance-aware deterministic detection + provable hash-chained incident timelines + SDK-enforced containment** |

---

## 8. Competitive landscape (June 2026)

Full head-to-head in the reassessment doc §5. Summary: the baseline is matched everywhere including free OSS. AegisAgent competes only on the integrity primitives (frozen-action binding; deterministic provenance gating), the open receipt format, neutrality/self-hosting, **and the integrity-anchored SOC** (provable timelines, deterministic detection, SDK-enforced containment). We **integrate with**, not displace, gateways; we **out-fit**, not imitate, generic SIEMs.

---

## 9. Pricing & packaging (reframed by free OSS; the SOC is the paid surface)

| Plan | Price | Included |
|---|---:|---|
| OSS Core | Free | Self-hosted gateway, Cedar policies, **frozen-action approval binding**, **provenance gate**, local receipts, **in-proc SOC** (deterministic rules + local console) |
| Team | $99–$299/mo | Hosted approvals (Slack/Teams), receipt retention, **notify sink**, policy/rule library |
| Startup | $499–$999/mo | Multi-tenant, SSO, SIEM/OTel export, **correlation + incidents**, SOC 2 evidence packs |
| Growth | $1.5K–$3K/mo | Longer retention, **Article 14 evidence reporting + provable incident records**, policy/rule templates, multiple teams |
| Enterprise | $15K+/yr | Self-hosted/air-gapped support, **multi-node SOC + Active-Response**, custom retention, SLAs |

**Primary metric:** protected/verified high-risk actions per month + incidents contained. Avoid seat-only pricing.

---

## 10. Distribution strategy

1. **Founder-led design partners (compliance-driven).** 20–30 conversations → 5 pilots → 2–3 paid. Offer: 60-day pilot + Article 14 / SOC 2 evidence output + a live SOC view of their agents + roadmap influence.
2. **Open-source + open standard.** OSS: gateway, SDKs, policy/rule templates, MCP gateway lite, **the verifiable action-receipt spec**, and the **deterministic detection-rule format**. Paid: hosted approvals, SSO, SIEM export, correlation/incidents, retention, evidence reporting, Active-Response, enterprise support.
3. **Layer-on adapters.** Add integrity + SOC on top of Microsoft toolkit / MintMCP / Pipelock. Distribution through complementarity.
4. **Content + partners.** Educate on TOCTOU-on-approvals, provenance gating, and "why your SIEM can't watch your agents." Partner with compliance consultants, MSSPs, agent frameworks.

---

## 11. Sales motion

Founder-led, demo-first. Open with the failure, not a deck:
```text
Does your current gateway guarantee the agent executed the EXACT action a human approved?
Have you tested approve-then-swap? Can untrusted content drive a privileged call?
When an attack unfolds across a run, does anything correlate it — and can you PROVE that timeline?
Can you contain a misbehaving agent in real time, and hand an auditor the evidence for Article 14?
```

**Qualified if (≥3):** mutating prod agents; already running/evaluating a gateway; compliance deadline; write access / external messaging; cannot prove approval-to-action binding; no fleet-level detect/contain today; refuse third-party-cloud routing.

**Proof of value (2 weeks):** layer AegisAgent onto their setup → blocked approve-then-swap + provenance denial → exported receipts → a **live SOC** showing a correlated, provable incident + one-click containment.

---

## 12. Messaging framework

**Hero:**
```text
Make the approval trustworthy. Run the SOC on the proof.

AegisAgent is the integrity layer for AI agent actions — the SOC that can PROVE what your agents did.
Every high-risk action is frozen, hashed, and bound to its approval — a swap won't execute. Every
decision knows whether the trigger was trusted. Every incident is correlated on tamper-evident
evidence and provable end to end. Export a verifiable receipt for SOC 2 and EU AI Act.
Open, self-hostable, layers onto your existing gateway.
```

**One-sentence pitch:** *AegisAgent proves the agent executed the exact action a human approved, from a trusted source — and runs the SOC that detects, contains, and proves it.*

**Differentiation pitch:**
```text
Gateways decide. Classifiers guess. SIEMs log. AegisAgent proves — and trusts the source, not the text.
```

---

## 13. Launch plan (120 days)

- **0–30 — validate the integrity + monitoring gap.** Interview 30 compliance-pressured teams; publish *"Your AI agent approval gate is lying to you (TOCTOU) — and your SIEM can't see it."* Landing page + approve-then-swap demo video + a SOC incident-timeline teaser. Draft the open receipt + detection-rule specs.
- **31–75 — private beta + adapters + SOC v0.** Onboard 5 partners; layer onto their gateway; produce Article 14 / SOC 2 evidence + a live SOC view; collect before/after.
- **76–120 — public launch.** GitHub, HN, Product Hunt, LinkedIn, MCP/AI-eng + security communities. Launch asset: *"AegisAgent OSS: make your agent approvals provable, and run the SOC that proves what your agents did."*

---

## 14. Content strategy (12 weeks)

1. "Your AI agent approval gate is lying to you (TOCTOU on HITL)."
2. "Approve-then-swap: a confused-deputy attack on agent approvals."
3. "Trust the source, not the text: deterministic provenance gating."
4. "A verifiable action receipt format for agent actions."
5. "EU AI Act Article 14 for AI agents: what 'provable human oversight' actually requires."
6. "Layering integrity onto the Microsoft Agent Governance Toolkit."
7. "Why we hash the frozen action (canonicalization, `aegis-jcs-1`)."
8. "Wazuh for AI agents: what an integrity-anchored Agent SOC is (and isn't)."
9. "Why your SIEM can't watch your agents (and why text-scoring fails)."
10. "Provable incident timelines: hash-chained receipts as SOC evidence."
11. "Don't build your SOC out of LLM agents: second-order prompt injection."
12. "Open standards beat lock-in in agent security."

---

## 15. Metrics

- **Pre-revenue:** buyer interviews, receipt/rule-spec feedback, GitHub stars, demo calls, design partners.
- **Product-led:** verified high-risk actions, approve-then-swap blocks, provenance escalations, receipts exported, **incidents correlated, mean-time-to-contain, % provable timelines**, layer-on adapter installs.
- **Sales:** qualified opps (compliance-driven), pilot→paid, ACV, cycle length, MRR.
- **Outcome:** % high-risk actions with verifiable receipt; mean approval response time; time-to-Article-14-evidence; MTTD/MTTC for agent incidents.

---

## 16. GTM risks & mitigations

| Risk | Mitigation |
|---|---|
| "Another agent security tool" fatigue | Refuse platform framing; one sharp claim (provable approvals + provenance + the SOC that proves it); demo-led |
| Free Microsoft OSS | Be neutral + better at integrity; ship layer-on adapter *for* it; open receipt standard; the SOC is the paid surface |
| **"Isn't this just a SIEM?"** | No — integrity-anchored, agent-native, deterministic, provable; lead with the provable incident timeline + second-order-injection argument |
| Integrity primitives copied | Ship first, own the receipt + rule specs + community |
| Buyer education cost | Tie to Article 14 deadline; lead with approve-then-swap + provable-timeline demos |
| MCP volatility | Support MCP and non-MCP tool calls |

---

## 17. Final GTM recommendation

Go to market as:

# **AegisAgent — the open integrity layer for AI agent actions, operated as an integrity-anchored Agent SOC**

**ICP:** compliance-pressured teams shipping mutating agents (SOC 2 / EU AI Act Article 14) with growing fleets. **Use case:** make agent approvals provable, gate on provenance, and detect/contain/prove incidents — layered onto an existing gateway. **Motion:** founder-led design partners + open-source + open receipt/rule specs + layer-on adapters. **Pricing:** free OSS core (integrity + in-proc SOC); paid = hosted ops + correlation/incidents + Active-Response + compliance evidence.

Best message:
> **Make the approval trustworthy. Trust the source, not the text. Run the SOC on the proof.**
