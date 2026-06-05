# AegisAgent — Vision Document (June 2026 reset)

**Document type:** Vision
**Product:** AegisAgent
**Version:** v0.3 (re-anchored on the integrity-anchored Agent SOC)
**Owner:** Lavkush Kumar
**Date:** 2026-06-05
**Read first:** [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md) · **Architecture:** [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md)

> ⚠️ **Reset note (two layers).** (1) The original vision aimed to "become the runtime control plane / category leader / default gateway for AI agents." By June 2026 that category is occupied (free Microsoft toolkit + OSS + funded SaaS), so the vision was re-anchored on a sharper, defensible ambition: **become the open standard for *trustworthy* agent-action control** — provable approvals and provenance-aware authorization. (2) This v0.3 adds the *product surface* that ambition is delivered through: an **integrity-anchored Agent SOC** — monitoring, detection, and response for AI agents whose differentiator is that **every alert is backed by verifiable evidence and every authorization is gated on deterministic provenance.** The moat is unchanged; the SOC is how teams consume it day-to-day. *We layer on the gateway you already run — we do not become a generic SIEM.*

---

## 1. Vision statement

> **A human approval of an agent action should mean exactly what it says, an untrusted source should never be able to drive a privileged action, and a team should be able to *prove* — not just log — what every agent did.**

The industry solved the easy half in 2025–2026: a market of gateways can now *decide* whether an agent action is allowed. AegisAgent exists to make those decisions **trustworthy** and the resulting record **provable** — to close the gap between "a control exists" and "the control provably held, and here is the evidence."

---

## 2. Short, memorable vision

> **Make the approval trustworthy. Trust the source, not the text. Prove every action.**

The chatbot era secured prompts. The 2026 agent era secured *the decision loop.* The next step is securing the *integrity* of that loop **and operating it** — proving the approved action is the executed action, gating on where the instruction came from, and turning the resulting verifiable receipts into a SOC that detects, correlates, and contains.

---

## 3. North star

> **Every high-risk agent action carries cryptographic proof that the exact action a human approved is the action that executed — a record of whether its trigger was trusted — and a tamper-evident receipt that a SOC can detect on, correlate over, and an auditor can verify.**

```text
Agent wants to act
→ classify the trigger's source trust (deterministic)
→ evaluate policy with source_trust + action_hash as inputs
→ if approval needed: freeze the EXACT action, hash it, bind the human decision to that hash
→ SDK executes only if about-to-run hash == approved hash, else FAIL CLOSED
→ emit a verifiable, hash-chained action receipt (evidence)
→ that receipt streams (async) into the Agent SOC: detect · correlate · alert · respond — without ever slowing the action path
```

This flow is automatic, framework-neutral, self-hostable, and layerable onto any existing gateway. The SOC consumes its output; it never sits in the critical path (see [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md) §4, the two-plane principle).

---

## 4. The world AegisAgent wants to create

A world where teams deploy mutating agents because every high-risk action is:

- **Provable** — the approved action == the executed action, demonstrably.
- **Provenance-aware** — untrusted-origin content cannot silently drive privileged actions.
- **Tamper-evident** — every decision yields a verifiable, hash-chained receipt an auditor accepts.
- **Observable & answerable** — a SOC can show, with cryptographic backing, *what* every agent did, *why* it was allowed, and *which* untrusted input tried to hijack it.
- **Open** — the receipt and policy formats are public standards, not vendor lock-in.
- **Neutral** — runs inside the customer's trust boundary, with or without a third-party gateway.

Teams should not choose between *AI productivity* and *control they can prove*.

---

## 5. The core belief

> **AI-agent security is not mainly a model problem, and — as of 2026 — no longer mainly a "does a control exist" problem. It is an integrity problem: can you prove the control held? And once you can, the highest-value security product is the SOC that operates on that proof.**

A gateway that returns `allow`/`deny`/`require_approval` is necessary but not sufficient. Two failure modes survive it:

1. **Approval manipulation (TOCTOU):** approve-then-swap, replay, render-vs-bytes — the gate gives *false assurance*.
2. **Confused deputy:** untrusted content reaches a privileged action; the text looks benign, so text-scoring defenses pass it.

AegisAgent is built to close exactly these two — and then to make the verifiable record they produce the **evidence spine** of a SOC, so detection and response are anchored on proof rather than on log-scraping and text scores.

---

## 6. Product philosophy

- **Integrity at the last step.** The SDK is in the trust boundary; it refuses to execute any action whose hash isn't the approved one. Decisions made upstream are not enough.
- **Deterministic over probabilistic where it matters.** Source-trust is a deterministic policy input; classifiers may *tighten* but never *loosen* it. **Detections decide deterministically; scores never gate** (Design Law 1).
- **A SOC anchored on evidence, not logs.** Alerts reference the action's `action_hash` and `receipt_hash`; incident timelines are hash-chained and therefore provable. We are not a generic log SIEM.
- **The LLM investigates; it never decides or enforces.** The only LLM in the SOC summarizes an already-closed, already-evidenced incident, sandboxed, evidence-as-data (Design Law 2). We do not fight prompt injection with more prompt-injectable surface.
- **The action path is sacred.** Detection, correlation, and response are asynchronous; nothing the SOC does adds latency to authorization (Design Law 3).
- **Open standards over lock-in.** Publish the action-receipt and policy primitives; win by interoperability.
- **Neutral and self-hostable.** Security teams must be able to run it inside their own boundary.
- **Layer, don't displace.** AegisAgent adds integrity — and an integrity-anchored SOC — onto the gateway you already run (including Microsoft's toolkit).
- **Humans approve risk, not routine.** Risk-based gating to avoid alert fatigue.
- **Developer experience is adoption.** Clean SDKs, readable Cedar policies, local dry-run, fail-closed by default.

---

## 7. Strategic phases (re-anchored)

### Phase 1 — Own the integrity primitives
Frozen-action approval binding (`action_hash`) + fail-closed SDK; 6-level trust-provenance gate; verifiable, hash-chained action receipts; one layer-on adapter. Prove the approve-then-swap and confused-deputy bypasses are closed. **(The moat — largely built.)**

### Phase 2 — Become the open evidence standard
Publish the verifiable action-receipt spec; adapters for the major gateways (Microsoft toolkit, MintMCP, Operant, Pipelock); SOC 2 / EU AI Act Article 14 evidence packs. Aim to be the *interoperable* integrity/receipt layer the way Sigstore became for signing.

### Phase 3 — The integrity-anchored Agent SOC
Turn the receipt + provenance stream into a SOC: async event emission, a **deterministic** detection/correlation engine (confused-deputy, replay, exfil-sequence, MCP drift, deny-storms), incident timelines that are provable because they are hash-chained, and an Active-Response loop (approve/freeze/revoke/quarantine). One sandboxed LLM narrates RCAs; nothing else reasons in the loop. **This is the day-to-day product surface — see [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md).**

### Phase 4 — Extend integrity to memory, RAG, and multi-agent
Provenance + receipts for memory writes and RAG ingestion (AgentPoison/PoisonedRAG class); multi-agent delegation chains where each hop carries provenance and bound approvals — and the SOC correlates across hops.

> Note: this is deliberately *not* "become the everything platform." The ambition is depth and standardization on integrity, then a SOC that is **uniquely good because it sits on that integrity** — not breadth for its own sake.

---

## 8. Category vision (realistic)

AegisAgent does not try to own "Agentic Runtime Security" — that's crowded. It defines a sub-layer, then operates it:

> **Agent Action Integrity** — the layer that makes agent-action controls provable and provenance-aware — delivered as an **integrity-anchored Agent SOC.**

```text
Identity governance      knows WHO the agent is.
Gateways                 decide IF an action is allowed.
Egress firewalls         control WHERE traffic goes.
Generic SIEMs            collect logs and score text after the fact.
AegisAgent               proves the decision HELD, gates on the source,
                         and runs the SOC that detects/responds on that proof.
```

The win condition is becoming the **open standard for verifiable agent-action approvals and receipts** — *and* the reference **integrity-anchored SOC** that consumes them — adopted across gateways, rather than being the gateway or a generic SIEM.

---

## 9. Ideal future UX

**AI engineer:** installs the SDK, writes a few Cedar policies referencing `source_trust` and approval rules; fail-closed integrity is automatic.

**Security engineer:** sees pending approvals each showing the canonical action, its `action_hash`, and its source-trust label; knows a "yes" binds to exactly that action.

**SOC analyst:** watches a live decision feed and an incident queue where every row carries a `receipt_hash` — so the timeline of "untrusted issue → attempted merge → blocked" is not just logged but **provable and tamper-evident**, with a one-click receipt-chain verify.

**Approver (Slack):** approves a signed request; an attempted swap afterward simply doesn't execute.

**Auditor / CTO:** exports verifiable action receipts proving human oversight for Article 14 / SOC 2 — chain-of-custody, not just logs.

---

## 10. What AegisAgent should NOT become

A **generic** SIEM, DLP, network egress firewall, model-scanning tool, red-team platform, identity lifecycle manager, or "the everything AI security platform." It integrates with those.

The distinction that keeps this sharp: AegisAgent **is** a SOC, but an **integrity-anchored** one. The line we hold:

| Generic SIEM/SOC (NOT us) | Integrity-anchored Agent SOC (us) |
|---|---|
| Ingests arbitrary logs | Consumes verifiable, hash-chained receipts as the evidence spine |
| Scores text for maliciousness to decide | Gates deterministically on source provenance; scores are advisory only |
| Detection reasoned by LLMs over raw content | Detection is deterministic rules; one sandboxed LLM only *narrates* closed incidents |
| Differentiates on connectors & dashboards | Differentiates on *provability* — the SOC that can prove what agents did |

If a feature would make us a better generic log-SIEM but doesn't ride on the integrity primitives, it's out of scope. **Our sharpness is still our strategy.**

---

## 11. Strategic differentiation

| Generic 2026 gateway / SIEM | AegisAgent |
|---|---|
| Decides allow/deny/approve | Proves the approved action == executed action |
| Scores text for injection | Gates deterministically on source provenance |
| Logs events | Emits verifiable, hash-chained receipts |
| SOC that collects and correlates logs | SOC that detects/correlates on **tamper-evident evidence** and can *prove* every incident |
| SaaS or ecosystem-bound | Open, neutral, self-hostable, layerable |

> **AegisAgent doesn't just decide what agents may do. It proves the decision was honored, refuses to let untrusted sources drive it, and runs the SOC that detects and contains on that proof.**

---

## 12. Honest vision risks

| Risk | Mitigation |
|---|---|
| Integrity primitives get copied by a funded/free incumbent | Be first + correct + open standard + community; defensibility is speed and trust, not secrecy |
| **Scope creep into a generic SOC/SIEM** (the trap §10 warns of) | Hold the line: every detection must ride the receipt/provenance spine; no arbitrary-log ingestion as a headline; deterministic detection only |
| Buyer doesn't understand "TOCTOU on approvals" | Lead with the approve-then-swap demo; tie to Article 14 |
| SOC adds an LLM attack surface | One sandboxed LLM, post-incident, evidence-as-data, never gating (Design Law 2) |
| Free Microsoft OSS resets pricing floor | OSS core must be genuinely better at integrity; monetize ops + evidence + the SOC |
| Too narrow to be a company | Acceptable outcome: a respected open standard + reference implementation; the integrity-anchored SOC is the venture upside if the standard spreads |

---

## 13. Mission

> **Make autonomous agent actions *provably* safe — not just decided-upon — and give security teams a SOC that operates on that proof.**

If AegisAgent succeeds, teams stop asking "does our gateway block bad actions?" and start asking "can we *prove* every high-risk action was the one a human approved, from a trusted source — and can our SOC show it?" — and AegisAgent is how they answer yes.

---

## 14. Internal mantra

> **A control you can't prove held is a control you don't have. Make the approval trustworthy; trust the source, not the text; prove every action — and run the SOC on the proof.**
