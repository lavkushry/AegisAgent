# AegisAgent — Vision Document (June 2026 reset)

**Document type:** Vision
**Product:** AegisAgent
**Version:** v0.2 (re-anchored)
**Owner:** Lavkush Kumar
**Date:** 2026-06-02
**Read first:** [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md)

> ⚠️ **Reset note.** The original vision aimed to "become the runtime control plane / category leader / default gateway for AI agents." By June 2026 that category is occupied (free Microsoft toolkit + OSS + funded SaaS). This vision is re-anchored on a sharper, defensible ambition: **become the open standard for *trustworthy* agent-action control** — provable approvals and provenance-aware authorization — that layers onto whatever gateway a team already runs.

---

## 1. Vision statement

> **A human approval of an agent action should mean exactly what it says, and an untrusted source should never be able to drive a privileged action.**

The industry solved the easy half in 2025–2026: a market of gateways can now *decide* whether an agent action is allowed. AegisAgent exists to make those decisions **trustworthy** — to close the gap between "a control exists" and "the control provably holds."

---

## 2. Short, memorable vision

> **Make the approval trustworthy. Trust the source, not the text.**

The chatbot era secured prompts. The 2026 agent era secured *the decision loop.* The next step is securing the *integrity* of that loop: proving the approved action is the executed action, and gating on where the instruction came from.

---

## 3. North star

> **Every high-risk agent action carries cryptographic proof that the exact action a human approved is the action that executed — and a record of whether its trigger was trusted.**

```text
Agent wants to act
→ classify the trigger's source trust (deterministic)
→ evaluate policy with source_trust + action_hash as inputs
→ if approval needed: freeze the EXACT action, hash it, bind the human decision to that hash
→ SDK executes only if about-to-run hash == approved hash, else FAIL CLOSED
→ emit a verifiable action receipt (evidence)
```

This flow is automatic, framework-neutral, self-hostable, and layerable onto any existing gateway.

---

## 4. The world AegisAgent wants to create

A world where teams deploy mutating agents because every high-risk action is:

- **Provable** — the approved action == the executed action, demonstrably.
- **Provenance-aware** — untrusted-origin content cannot silently drive privileged actions.
- **Tamper-evident** — every decision yields a verifiable receipt an auditor accepts.
- **Open** — the receipt and policy formats are public standards, not vendor lock-in.
- **Neutral** — runs inside the customer's trust boundary, with or without a third-party gateway.

Teams should not choose between *AI productivity* and *control they can prove*.

---

## 5. The core belief

> **AI-agent security is not mainly a model problem, and — as of 2026 — no longer mainly a "does a control exist" problem. It is an integrity problem: can you prove the control held?**

A gateway that returns `allow`/`deny`/`require_approval` is necessary but not sufficient. Two failure modes survive it:

1. **Approval manipulation (TOCTOU):** approve-then-swap, replay, render-vs-bytes — the gate gives *false assurance*.
2. **Confused deputy:** untrusted content reaches a privileged action; the text looks benign, so text-scoring defenses pass it.

AegisAgent is built to close exactly these two.

---

## 6. Product philosophy

- **Integrity at the last step.** The SDK is in the trust boundary; it refuses to execute any action whose hash isn't the approved one. Decisions made upstream are not enough.
- **Deterministic over probabilistic where it matters.** Source-trust is a deterministic policy input; classifiers may *tighten* but never *loosen* it.
- **Open standards over lock-in.** Publish the action-receipt and policy primitives; win by interoperability.
- **Neutral and self-hostable.** Security teams must be able to run it inside their own boundary.
- **Layer, don't displace.** AegisAgent adds integrity to the gateway you already run (including Microsoft's toolkit).
- **Humans approve risk, not routine.** Risk-based gating to avoid alert fatigue.
- **Developer experience is adoption.** Clean SDKs, readable Cedar policies, local dry-run, fail-closed by default.

---

## 7. Strategic phases (re-anchored)

### Phase 1 — Own the integrity primitives
Frozen-action approval binding (`action_hash`) + fail-closed SDK; 6-level trust-provenance gate; verifiable action receipts; one layer-on adapter. Prove the approve-then-swap and confused-deputy bypasses are closed.

### Phase 2 — Become the open evidence standard
Publish the verifiable action-receipt spec; adapters for the major gateways (Microsoft toolkit, MintMCP, Operant, Pipelock); SOC 2 / EU AI Act Article 14 evidence packs. Aim to be the *interoperable* integrity/receipt layer the way Sigstore became for signing.

### Phase 3 — Extend integrity to memory, RAG, and multi-agent
Provenance + receipts for memory writes and RAG ingestion (AgentPoison/PoisonedRAG class); multi-agent delegation chains where each hop carries provenance and bound approvals.

> Note: this is deliberately *not* "become the everything platform." The ambition is depth and standardization on integrity, not breadth.

---

## 8. Category vision (realistic)

AegisAgent does not try to own "Agentic Runtime Security" — that's crowded. It defines a sub-layer:

> **Agent Action Integrity** — the layer that makes agent-action controls provable and provenance-aware.

```text
Identity governance      knows WHO the agent is.
Gateways                 decide IF an action is allowed.
Egress firewalls         control WHERE traffic goes.
AegisAgent               proves the decision HELD, and gates on the source.
```

The win condition is becoming the **open standard for verifiable agent-action approvals and receipts**, adopted across gateways — not being the gateway.

---

## 9. Ideal future UX

**AI engineer:** installs the SDK, writes a few Cedar policies referencing `source_trust` and approval rules; fail-closed integrity is automatic.

**Security engineer:** sees pending approvals each showing the canonical action, its `action_hash`, and its source-trust label; knows a "yes" binds to exactly that action.

**Approver (Slack):** approves a signed request; an attempted swap afterward simply doesn't execute.

**Auditor / CTO:** exports verifiable action receipts proving human oversight for Article 14 / SOC 2 — chain-of-custody, not just logs.

---

## 10. What AegisAgent should NOT become

A SIEM, DLP, network egress firewall, model-scanning tool, red-team platform, identity lifecycle manager, or "the everything AI security platform." It integrates with those. Its sharpness *is* its strategy.

---

## 11. Strategic differentiation

| Generic 2026 gateway | AegisAgent |
|---|---|
| Decides allow/deny/approve | Proves the approved action == executed action |
| Scores text for injection | Gates deterministically on source provenance |
| Logs events | Emits verifiable, exportable receipts |
| SaaS or ecosystem-bound | Open, neutral, self-hostable, layerable |

> **AegisAgent doesn't just decide what agents may do. It proves the decision was honored, and refuses to let untrusted sources drive it.**

---

## 12. Honest vision risks

| Risk | Mitigation |
|---|---|
| Integrity primitives get copied by a funded/free incumbent | Be first + correct + open standard + community; defensibility is speed and trust, not secrecy |
| Buyer doesn't understand "TOCTOU on approvals" | Lead with the approve-then-swap demo; tie to Article 14 |
| Free Microsoft OSS resets pricing floor | OSS core must be genuinely better at integrity; monetize ops + evidence |
| Too narrow to be a company | Acceptable outcome: a respected open standard + reference implementation; venture upside only if the standard spreads |

---

## 13. Mission

> **Make autonomous agent actions *provably* safe — not just decided-upon.**

If AegisAgent succeeds, teams stop asking "does our gateway block bad actions?" and start asking "can we *prove* every high-risk action was the one a human approved, from a trusted source?" — and AegisAgent is how they answer yes.

---

## 14. Internal mantra

> **A control you can't prove held is a control you don't have. Make the approval trustworthy; trust the source, not the text.**
