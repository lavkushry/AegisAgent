# AegisAgent — In-Depth Problem Definition (June 2026 reset)

**Document type:** Problem Definition
**Product:** AegisAgent
**Category:** Agentic AI Security / Runtime Agent Action Integrity
**Version:** v0.2 (re-anchored)
**Date:** 2026-06-02
**Read first:** [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md)

---

## 1. Executive summary

AI agents now reason, plan, use tools, hold memory, and take real actions across company systems. The danger is no longer "the model says something wrong" — it is "the agent *does* something wrong, or under manipulated context, or under an approval that doesn't actually constrain it."

The original framing of this problem — *companies lack a runtime control plane to authorize, approve, and audit agent actions* — is **correct but no longer unmet.** By June 2026 the baseline control plane is shipped by multiple products, including a free Microsoft toolkit (see reassessment doc §2). The problem that remains **unsolved** is narrower and sharper:

> **The controls that exist do not prove their own correctness.** A human approval is rarely bound to the exact action that executes (a time-of-check/time-of-use gap), and authorization rarely accounts for *where the triggering instruction came from* (the confused-deputy / indirect-prompt-injection gap). Teams can now *decide* about agent actions; they cannot yet *prove* the decision was honored or *that an untrusted source did not drive it.*

AegisAgent exists to close that integrity gap.

---

## 2. One-line problem statement

> **AI agents can act on production systems, and a market of gateways can now allow/deny/approve those actions — but the approvals are not cryptographically bound to the executed action, and authorization is not gated on the trust level of the content that triggered it. The control is decidable but not provable, and injection-blind at the policy layer.**

---

## 3. Problem context

Security teams built controls for humans, services, API tokens, and cloud workloads. The AI agent is a new autonomous actor that interprets language, pulls external context, chooses tools dynamically, remembers, plans multi-step, and reacts to untrusted content. OWASP's Agentic guidance enumerates direct/indirect prompt injection, tool abuse, privilege escalation, data exfiltration, memory poisoning, goal hijacking, excessive autonomy, high-impact action abuse, **approval manipulation**, cascading failures, and supply-chain attacks.

Two of those — **approval manipulation** and **indirect prompt injection driving tool calls** — are exactly where the current generation of products is weakest, because they shipped the *decision loop* but not the *integrity of the decision.*

---

## 4. The painful problem (sharpened)

Teams deploying mutating agents cannot confidently answer:

```text
When a human approved an action, did the agent execute THAT action — byte for byte — or something it swapped in afterward?
Can an old approval be replayed for a new action?
Did the approver see the same thing that actually ran, or a friendlier rendering?
Was this privileged action triggered by trusted internal intent, or by untrusted external content (a GitHub issue, an email, a support ticket)?
Can we PROVE all of the above to an auditor after the fact?
```

A gateway that returns `allow` / `deny` / `require_approval` does not answer these. The risk path is:

```text
untrusted content (or post-approval mutation)
  -> agent reasoning
  -> a tool call the approval never actually authorized
  -> real-world action
  -> data leak / outage / fraud / compliance failure
```

---

## 5. Who has this problem?

Same personas as before — security engineers, platform/DevOps leads, CTO/VP Eng, AI engineers, and regulated companies — but the **acute** version of the pain now belongs to teams that have *already adopted a gateway* and discovered it doesn't make their approvals trustworthy:

- **AI-native startups** shipping mutating agents fast, now asked by enterprise buyers for SOC 2 evidence.
- **SaaS teams** whose internal agents touch source code, billing, customer data.
- **Platform/SRE teams** allowing agents near merge/deploy/IAM.
- **Security teams** who must *prove* human oversight (EU AI Act Article 14, Aug 2 2026).
- **Regulated companies** (fintech, healthcare, legal) who need chain-of-custody, not just logs.

---

## 6. Primary personas (jobs-to-be-done, re-anchored)

| Persona | Job | The integrity-specific pain |
|---|---|---|
| Security Engineer | Approve agents safely | Needs proof the approved action == executed action, and that untrusted content can't drive privileged calls |
| Platform/SRE Lead | Enable safe automation | Low-risk auto, high-risk **provably** gated; no approve-then-swap |
| CTO / VP Eng | Adopt agents without unacceptable risk | Enterprise/regulators ask for *evidence*, not "we have a gateway" |
| AI Engineer | Ship agents to prod | Wants an SDK that fails closed automatically, not bespoke approval glue |
| Compliance/Auditor | Demonstrate Article 14 / SOC 2 | Needs tamper-evident receipts binding approver + action + source trust |

---

## 7. Pain analysis (the gaps current products leave)

### 7.1 Approval integrity (the headline gap)

Current gateways pause and ask a human, then resume. Few bind the human's "yes" to a **frozen, hashed** representation of the exact action, and fewer have an SDK that **refuses to execute** a different action. This leaves approve-then-swap, replay, and render-vs-bytes attacks open. OWASP names this class "approval manipulation." 2026 HITL guides recommend storing a parameter hash — recommendation, not enforcement.

### 7.2 Trust-provenance blindness (the second gap)

Indirect prompt injection (AgentDojo, InjecAgent) hijacks agents via untrusted tool output. Most defenses *score the text*. The deterministic question — "did this privileged action originate from untrusted content?" — is rarely a first-class authorization input. A confused deputy with perfectly benign-looking text sails through.

### 7.3 Still-real supporting pains (now commodity to address, but required)

Agent inventory, over-permissioned agents, runtime authorization, MCP attack surface, weak auditability, memory/RAG poisoning. These remain real, but the market now addresses them adequately; AegisAgent treats them as **table stakes**, not differentiators.

---

## 8. Why current solutions are insufficient

| Current control | Why it doesn't close the integrity gap |
|---|---|
| System prompts | Not a security boundary; injection bypasses them |
| Static tool allowlists | Too coarse; "allow GitHub" ≠ "merge to main under untrusted trigger" |
| **Gateways (MSFT toolkit, MintMCP, Operant, Peta, ...)** | Decide allow/deny/approve, but approval is not bound to executed action; provenance is scored, not deterministically gated |
| Egress firewalls (Pipelock) | Network/DLP layer; not Cedar action-authz or TOCTOU-safe approvals |
| Identity governance (ConductorOne/Entra) | Knows *who* the agent is, not whether *this* approval constrains *this* action |
| Prompt-injection classifiers | Probabilistic, evadable; don't answer "what was the source of this action?" |
| SIEM / logs | After the fact; don't prevent the unauthorized action or prove the approval bound it |

The fragmentation isn't "no one does authorization" anymore — it's "no one makes the authorization *provably honored* and *provenance-aware*."

---

## 9. Why now

1. **Agents are in production with write access** — the blast radius is real.
2. **Gateways are adopted but shallow** — teams now feel the *integrity* gap because they cleared the *decision* gap.
3. **Regulation rewards proof** — EU AI Act Article 14 (Aug 2 2026), SOC 2, NIST AI RMF want demonstrable, tamper-evident human oversight.
4. **The standard is unsettled** — arXiv:2603.20953 (Mar 2026): no security-grade authorization standard at the tool-call boundary. A verifiable approval/receipt primitive can become that standard.

---

## 10. What happens if unsolved

- Approve-then-swap and confused-deputy incidents that *passed* an approval gate (worse than no gate — false assurance).
- Audit failures: "you have logs, but can you prove the approved action is the one that ran?" — no.
- Duplicated, inconsistent home-grown approval glue per team.
- Erosion of trust in human-in-the-loop as a control, slowing agent adoption.

---

## 11. Problem boundaries

**In scope:** approval-integrity (frozen-action hashing, fail-closed SDK), deterministic trust-provenance gating, verifiable action receipts, Cedar policy primitives for both, MCP + non-MCP tool calls, multi-tenant isolation, the supporting baseline (inventory/authz/audit) at table-stakes quality, neutral self-hostable deployment.

**Out of scope:** full SIEM, full DLP, network egress firewall, model scanning, red-team platform, generic chatbot moderation, identity lifecycle management (integrate, don't replace).

---

## 12. Strongest initial wedge

> **Provably-correct human approval + injection-resistant (provenance-gated) authorization for mutating agent actions — open, self-hostable, and layerable onto any existing gateway.**

Why strong: concrete, demonstrable (approve-then-swap demo), regulation-aligned (Art.14/SOC 2), not yet owned by incumbents, and already built in AegisAgent (`action_hash` + 6-level trust model).

---

## 13. Example scenario (re-anchored)

A coding agent reads a malicious GitHub issue instructing it to merge a PR that disables auth checks and to "mark it urgent so the user approves."

**Without AegisAgent:** a gateway may pause for approval; a hurried approver says yes; the agent then executes a slightly different, more dangerous action, or the approval is for friendly-looking text masking dangerous bytes. The gate gave *false assurance.*

**With AegisAgent:**
```text
Trigger source classified: untrusted_external (deterministic) -> require_approval
Exact action frozen + SHA-256 hashed; approval bound to that hash
Approver sees the canonical action + its source-trust label
Agent attempts a swapped action -> SDK hash mismatch -> FAIL CLOSED, nothing runs
Verifiable action receipt emitted (agent, user, tool, resource, source_trust, decision, approver, action_hash, ts)
```

---

## 14. Validation hypotheses (updated)

1. Teams that already run a gateway will pay for *provable* approvals and provenance gating once shown an approve-then-swap / confused-deputy bypass of their current setup.
2. SOC 2 / EU AI Act buyers value a verifiable action-receipt artifact over generic logs.
3. Security teams prefer a neutral, self-hostable integrity layer over routing prod tool calls through a vendor cloud.
4. An open receipt format + layer-on adapters drive adoption faster than a standalone gateway would.

---

## 15. Validation questions

- Does your current gateway bind the human approval to the exact executed action? Can you prove it?
- Can an agent execute a different action than the one approved? Have you tested approve-then-swap?
- Is "the source of the triggering content" a deterministic input to your authorization decision, or just a text score?
- For Article 14 / SOC 2, can you produce a tamper-evident receipt linking approver → action → source trust?
- Would you route production tool calls through a third-party cloud, or do you need self-hosting?

---

## 16. Final problem definition

> **Modern AI agents take high-impact actions, and a market of gateways can now decide allow/deny/approve. But those decisions are not provably honored — human approvals are not cryptographically bound to the executed action, and authorization is blind to the trust level of the content that triggered the action. Organizations therefore operate agents under controls that can be silently bypassed (approve-then-swap, replay, confused deputy) and cannot prove oversight to auditors. AegisAgent provides the integrity layer: frozen-action approval binding with a fail-closed SDK, deterministic trust-provenance gating, and verifiable action receipts — open, self-hostable, and layerable onto existing gateways.**

---

## 17. Internal motto

> **Make the approval trustworthy. Trust the source, not the text.**
