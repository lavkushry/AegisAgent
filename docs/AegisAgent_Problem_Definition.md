# AegisAgent — In-Depth Problem Definition (June 2026 reset)

**Document type:** Problem Definition
**Product:** AegisAgent
**Category:** Agentic AI Security / Runtime Agent Action Integrity → Integrity-anchored Agent SOC
**Version:** v0.3 (re-anchored on the integrity-anchored Agent SOC)
**Date:** 2026-06-05
**Read first:** [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md) · **Architecture:** [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md)

---

## 1. Executive summary

AI agents now reason, plan, use tools, hold memory, and take real actions across company systems. The danger is no longer "the model says something wrong" — it is "the agent *does* something wrong, or under manipulated context, or under an approval that doesn't actually constrain it."

The original framing of this problem — *companies lack a runtime control plane to authorize, approve, and audit agent actions* — is **correct but no longer unmet.** By June 2026 the baseline control plane is shipped by multiple products, including a free Microsoft toolkit (see reassessment doc §2). The problem that remains **unsolved** is narrower and sharper, and it has two faces:

> **(a) The controls that exist do not prove their own correctness.** A human approval is rarely bound to the exact action that executes (a time-of-check/time-of-use gap), and authorization rarely accounts for *where the triggering instruction came from* (the confused-deputy / indirect-prompt-injection gap).
>
> **(b) There is no SOC that operates on that proof.** Even teams that adopt a gateway have no way to *detect, correlate, and respond* to agent threats on **provable** evidence. The tools they reach for — generic SIEMs — detect by **scoring text and scraping logs**, which fails for agents for the *same* reason prompt-injection classifiers fail: the signal isn't in the text, it's in the **provenance** and the **integrity of the decision**.

Teams can now *decide* about agent actions; they cannot yet *prove* the decision was honored, *that an untrusted source did not drive it*, or *operate a SOC that detects and contains on that proof.* AegisAgent exists to close that integrity gap — and to run the SOC anchored on it.

---

## 2. One-line problem statement

> **AI agents can act on production systems, and a market of gateways can now allow/deny/approve those actions — but the approvals are not cryptographically bound to the executed action, authorization is not gated on the trust level of the content that triggered it, and there is no SOC that detects or responds to agent threats on provable evidence. The control is decidable but not provable, injection-blind at the policy layer, and unmonitored on anything but text-scoring logs.**

---

## 3. Problem context

Security teams built controls for humans, services, API tokens, and cloud workloads. The AI agent is a new autonomous actor that interprets language, pulls external context, chooses tools dynamically, remembers, plans multi-step, and reacts to untrusted content. OWASP's Agentic guidance enumerates direct/indirect prompt injection, tool abuse, privilege escalation, data exfiltration, memory poisoning, goal hijacking, excessive autonomy, high-impact action abuse, **approval manipulation**, cascading failures, and supply-chain attacks.

Two of those — **approval manipulation** and **indirect prompt injection driving tool calls** — are exactly where the current generation of products is weakest, because they shipped the *decision loop* but not the *integrity of the decision.* And once an organization runs more than a handful of agents, a third problem appears: **there is no operations plane** — no SOC — to watch the fleet, correlate an attack across a multi-step run, alert, and contain. The SOCs that exist were built for endpoints and logs, not for autonomous agents whose risk lives in provenance and approval integrity.

---

## 4. The painful problem (sharpened)

Teams deploying mutating agents cannot confidently answer:

```text
When a human approved an action, did the agent execute THAT action — byte for byte — or something it swapped in afterward?
Can an old approval be replayed for a new action?
Did the approver see the same thing that actually ran, or a friendlier rendering?
Was this privileged action triggered by trusted internal intent, or by untrusted external content (a GitHub issue, an email, a support ticket)?
Across a whole agent run, can we DETECT the chain — untrusted input → sensitive read → external write — as one incident, not five disconnected logs?
When an agent goes rogue, can we CONTAIN it (freeze/revoke) in real time?
Can we PROVE all of the above to an auditor after the fact, with a tamper-evident timeline?
```

A gateway that returns `allow` / `deny` / `require_approval` answers none of these. The risk path is:

```text
untrusted content (or post-approval mutation)
  -> agent reasoning
  -> a tool call the approval never actually authorized
  -> real-world action
  -> data leak / outage / fraud / compliance failure
  -> (and no SOC notices it as a correlated incident, because the logs look benign)
```

---

## 5. Who has this problem?

Same personas as before — security engineers, platform/DevOps leads, CTO/VP Eng, AI engineers, and regulated companies — but the **acute** version of the pain now belongs to teams that have *already adopted a gateway* and discovered (a) it doesn't make their approvals trustworthy, and (b) they have no SOC that can watch or prove what their agents do:

- **AI-native startups** shipping mutating agents fast, now asked by enterprise buyers for SOC 2 evidence.
- **SaaS teams** whose internal agents touch source code, billing, customer data.
- **Platform/SRE teams** allowing agents near merge/deploy/IAM — who need a fleet view and a containment switch.
- **Security/SOC teams** who must *detect, respond to,* and *prove* human oversight (EU AI Act Article 14, Aug 2 2026) — and who are being handed agents their existing SIEM can't meaningfully monitor.
- **Regulated companies** (fintech, healthcare, legal) who need chain-of-custody, not just logs.

---

## 6. Primary personas (jobs-to-be-done, re-anchored)

| Persona | Job | The integrity-specific pain |
|---|---|---|
| Security Engineer | Approve agents safely | Needs proof the approved action == executed action, and that untrusted content can't drive privileged calls |
| **SOC Analyst** | Monitor & respond to the agent fleet | Has no provenance-aware detection, no provable incident timeline, no real-time containment — only a SIEM that scores text |
| Platform/SRE Lead | Enable safe automation | Low-risk auto, high-risk **provably** gated; no approve-then-swap; a freeze switch when an agent misbehaves |
| CTO / VP Eng | Adopt agents without unacceptable risk | Enterprise/regulators ask for *evidence* and *monitoring*, not "we have a gateway" |
| AI Engineer | Ship agents to prod | Wants an SDK that fails closed automatically, not bespoke approval glue |
| Compliance/Auditor | Demonstrate Article 14 / SOC 2 | Needs tamper-evident receipts binding approver + action + source trust, and a verifiable incident record |

---

## 7. Pain analysis (the gaps current products leave)

### 7.1 Approval integrity (the headline gap)

Current gateways pause and ask a human, then resume. Few bind the human's "yes" to a **frozen, hashed** representation of the exact action, and fewer have an SDK that **refuses to execute** a different action. This leaves approve-then-swap, replay, and render-vs-bytes attacks open. OWASP names this class "approval manipulation." 2026 HITL guides recommend storing a parameter hash — recommendation, not enforcement.

### 7.2 Trust-provenance blindness (the second gap)

Indirect prompt injection (AgentDojo, InjecAgent) hijacks agents via untrusted tool output. Most defenses *score the text*. The deterministic question — "did this privileged action originate from untrusted content?" — is rarely a first-class authorization input. A confused deputy with perfectly benign-looking text sails through.

### 7.3 No SOC anchored on provable evidence (the operational gap)

Even with a gateway, there is no operations plane that detects and responds to agent threats on **evidence that can be trusted**. Teams fall back to generic SIEMs, which:
- **detect by scoring text / scraping logs** — the exact approach that fails for indirect injection (the signal is provenance, not text);
- have **no notion of approval integrity** — they can't tell an approve-then-swap from a normal approval;
- produce **logs, not proof** — an incident timeline that an adversary (or a bug) could have altered;
- and if they bolt on LLM "analyst agents," those agents *read the attacker's content*, recreating the very injection threat inside the SOC.

The missing product is a SOC whose detections are **deterministic**, whose evidence is **tamper-evident**, and whose only reasoning LLM merely **narrates closed incidents** — i.e., a SOC built *on* the integrity primitives.

### 7.4 Still-real supporting pains (now commodity to address, but required)

Agent inventory, over-permissioned agents, runtime authorization, MCP attack surface, weak auditability, memory/RAG poisoning. These remain real, but the market now addresses them adequately; AegisAgent treats them as **table stakes**, not differentiators.

---

## 8. Why current solutions are insufficient

| Current control | Why it doesn't close the integrity / monitoring gap |
|---|---|
| System prompts | Not a security boundary; injection bypasses them |
| Static tool allowlists | Too coarse; "allow GitHub" ≠ "merge to main under untrusted trigger" |
| **Gateways (MSFT toolkit, MintMCP, Operant, Peta, ...)** | Decide allow/deny/approve, but approval is not bound to executed action; provenance is scored, not deterministically gated; no fleet-level detection/response |
| Egress firewalls (Pipelock) | Network/DLP layer; not Cedar action-authz or TOCTOU-safe approvals |
| Identity governance (ConductorOne/Entra) | Knows *who* the agent is, not whether *this* approval constrains *this* action |
| Prompt-injection classifiers | Probabilistic, evadable; don't answer "what was the source of this action?" |
| **Generic SIEM / SOC / logs** | After the fact; detect by **text-scoring/log-scraping** (fails for the same reason classifiers do); no provenance, no approval-integrity awareness; produce **logs, not provable timelines**; LLM "analysts" read attacker content |

The fragmentation isn't "no one does authorization" anymore — it's "no one makes the authorization *provably honored*, *provenance-aware*, and *operable as a SOC on that proof*."

---

## 9. Why now

1. **Agents are in production with write access** — the blast radius is real.
2. **Gateways are adopted but shallow** — teams now feel the *integrity* and *monitoring* gaps because they cleared the *decision* gap.
3. **Fleets are growing** — once a team runs dozens of agents, the absence of a SOC (detect/correlate/contain) becomes operationally acute.
4. **Regulation rewards proof** — EU AI Act Article 14 (Aug 2 2026), SOC 2, NIST AI RMF want demonstrable, tamper-evident human oversight *and* monitoring.
5. **The standard is unsettled** — arXiv:2603.20953 (Mar 2026): no security-grade authorization standard at the tool-call boundary. A verifiable approval/receipt primitive — and a SOC that consumes it — can become that standard.

---

## 10. What happens if unsolved

- Approve-then-swap and confused-deputy incidents that *passed* an approval gate (worse than no gate — false assurance).
- Incidents that unfold across a multi-step run and are **never correlated**, because each log line looks benign in isolation.
- No containment: a hijacked agent keeps acting because there is no freeze/revoke switch wired to detection.
- Audit failures: "you have logs, but can you prove the approved action is the one that ran, and show the incident timeline?" — no.
- Duplicated, inconsistent home-grown approval glue and ad-hoc dashboards per team.
- Erosion of trust in human-in-the-loop as a control, slowing agent adoption.

---

## 11. Problem boundaries

**In scope:** approval-integrity (frozen-action hashing, fail-closed SDK), deterministic trust-provenance gating, verifiable hash-chained action receipts, Cedar policy primitives for both, MCP + non-MCP tool calls, multi-tenant isolation, the supporting baseline (inventory/authz/audit) at table-stakes quality, **an integrity-anchored Agent SOC** (async detection, correlation, alerting, and Active-Response on the receipt/provenance spine), neutral self-hostable deployment.

**Out of scope:** a **generic** SIEM / DLP / network egress firewall / model scanning / red-team platform / generic chatbot moderation / identity lifecycle management (integrate, don't replace). The line: we run a SOC, but an **integrity-anchored** one — detections ride verifiable evidence and deterministic provenance; we do not ingest arbitrary logs or score text to decide.

---

## 12. Strongest initial wedge

> **Provably-correct human approval + injection-resistant (provenance-gated) authorization for mutating agent actions — open, self-hostable, and layerable onto any existing gateway — operated through a SOC that can *prove* every agent action.**

Why strong: concrete, demonstrable (approve-then-swap demo + a provable incident timeline), regulation-aligned (Art.14/SOC 2), not yet owned by incumbents, and already built in AegisAgent (`action_hash` + 6-level trust model + hash-chained receipts). The SOC is the daily-use surface that makes the wedge sticky.

---

## 13. Example scenario (re-anchored)

A coding agent reads a malicious GitHub issue instructing it to merge a PR that disables auth checks and to "mark it urgent so the user approves."

**Without AegisAgent:** a gateway may pause for approval; a hurried approver says yes; the agent then executes a slightly different, more dangerous action, or the approval is for friendly-looking text masking dangerous bytes. The gate gave *false assurance* — and no SOC correlates the issue-read with the merge attempt.

**With AegisAgent:**
```text
Trigger source classified: untrusted_external (deterministic) -> require_approval
Exact action frozen + SHA-256 hashed; approval bound to that hash
Approver sees the canonical action + its source-trust label
Agent attempts a swapped action -> SDK hash mismatch -> FAIL CLOSED, nothing runs
Verifiable, hash-chained action receipt emitted (agent, user, tool, resource, source_trust, decision, approver, action_hash, ts)
-- and asynchronously, in the SOC --
Detection AEG-1002 (confused-deputy-mutation) fires on the untrusted+mutate event
Correlation links issue-read -> merge-attempt as ONE incident, severity high
Incident timeline is provable (each row carries its receipt_hash)
Active Response: agent approval-gated / frozen if it re-offends; Slack alert to #agent-security
RCA narrator (sandboxed LLM) drafts the human-readable post-incident summary
```

---

## 14. Validation hypotheses (updated)

1. Teams that already run a gateway will pay for *provable* approvals and provenance gating once shown an approve-then-swap / confused-deputy bypass of their current setup.
2. SOC 2 / EU AI Act buyers value a verifiable action-receipt artifact — and a **provable incident timeline** — over generic logs.
3. Security teams prefer a neutral, self-hostable integrity layer (and SOC) over routing prod tool calls through a vendor cloud.
4. An open receipt format + layer-on adapters + a SOC console drive adoption faster than a standalone gateway would.
5. Once a team has more than ~20 agents, the SOC (fleet view + correlation + containment) becomes the reason they stay.

---

## 15. Validation questions

- Does your current gateway bind the human approval to the exact executed action? Can you prove it?
- Can an agent execute a different action than the one approved? Have you tested approve-then-swap?
- Is "the source of the triggering content" a deterministic input to your authorization decision, or just a text score?
- When an attack unfolds across a multi-step run, does anything correlate it into one incident? Can you prove that timeline?
- Do you have a real-time way to **contain** a misbehaving agent (freeze/revoke), wired to detection?
- For Article 14 / SOC 2, can you produce a tamper-evident receipt linking approver → action → source trust?
- Would you route production tool calls through a third-party cloud, or do you need self-hosting?

---

## 16. Final problem definition

> **Modern AI agents take high-impact actions, and a market of gateways can now decide allow/deny/approve. But those decisions are not provably honored — human approvals are not cryptographically bound to the executed action, authorization is blind to the trust level of the content that triggered the action, and no SOC detects or responds to agent threats on provable evidence. Organizations therefore operate agents under controls that can be silently bypassed (approve-then-swap, replay, confused deputy), incidents that are never correlated, no real-time containment, and no way to prove oversight to auditors. AegisAgent provides the integrity layer and the SOC built on it: frozen-action approval binding with a fail-closed SDK, deterministic trust-provenance gating, verifiable hash-chained action receipts, and a deterministic, async detection/correlation/response plane — open, self-hostable, and layerable onto existing gateways.**

---

## 17. Internal motto

> **Make the approval trustworthy. Trust the source, not the text. Run the SOC on the proof.**
