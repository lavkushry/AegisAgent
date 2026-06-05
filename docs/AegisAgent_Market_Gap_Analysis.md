# AegisAgent — Deep Market Gap Analysis (June 2026 reset)

**Product:** AegisAgent
**Category:** Agentic AI Security / Runtime Agent Action Integrity → Integrity-anchored Agent SOC
**Date of reset:** 2026-06-02 · **Extended:** 2026-06-05 (SOC surface)
**Read first:** [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md) — the authoritative source of truth this document is re-anchored on. **SOC architecture:** [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md)

**Core thesis (revised):** The "runtime tool-call authorization + MCP governance + approval + audit" category opened *and closed* inside ~12 months. The remaining defensible gap is the **integrity and provenance of the control itself** — cryptographically binding human approvals to the exact action that executes, and gating authorization on the *trust level of the triggering content*. The **product surface** that delivers this gap is an **integrity-anchored Agent SOC** — and there is a *second*, adjacent gap there too: the SOC/SIEM tools teams reach for cannot meaningfully monitor agents (they score text and scrape logs; they have no provenance, no approval-integrity awareness, no provable timelines).

> ⚠️ **History note.** A prior version (≈2026-05-29) concluded the "Agent Action Firewall" category was largely uncontested and recommended owning it. Retired — see §2.

---

## 1. Executive verdict

- **The problem is real and validated.** Tool-using agents are hijackable through untrusted content; the dangerous layer is the *action*. (OWASP Agentic Top 10 2026, AgentDojo, InjecAgent.)
- **The baseline category is no longer a gap.** As of June 2026, intercept → policy → allow/deny → audit → approval is shipped by free MIT-licensed **Microsoft Agent Governance Toolkit**, OSS **Pipelock**, and funded SaaS (**MintMCP, Operant, Peta, TrueFoundry, ConductorOne**).
- **The real gap is integrity + provenance.** Almost nobody *enforces* (a) approval bound to a frozen-action hash with a fail-closed SDK, or (b) deterministic trust-provenance gating. AegisAgent implements both.
- **A second gap: there is no SOC that operates on that proof.** Generic SIEMs detect agents by text-scoring/log-scraping (the exact approach that fails for indirect injection), have no provenance or approval-integrity awareness, produce logs not provable timelines, and — if they bolt on LLM "analyst agents" — re-introduce prompt injection inside the SOC. **An integrity-anchored Agent SOC is uncontested.**

> **Best gap statement (internal):** The market has many tools that *decide* whether an agent action is allowed. Few make the *decision itself trustworthy*, and none operate a SOC on that trust — provenance-aware detection, provable incident timelines, SDK-enforced containment. AegisAgent fills both the integrity gap and the SOC-on-integrity gap.

---

## 2. What changed since the last version

The previous thesis depended on: *"few combine agent identity + action-level authorization + MCP governance + approval workflow + audit evidence in a simple product."* Now false.

| Original assumption | June 2026 reality |
|---|---|
| The combined loop is rare | Shipped by ≥6 products, incl. free OSS |
| Cedar policy-as-code is a differentiator | Microsoft toolkit ships Cedar/OPA/YAML, free |
| Rust gateway is a differentiator | Microsoft toolkit ships Rust + 4 other languages |
| "Agent action receipt" is a moat idea | Pipelock ships mediator-signed action receipts (OSS) |
| Parameter hashing in approvals is novel | Now a documented 2026 HITL best practice |
| MCP-native is a wedge | Five MCP gateways shipped at RSAC 2026 |
| **A SIEM can monitor agents** | **False — generic SOC tooling is provenance-blind, integrity-blind, and proof-less for agents (new gap)** |

Conclusion: the *loop* commoditized; the *integrity primitives* and an *integrity-anchored SOC* did not.

---

## 3. Market timing (favorable for the narrower wedge + its SOC)

- **Market growth:** agentic AI security ≈ USD 1.65B (2026) → 13.52B (2032), ~42% CAGR (MarketsandMarkets); SMEs fastest-growing.
- **Regulatory pull:** EU AI Act **Article 14** deadline **Aug 2, 2026**; SOC 2 / NIST AI RMF expect agent-action audit, provable sign-off, **and monitoring**. This rewards approval integrity, verifiable receipts, *and* a SOC that can prove incidents.
- **Standard unsettled:** arXiv:2603.20953 (Mar 2026): no security-grade authorization standard at the tool-call boundary. The *trustworthy primitive* — and the SOC that consumes it — is up for grabs.
- **Operational pull (new):** once a team runs dozens of agents, the absence of a fleet-level detect/correlate/contain plane becomes acute — and existing SOC tools don't fit.

---

## 4. Where AegisAgent fits now

```text
NOT competing as:           the gateway / the platform / a generic SIEM / the network firewall
Competing as:               the approval-integrity + trust-provenance decision point,
                            operated as an INTEGRITY-ANCHORED AGENT SOC
Runs:                       standalone OR alongside any gateway (MSFT toolkit, Pipelock, MintMCP, ...)
Inputs it uniquely binds:   frozen-action SHA-256 hash  +  6-level content trust provenance
Outputs:                    fail-closed enforcement at the SDK + verifiable hash-chained receipt
                            + deterministic detection/correlation/response on that receipt stream
```

AegisAgent is deliberately *layerable*. GTM is interop ("add integrity — and a SOC that proves what your agents did — to the gateway you already run"), not displacement.

---

## 5. The real gaps AegisAgent owns

### Gap A — Approval integrity (TOCTOU on human-in-the-loop)
The field logs a parameter hash but rarely binds the human decision to the exact executed action, leaving **approve-then-swap**, **render-vs-bytes**, **replay**. **AegisAgent:** freeze → SHA-256 → bind → edits force re-eval → SDK **fails closed**. *An approval is valid for exactly one action.*

```cedar
@decision("require_approval")
@approver_group("platform-lead")
permit (principal, action == Action::"tool_call", resource == ToolAction::"github_merge_pull_request")
when { context.resource_base_branch == "main" };
// On approval, the gateway binds approver + decision + SHA-256(frozen action).
// The SDK refuses to execute any action whose hash != approved hash.
```

### Gap B — Trust-provenance gating (deterministic, not probabilistic)
Most injection defenses score *text*. The confused-deputy attack only needs untrusted content to *reach* a privileged action. **AegisAgent:** classify the *origin* into six trust levels; a mutating action triggered by `untrusted_external` is denied/escalated regardless of how benign the text looks. **Trust the source, not the text.**

### Gap C — Vendor-neutral, self-hostable, framework-agnostic
Free option is a Microsoft ecosystem play; strong commercial options are SaaS lock-in. A neutral, self-hostable single-Rust-binary control inside the customer's trust boundary is the adoption wedge.

### Gap D — No SOC anchored on provable evidence (new)
Generic SIEMs/SOCs cannot monitor agents well: they score text/scrape logs (fails for injection), are blind to provenance and approval integrity, and produce logs rather than provable timelines. **AegisAgent:** a SOC whose detections are deterministic, whose evidence is the hash-chained receipt, and whose only LLM narrates closed incidents — *"the SOC that can prove what agents did."* This is the **daily-use surface** that turns the wedge into a sticky product.

---

## 6. Competitive landscape (summarized; full matrix in reassessment doc)

| Segment | Representative players (June 2026) | What they own | Why AegisAgent is not them |
|---|---|---|---|
| Free OSS toolkit | **Microsoft Agent Governance Toolkit** | The whole baseline loop, free, MIT | Ecosystem-bound; no frozen-action approval binding, no deterministic provenance gate, no integrity-anchored SOC |
| OSS agent firewall | **Pipelock** | Egress/DLP/SSRF + signed receipts | Network-egress focus; not Cedar action-authz + TOCTOU-safe approvals; no correlation/incident SOC |
| Commercial MCP gateways | **MintMCP, Operant, TrueFoundry, Peta** | Turnkey gateway, RBAC, audit, SOC 2 | SaaS lock-in; integrity primitives aren't the product; no provable-timeline SOC |
| Identity governance | **ConductorOne, Orchid, Entra Agent ID** | Who the agent is, JIT access | Knows identity, not whether *this* approval is bound to *this* action |
| Broad AI platforms | **Palo Alto, Check Point (Lakera), Cisco** | Inline enforcement, posture | Heavy; not a neutral self-hostable integrity primitive |
| **Generic SIEM/SOC/XDR** | **Splunk, Sentinel, Wazuh, Elastic** | Log collection, correlation, dashboards, SOAR | **Provenance-blind, integrity-blind; text-scoring detection; logs not proofs; not agent-native** — AegisAgent is the integrity-anchored, agent-native SOC |

---

## 7. Beachhead and demo

**Beachhead:** teams putting mutating, high-blast-radius agent actions into production (merge/deploy/IAM/refund/data-export), especially under SOC 2 / EU AI Act Article 14.

**Killer demo (integrity + SOC framing):**
```text
1. Malicious GitHub issue tries to hijack a coding agent into merging unsafe code / reading secrets.
2. AegisAgent classifies the trigger as untrusted_external -> require_approval (deterministic, not a text score).
3. The exact action is frozen + SHA-256 hashed; approval is bound to that hash.
4. Attacker attempts approve-then-swap: a different action is submitted under the approval.
5. SDK fails closed (hash mismatch). Nothing executes.
6. A verifiable, hash-chained action receipt is emitted -> SOC 2 / Art.14 evidence.
7. In the SOC: the issue-read -> merge-attempt is correlated into ONE incident with a PROVABLE timeline
   (each row carries its receipt_hash; one-click verify). Containment (freeze) is one click; RCA auto-drafted.
```

This demo teaches the three things competitors don't show: *provable approval*, *provenance-driven denial*, and a *provable incident timeline*.

---

## 8. Pricing (reframed by free Microsoft OSS; SOC adds the paid surface)

| Plan | Price | Value (not "the loop" — integrity + evidence + the SOC) |
|---|---|---|
| OSS Core | Free | Self-hosted gateway, Cedar policies, frozen-action approval binding, provenance gating, local receipts, in-proc SOC (deterministic rules + local console) |
| Team | $99–$299/mo | Hosted approvals (Slack/Teams), receipt retention, notify sink, policy/rule library |
| Startup | $499–$999/mo | Multi-tenant, SSO, SIEM/OTel export, correlation + incidents, SOC 2 evidence packs |
| Enterprise | $10K+/yr | Air-gapped support, Art.14 evidence reporting, multi-node SOC, Active-Response, long retention, SLAs |

The SOC (correlation, incidents, Active-Response, evidence packs) is the natural paid tier on top of the free integrity core.

---

## 9. Strategic moat (realistic)

A **feature-grade** differentiator defended by being *first, correct, neutral, and open*:
1. **Verifiable action-receipt format** — publish an open spec; become the interoperable evidence standard (Sigstore-for-signing analogy).
2. **Integrity primitives done right** — TOCTOU-safe approval binding + deterministic provenance gating, hardened and benchmarked (AgentDojo/InjecAgent).
3. **The integrity-anchored SOC** — detection/correlation/response that rides the receipt+provenance spine; defended by the four design laws so it cannot be commoditized into a generic SIEM.
4. **Layerability + neutrality** — adapters add integrity + SOC *on top of* existing gateways; the un-lock-in option.

Honest caveat: a funded incumbent could copy frozen-action binding in a quarter. Defensibility = speed + correctness + an open receipt standard + community + the SOC's deterministic/provable design — not secrecy.

---

## 10. Key risks

| Risk | Mitigation |
|---|---|
| Microsoft (free) bundles everything | Be the neutral, layerable integrity primitive + SOC; integrate *with* the toolkit |
| Integrity primitives get copied | Ship first, publish the receipt spec, win the standard + community |
| Buyer education cost ("TOCTOU on approvals"?) | Lead with the GitHub-issue approve-then-swap demo + provable timeline |
| Category fatigue / "another agent security tool" | Refuse the platform framing; one sharp claim: *provable approvals + provenance + the SOC that proves it* |
| **Scope creep into a generic SIEM** | Hold the four design laws; no headline feature off the receipt/provenance spine |

---

## 11. Final recommendation

Do **not** build or market AegisAgent as the action-firewall category, an AI security platform, or a generic SIEM. Build it as:

> **AegisAgent — the open, neutral integrity layer for AI agent actions, operated as an integrity-anchored Agent SOC: provably-correct human approvals (frozen-action hashing, fail-closed SDK), deterministic trust-provenance gating, verifiable receipts, and a deterministic detect/correlate/contain plane that can *prove* every agent action.**

**First MVP focus:** harden the two integrity primitives + ship a verifiable receipt format + the Phase-0 SOC event emitter + one layer-on adapter. **First ICP:** SOC 2 / EU-AI-Act-driven teams shipping mutating production agent actions. **First demo:** malicious-GitHub-issue → provenance denial → approve-then-swap blocked → verifiable receipt → provable correlated incident in the SOC.
