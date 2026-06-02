# AegisAgent — Deep Market Gap Analysis (June 2026 reset)

**Product:** AegisAgent
**Category:** Agentic AI Security / Runtime Agent Action Integrity
**Date of reset:** 2026-06-02
**Read first:** [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md) — the authoritative source of truth this document is re-anchored on.

**Core thesis (revised):** The "runtime tool-call authorization + MCP governance + approval + audit" category opened *and closed* inside ~12 months. The remaining defensible gap is not the baseline control loop — that is now commodity, and even free from Microsoft. The gap is the **integrity and provenance of the control itself**: cryptographically binding human approvals to the exact action that executes, and gating authorization on the *trust level of the content that triggered the action.*

> ⚠️ **History note.** A prior version of this document (≈2026-05-29) concluded the "Agent Action Firewall" category was largely uncontested and recommended owning it. That conclusion is retired. See §2.

---

## 1. Executive verdict

- **The problem is real and validated.** Tool-using agents are hijackable through untrusted content; the dangerous layer is the *action*. (OWASP Agentic Top 10 2026, AgentDojo, InjecAgent.)
- **The baseline category is no longer a gap.** As of June 2026, intercept → policy → allow/deny → audit → human approval is shipped by a free MIT-licensed **Microsoft Agent Governance Toolkit** (same Cedar + Rust + MCP bets), an OSS **Pipelock** firewall, and funded SaaS (**MintMCP, Operant, Peta, TrueFoundry, ConductorOne**).
- **The real gap is integrity + provenance.** Almost nobody *enforces* (a) approval bound to a frozen-action hash with a fail-closed SDK, or (b) deterministic trust-provenance gating. AegisAgent already implements both.

> **Best gap statement (internal):** The market now has many tools that *decide* whether an agent action is allowed. Few make the *decision itself trustworthy* — proof that the approved action is the executed action, and proof that an untrusted source cannot drive a privileged action. AegisAgent fills that integrity gap.

---

## 2. What changed since the last version

The previous thesis depended on: *"few combine agent identity + action-level authorization + MCP governance + approval workflow + audit evidence in a simple product."* That is now false.

| Original assumption | June 2026 reality |
|---|---|
| The combined loop is rare | Shipped by ≥6 products, incl. free OSS |
| Cedar policy-as-code is a differentiator | Microsoft toolkit ships Cedar/OPA/YAML, free |
| Rust gateway is a differentiator | Microsoft toolkit ships Rust + 4 other languages |
| "Agent action receipt" is a moat idea | Pipelock ships mediator-signed action receipts (OSS) |
| Parameter hashing in approvals is novel | Now a documented 2026 HITL best practice |
| MCP-native is a wedge | Five MCP gateways shipped at RSAC 2026 |

Conclusion: the category commoditized. Building the generic loop adds nothing. The full competitor scan and matrix live in the reassessment doc.

---

## 3. Market timing (still favorable, for the narrower wedge)

The macro tailwinds are intact and now stronger:

- **Market growth:** agentic AI security ≈ USD 1.65B (2026) → 13.52B (2032), ~42% CAGR (MarketsandMarkets); SMEs fastest-growing.
- **Regulatory pull:** EU AI Act **Article 14 (human oversight)** deadline **Aug 2, 2026**; SOC 2 / NIST AI RMF expect agent-action audit + provable sign-off. This directly rewards *approval integrity* and *verifiable receipts* — AegisAgent's wedge — over generic blocking.
- **Standard unsettled:** arXiv:2603.20953 (Mar 2026) states no security-grade authorization standard exists at the tool-call boundary. Products proliferate; the *trustworthy primitive* is still up for grabs.

Timing favors a focused integrity layer even though it no longer favors a new generalist gateway.

---

## 4. Where AegisAgent fits now

```text
NOT competing as:           the gateway / the platform / the SIEM / the network firewall
Competing as:               the approval-integrity + trust-provenance decision point
Runs:                       standalone OR alongside any gateway (MSFT toolkit, Pipelock, MintMCP, ...)
Inputs it uniquely binds:   frozen-action SHA-256 hash  +  6-level content trust provenance
Outputs:                    fail-closed enforcement at the SDK + verifiable action receipt
```

AegisAgent is deliberately *layerable*. The go-to-market is interop ("add integrity to the gateway you already run"), not displacement.

---

## 5. The real gaps AegisAgent owns

### Gap A — Approval integrity (TOCTOU on human-in-the-loop)

The field logs a parameter hash but rarely binds the human decision to the exact executed action, leaving:

- **approve-then-swap** (benign action approved, mutated action executes),
- **render-vs-bytes** mismatch (approver sees friendly text, different bytes run),
- **replay** (old approval reused).

**AegisAgent:** freeze action → SHA-256 → bind approval to that hash → edits force re-evaluation → SDK **fails closed** on hash mismatch. *An approval is valid for exactly one action.*

```cedar
@decision("require_approval")
@approver_group("platform-lead")
permit (
    principal == Agent::"coding-agent-prod",
    action == Action::"merge_pull_request",
    resource == Repository::"payments-service/main"
)
when {
    principal.source_trust == "untrusted_external"
};
// On approval, the gateway binds approver + decision + SHA-256(frozen action).
// The SDK refuses to execute any action whose hash != approved hash.
```

### Gap B — Trust-provenance gating (deterministic, not probabilistic)

Most injection defenses score *text*. The confused-deputy attack only needs untrusted content to *reach* a privileged action.

**AegisAgent:** classify the *origin* of the triggering content into six trust levels and make it a first-class Cedar policy input. A mutating action triggered by `untrusted_external` is denied/escalated regardless of how benign the text looks. **Trust the source, not the text.**

### Gap C — Vendor-neutral, self-hostable, framework-agnostic

Free option is a Microsoft ecosystem play; strong commercial options are SaaS with lock-in. A neutral, self-hostable, single-Rust-binary control that runs inside the customer's trust boundary is the adoption wedge for security buyers who will not route production tool calls through a third-party cloud.

---

## 6. Competitive landscape (summarized; full matrix in reassessment doc)

| Segment | Representative players (June 2026) | What they own | Why AegisAgent is not them |
|---|---|---|---|
| Free OSS toolkit | **Microsoft Agent Governance Toolkit** | The whole baseline loop, free, MIT | Ecosystem-bound; does not enforce frozen-action approval binding or deterministic provenance gating |
| OSS agent firewall | **Pipelock** | Egress/DLP/SSRF + signed receipts | Network-egress focus; not Cedar action-authz + TOCTOU-safe approvals |
| Commercial MCP gateways | **MintMCP, Operant, TrueFoundry, Peta** | Turnkey gateway, RBAC, audit, SOC 2 | SaaS lock-in; integrity primitives are not the product |
| Identity governance | **ConductorOne, Orchid, Entra Agent ID** | Who the agent is, JIT access | Knows identity, not whether *this* approval is bound to *this* action |
| Broad AI platforms | **Palo Alto, Check Point (Lakera), Cisco** | Inline enforcement, posture | Heavy; not a neutral, self-hostable integrity primitive |

---

## 7. Beachhead and demo

**Beachhead:** teams putting mutating, high-blast-radius agent actions into production (merge/deploy/IAM/refund/data-export), especially under SOC 2 / EU AI Act Article 14.

**Killer demo (integrity framing):**

```text
1. Malicious GitHub issue tries to hijack a coding agent into merging unsafe code / reading secrets.
2. AegisAgent classifies the trigger as untrusted_external  -> require_approval (deterministic, not a text score).
3. The exact action is frozen + SHA-256 hashed; approval is bound to that hash.
4. Attacker attempts approve-then-swap: a different action is submitted under the approval.
5. SDK fails closed (hash mismatch). Nothing executes.
6. A verifiable action receipt is emitted (who/what/source-trust/approver/hash) -> SOC 2 / Art.14 evidence.
```

This demo teaches the two things competitors don't show: *provable approval* and *provenance-driven denial.*

---

## 8. Pricing (reframed by free Microsoft OSS)

The free Microsoft toolkit resets the floor. Pricing must reflect that the OSS core is genuinely better at the integrity primitives, and that paid value is operations + evidence, not the basic loop.

| Plan | Price | Value (not "the loop" — the integrity + evidence around it) |
|---|---|---|
| OSS Core | Free | Self-hosted gateway, Cedar policies, frozen-action approval binding, trust-provenance gating, local receipts |
| Team | $99–$299/mo | Hosted approvals (Slack/Teams), receipt retention, policy library |
| Startup | $499–$999/mo | Multi-tenant, SSO, SIEM/OTel export, SOC 2 evidence packs |
| Enterprise | $10K+/yr | Air-gapped/self-hosted support, Art.14 evidence reporting, long retention, SLAs |

---

## 9. Strategic moat (realistic)

This is a **feature-grade** differentiator that must be defended by being *first, correct, neutral, and open*:

1. **Verifiable action-receipt format** — publish an open spec; become the interoperable evidence standard the way Sigstore did for signing.
2. **Integrity primitives done right** — TOCTOU-safe approval binding and deterministic provenance gating, hardened and benchmarked (AgentDojo/InjecAgent for the provenance side).
3. **Layerability** — adapters so AegisAgent adds integrity *on top of* existing gateways, including Microsoft's. Distribution through complementarity, not displacement.
4. **Neutrality** — the un-lock-in option for security teams.

Honest caveat: a funded incumbent could copy frozen-action binding in a quarter. Defensibility = speed + correctness + an open receipt standard + community, not secrecy.

---

## 10. Key risks

| Risk | Mitigation |
|---|---|
| Microsoft (free) bundles everything | Be the neutral, layerable integrity primitive; integrate *with* the toolkit |
| Integrity primitives get copied | Ship first, publish the receipt spec, win the standard + community |
| Buyer education cost ("TOCTOU on approvals"?) | Lead with the GitHub-issue approve-then-swap demo |
| Category fatigue / "another agent security tool" | Refuse the platform framing; one sharp claim: *provable approvals + provenance* |

---

## 11. Final recommendation

Do **not** build or market AegisAgent as the action-firewall category or an AI security platform. Build it as:

> **AegisAgent — the open, neutral integrity layer for AI agent actions: provably-correct human approvals (frozen-action hashing, fail-closed SDK) and deterministic trust-provenance gating.**

**First MVP focus:** harden the two integrity primitives + ship a verifiable action-receipt format + one layer-on adapter. **First ICP:** SOC 2 / EU-AI-Act-driven teams shipping mutating production agent actions. **First demo:** malicious-GitHub-issue → provenance denial → approve-then-swap blocked by hash mismatch → verifiable receipt.
