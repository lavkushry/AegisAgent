# AegisAgent (fka AgentGuard): Agent Action Integrity Layer → Integrity-anchored Agent SOC — Product Research

**Author:** Lavkush Kumar
**Original draft:** 2026-05-29 · **Reset:** 2026-06-02 · **Extended:** 2026-06-05 (SOC surface)
**Working title:** AegisAgent — Integrity Layer for AI Agent Actions, operated as an Agent SOC
**Read first:** [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md) · **SOC architecture:** [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md)

> ⚠️ **Reset note (two layers).** The original draft positioned this as an "MCP and tool-use firewall." By June 2026 that wedge is occupied (free Microsoft toolkit + OSS Pipelock + funded SaaS), so it re-anchored on the **integrity + provenance** gap. v0.3 adds the **product surface**: an **integrity-anchored Agent SOC** that consumes the receipt+provenance stream (detect → correlate → contain → prove). The §4 research matrix remains valid; §4 adds the SOC's detection-taxonomy sources.

---

## 1. Executive summary

AegisAgent is the **integrity layer for AI agent actions, delivered as an integrity-anchored Agent SOC.** The baseline runtime-authorization loop (intercept → policy → allow/deny → audit → approval) is now commodity. AegisAgent's reason to exist is the two things that loop doesn't guarantee — plus the SOC that operates on them:

1. **Approval integrity** — the human "yes" is cryptographically bound to a frozen, hashed representation of the exact action; the SDK fails closed if a different action would execute (defends approve-then-swap, replay, render-vs-bytes).
2. **Trust-provenance gating** — authorization is gated deterministically on *where the triggering content came from* (six trust levels), not a probabilistic text score (defends confused-deputy / indirect injection).
3. **The SOC on top** — every verifiable receipt streams (async) into a deterministic detect/correlate/contain plane whose alerts are backed by tamper-evident evidence: *"the SOC that can prove what agents did."*

Plus adoption properties: **open, self-hostable, framework-neutral, layerable onto any existing gateway.**

---

## 2. Product idea

### 2.1 Name & one-liner
**AegisAgent.**
> The open, neutral integrity layer for AI agent actions — provably-correct human approvals and deterministic trust-provenance gating, with verifiable receipts — operated as an integrity-anchored Agent SOC.

### 2.2 Target users
**Buyer:** Head of Security / AI Platform Lead / VP Eng at teams shipping mutating agents, especially under SOC 2 or EU AI Act Article 14.
**ICP:** teams that *already run or plan* a gateway and need the integrity + evidence + monitoring it doesn't provide; regulated SaaS; security-conscious AI-native startups with a growing agent fleet.

### 2.3 The questions AegisAgent uniquely answers
```text
Did the agent execute the exact action a human approved? (prove it)
Can an old approval be replayed, or a benign one swapped for a dangerous one?
Did this privileged action originate from untrusted content?
Across a multi-step run, is the attack correlated into one provable incident?
Can we contain a misbehaving agent (freeze/revoke) in real time?
Can we hand an auditor a tamper-evident receipt + provable incident timeline?
```
Gateways answer "is it allowed?" AegisAgent answers "is the decision provably honored, provenance-aware, and operable as a SOC?"

---

## 3. Product modules (re-prioritized)

### 3.1 Approval Integrity Engine — **headline (moat #1)**
- Freeze the exact tool call (canonical serialization) → `action_hash = SHA-256(canonical_action)`.
- Bind the approval to `action_hash` + approver + decision + timestamp; **single-use** (atomic consume).
- Re-evaluate on any edit. SDK **fails closed** on mismatch/expiry/replay/un-consumable.

### 3.2 Trust-Provenance Gate — **headline (moat #2)**
- Six deterministic trust levels as first-class Cedar context. Mutating + untrusted/suspected → deny/escalate, independent of text. Classifiers tighten, never loosen.

### 3.3 Verifiable Action Receipts — **headline (moat #3) + SOC evidence spine**
- Tamper-evident, **hash-chained** record; open format; SOC 2 / Art.14 evidence; the SOC's immutable cold tier.

### 3.4 Cedar policy-as-code (table stakes) — `action_hash` + `source_trust` native context.
### 3.5 MCP + non-MCP authorization (table stakes) — manifest pinning/drift as a provenance signal + SOC drift alert.
### 3.6 Layer-on adapters — standalone OR in front of/alongside an existing gateway (incl. Microsoft toolkit).
### 3.7 Agent registry / inventory (table stakes).

### 3.8 Agent SOC plane (async) — **the product surface (see [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md))**
- **Event emitter (Phase 0 keystone):** non-blocking `tokio::mpsc` emission of an Agent Security Event after each decision — the consumer point for everything below; never in the action path.
- **Deterministic detection:** YAML atomic rules (confused-deputy, drift) + correlation (deny-storm, read→exfil sequence), tagged MITRE ATLAS / OWASP LLM.
- **Active Response:** deterministic `freeze`/`revoke`/`quarantine` via the gateway control API; tenant-scoped, fail-closed.
- **RCA narrator (the only LLM):** sandboxed, post-incident, evidence-as-data, no authority — closes second-order injection.
- **Console + indexer:** live decision feed, approval queue, **provable** incident timelines, receipt-integrity viewer.

---

## 4. Research matrix (validated — extended for the SOC)

| Area | Source | Key finding | Implication |
|---|---|---|---|
| Landscape | *Agentic AI Security: Threats, Defenses, Evaluation* | Planning + tools + memory + autonomy create new risk classes | Integrity is the under-served layer |
| Prompt injection | **AgentDojo** (97 tasks, 629 tests) | Tool output hijacks tool-using agents | Benchmark the provenance gate against it |
| Indirect injection | **InjecAgent** (1,054 cases; ReAct GPT-4 ~24% vulnerable) | External content triggers sensitive calls | Provenance gating, not text scoring, is the deterministic defense |
| Access control | **SEAgent / MAC framework** | Privilege escalation = action beyond least privilege | ABAC/Cedar with source-trust as attribute |
| MCP security | *MCP: Landscape, Threats, Future* | Lifecycle + 16 threat scenarios | Manifest pinning as provenance; drift → escalate + SOC alert |
| Memory/RAG | **AgentPoison**, **PoisonedRAG** | ≥80% / 90% ASR with tiny poison rates | Provenance + receipts extend to memory/RAG (later) |
| Runtime guardrails | **LlamaFirewall** | Guardrails belong on the execution path | Enforce at the tool-call boundary, fail-closed |
| Standards | **OWASP AI Agent Security** | Least privilege, explicit authz, **approval integrity**, audit | "Approval manipulation" is the named gap |
| Authz boundary | **arXiv:2603.20953** *Before the Tool Call* | No security-grade authz standard at the boundary | Verifiable receipts/approval binding can become it |
| **SOC pipeline** | **Wazuh architecture** (agent→manager→indexer→dashboard; decode→rules→active-response) | Proven detect/respond pipeline | Mirror it for agents, but anchored on receipts + deterministic rules |
| **Agent threat taxonomy** | **MITRE ATLAS + OWASP LLM Top 10 (2025)** | Standard tactics/techniques for AI/agent attacks | Tag every detection; coverage matrix |
| **LLM-in-SOC risk** | second-order prompt injection (canonical LLM-tooling failure) | LLM analysts reading attacker content get hijacked | One sandboxed RCA LLM only; deterministic detection elsewhere |

---

## 5. Architecture

```text
INLINE (sync)                                 ASYNC SOC (out-of-band)
User / App
   v
AI Agent Runtime (LangGraph / CrewAI / AutoGen / OpenAI Agents SDK / custom)
   v
AegisAgent SDK  ── canonical action, fail-closed on hash mismatch
   v
AegisAgent Gateway (Rust + Axum + Cedar + SQLite/Postgres)   [standalone OR layered on a gateway]
   ├─ Trust-Provenance Gate     (6-level -> Cedar context)
   ├─ Policy Engine (Cedar)     (action_hash + source_trust native)
   ├─ Approval Integrity Engine (freeze -> SHA-256 -> bind -> single-use -> re-eval)
   ├─ Approval Delivery         (Slack/Teams/dashboard, signature-verified)
   ├─ Verifiable Receipt + Audit (hash chain, OTel export)
   └─ Event emitter ───mpsc───► Normalizer → Detect → Correlate → Alert
   v                                  → { Response (freeze/revoke/quarantine), Notify, Index, RCA(LLM,box) }
Tools / APIs / MCP servers              → SOC Console (provable incident timelines)
```

**Key design decisions:** (1) the SDK is part of the trust boundary and refuses to execute an action whose hash isn't the approved one — integrity enforced at the last step. (2) The SOC is a strictly **async** consumer; emission is fire-and-forget; the action path is never slowed or made fail-open by the SOC.

---

## 6. Technology stack (unchanged core, SOC additions)

Rust + Axum gateway (memory-safe, sub-ms decisions); Cedar (native `action_hash`/`source_trust`); Go + TypeScript SDKs (Python reference oracle); SQLite (MVP) → Postgres (SaaS); **`tokio::mpsc` event bus → Redis Streams → Kafka/NATS at scale; ClickHouse for the SOC event tier; deterministic YAML rule engine; one sandboxed LLM (RCA only)**; OpenTelemetry + Grafana; WorkOS/Clerk SSO later; Vault/KMS for secrets. Single self-hostable binary (gateway + in-proc SOC) is a first-class requirement.

### 6.1 Decision example
```json
{
  "decision": "deny",
  "reason": "Mutating action triggered by untrusted_external content; deterministic provenance gate",
  "source_trust": "untrusted_external",
  "matched_policy": "forbid-mutate-from-untrusted",
  "action_hash": "sha256:...",
  "receipt_hash": "sha256:...",
  "soc": { "detection": "AEG-1002 confused-deputy-mutation", "level": 12, "atlas": "AML.T0051" }
}
```

---

## 7. MVP scope (re-anchored)

**Goal:** protect one mutating workflow end-to-end *with provable integrity*, and **emit the SOC event stream** — a coding/support agent on GitHub + Slack + one MCP server.

**MVP features:**
1. Cedar engine with `action_hash` + `source_trust` context. ✅ (built)
2. Approval Integrity Engine: freeze + SHA-256 + bind + single-use + re-eval; SDK fail-closed. ✅ (built)
3. Trust-Provenance Gate: 6 levels as policy input. ✅ (built)
4. Verifiable hash-chained action-receipt format + audit pipeline. ✅ (Python verifier/CLI; Rust emission pending cargo)
5. Slack approval with signature verification + approver role lookup. *(gap)*
6. MCP manifest pinning/drift as provenance signal. ✅ (governance built; runtime proxy pending)
7. **Phase 0 SOC keystone: async event emitter** in `/v1/authorize`. *(next — unlocks the SOC)*
8. One layer-on adapter.

**Non-goals:** a generic SIEM/DLP/network-egress firewall, model scanning, red-team platform, identity lifecycle, LLM auto-remediation over attacker content.

---

## 8. Competitive differentiation (honest)

Against the June-2026 field, the baseline loop is matched everywhere (incl. free OSS). AegisAgent differentiates **only** on:
1. **Frozen-action approval binding + fail-closed SDK** (TOCTOU-resistant) — not in the surveyed field.
2. **Deterministic trust-provenance gating** — vs probabilistic text scoring.
3. **Open verifiable action-receipt format** — interoperable evidence standard.
4. **Integrity-anchored Agent SOC** — provenance-aware deterministic detection + provable incident timelines + SDK-enforced containment, vs generic SIEMs that text-score and log.
5. **Vendor-neutral, self-hostable, layerable.**

A *feature-grade* edge defended by being first, correct, open, neutral, and *provable* — not a category moat (see reassessment §7 + §9).

---

## 9. 90-day execution plan

- **Days 1–15 — validate.** Show 15–20 teams an approve-then-swap / confused-deputy bypass of a stock gateway, *and* the fact their SIEM can't correlate or prove the agent incident; confirm they'd pay. Publish: *"Your AI agent approval gate is lying to you (TOCTOU), and your SIEM can't see it."*
- **Days 16–45 — harden primitives + Phase 0.** Canonical `action_hash` binding; SDK fail-closed; 6-level provenance gate; receipt format v0; **the async event emitter (SOC keystone)**; one layer-on adapter.
- **Days 46–70 — first detections + demo.** Deterministic atomic rules (confused-deputy, drift) + the read→exfil correlation; AgentDojo/InjecAgent for the provenance gate; build the GitHub-issue → provenance-deny → swap-blocked → verifiable-receipt → **provable correlated incident** demo.
- **Days 71–90 — design partners.** 3–5 teams under SOC 2 / Art.14 pressure; publish the open receipt spec; ship the SOC console v0 (live feed + incident timeline).

---

## 10. Pricing hypothesis (reframed by free OSS; SOC is the paid surface)

| Plan | Price | Value |
|---|---:|---|
| OSS Core | Free | Self-hosted gateway, frozen-action approvals, provenance gate, local receipts, in-proc SOC (rules + local console) |
| Startup | $299–$999/mo | Hosted approvals, SSO, SIEM/OTel export, correlation + incidents, receipt retention |
| Enterprise | $3K–$10K+/mo | Self-hosted/air-gapped support, Art.14/SOC 2 evidence reporting, multi-node SOC, Active-Response, retention, SLAs |

First milestone: $25K–$40K MRR via design partners under compliance pressure; the SOC (correlation/incidents/Active-Response) is the expansion lever.

---

## 11. Final recommendation

Build AegisAgent as the **open, neutral integrity layer operated as an integrity-anchored Agent SOC** — provable approvals + provenance gating + verifiable receipts + a deterministic detect/correlate/contain plane — that *layers onto* the now-commodity gateway market rather than competing to be the gateway or a generic SIEM. Lead every conversation with the approve-then-swap demo, the Article 14 evidence story, and the **provable incident timeline**.
