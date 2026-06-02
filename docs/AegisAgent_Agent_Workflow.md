# AegisAgent — Deep Agent Workflow Design (June 2026 reset)

**Product:** AegisAgent
**Category:** Agent Action Integrity (integrity + provenance layer for agent actions)
**Version:** v0.2 (re-anchored)
**Date:** 2026-06-02
**Read first:** [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md)

> ⚠️ **Reset note.** v0.1 designed the generic "every action passes a runtime decision point" workflow — now commodity. This version keeps the six workflows but rebuilds the **Approval workflow** (§7) around frozen-action hashing + fail-closed SDK enforcement, and the **Authorization workflow** (§6) around deterministic provenance gating, and adds **verifiable receipts** to the audit workflow (§9). Those are the parts that make the workflow defensible.

---

## 1. Design thesis

> **Every meaningful agent action passes a runtime decision point — and the decision is *provable*: the executed action is cryptographically bound to the human approval, and the decision is gated on the deterministic trust level of the content that triggered it.**

Baseline interception (AgentDojo/LlamaFirewall justify the seam) is necessary but no longer differentiating. AegisAgent's workflow engine adds two guarantees the field leaves open: **integrity** (approved == executed) and **deterministic provenance** (untrusted source cannot drive a privileged action).

---

## 2. Core question (per risky action)

```text
Should THIS agent perform THIS action on THIS resource, via THIS tool, under THIS source-trust, right now —
AND, if a human approves, can we prove the executed bytes are exactly the approved bytes?
```

---

## 3. The six workflows

1. Agent registration
2. Tool / MCP registration (+ manifest pinning)
3. **Runtime authorization** (provenance-gated) — §6
4. **Human approval** (frozen-action integrity) — §7
5. Memory / RAG trust (provenance + receipts; later)
6. Audit & investigation (**verifiable receipts**) — §9

---

## 4. End-to-end flow

```text
User / App
   v
AI Agent Runtime (LangGraph / OpenAI Agents SDK / CrewAI / AutoGen / custom)
   v
AegisAgent SDK  ── canonicalize action -> action_hash; FAIL CLOSED on mismatch before execute
   v
AegisAgent Gateway
   ├─ Identity Resolver
   ├─ Trust-Provenance Gate     (deterministic 6-level label -> Cedar context)
   ├─ Policy Engine (Cedar)     (action_hash + source_trust native inputs)
   ├─ Risk Engine               (enrich/route; never overrides forbid)
   ├─ Approval Integrity Engine (freeze -> hash -> bind -> verify)
   ├─ Token Broker              (agents never hold raw tool creds)
   └─ Receipt + Audit Writer    (hash-chained verifiable receipts)
   v
External Tool / MCP Server
```

The SDK is part of the trust boundary: the final fail-closed `action_hash` check happens there, so a compromised agent process cannot execute an unapproved action.

---

## 5. Workflows 1–2: registration & manifest pinning (table stakes)

- **Agent registration:** identity, owner, environment, framework, model, risk tier, status; issue tenant-scoped token.
- **Tool/MCP registration:** register tools + per-action risk/mutation flags; register MCP servers, **discover + pin + hash manifests**; deny unknown tools by default. Manifest drift (hash ≠ pinned) downgrades provenance to `unknown`/`malicious_suspected` and feeds §6.

---

## 6. Workflow 3 — Runtime authorization (provenance-gated)

```text
1. Agent proposes tool call.
2. SDK canonicalizes {tool, action, resource, parameters} -> action_hash.
3. SDK -> POST /v1/authorize (with run's source_trust label).
4. Gateway resolves tenant/agent/user; Trust-Provenance Gate sets context.source_trust
   = lowest trust level of any content consumed in the run.
5. Cedar evaluates with source_trust + action risk + resource + environment:
      - mutating + untrusted_external/malicious_suspected -> DENY (deterministic forbid)
      - mutating + semi_trusted_customer/unknown          -> REQUIRE_APPROVAL
      - read-only / trusted                               -> ALLOW
6. Risk Engine enriches/routes (cannot override a forbid).
7. Decision + action_hash + source_trust returned; receipt written.
```

**Determinism rule:** a classifier (regex/LLM) may lower the trust label (tighten) but never raise it. The deny for "mutating + untrusted" is not overridable by a "looks benign" score. This is the confused-deputy defense at the policy layer.

```cedar
forbid (principal, action == Action::"tool_call", resource)
when {
  resource.mutates_state == true &&
  (context.source_trust == "untrusted_external" || context.source_trust == "malicious_suspected")
};
```

---

## 7. Workflow 4 — Human approval (frozen-action integrity) — **centerpiece**

This is where AegisAgent diverges from every gateway that "pauses and asks a human."

```text
1. Decision = require_approval.
2. Approval Integrity Engine FREEZES the exact canonical action and stores:
      { action_hash, canonical_action, approver_group, nonce, expires_at }.
3. Agent execution pauses (LangGraph interrupt / OpenAI HITL / SDK block).
4. Slack/Teams/dashboard card renders the CANONICAL action + source_trust label,
   so the human approves exactly what will run. (Callback signature verified; approver role checked.)
5. Human decision:
      APPROVE -> approval bound to action_hash + approver identity + timestamp
      EDIT    -> edited params -> NEW canonical action -> NEW action_hash -> RE-EVALUATE (fresh decision)
      REJECT / ESCALATE / EXPIRE -> action never runs
6. SDK resumes: re-fetch approval -> recompute hash(about_to_run).
      hash == approved action_hash AND status == approved AND not expired/replayed
          -> execute via Token Broker proxy
      else -> FAIL CLOSED + emit tamper-attempt receipt.
7. Verifiable receipt written (hash-chained).
```

**Approval state machine:** `CREATED → NOTIFIED → {APPROVED | EDITED→re-evaluate | REJECTED | ESCALATED | EXPIRED | CANCELLED}`. Approvals are single-use (nonce), time-boxed (`expires_at`), and replay-checked.

**Threats this workflow closes (that a naive pause/resume does not):**
- **Approve-then-swap** — execute a different action under a benign approval → blocked by hash mismatch.
- **Parameter tampering after approval** → new hash ≠ approved hash → blocked.
- **Replay/reuse** of an old approval → nonce/expiry rejects it.
- **Render-vs-bytes** — approver saw friendly text, different bytes execute → the card renders the canonical action that is hashed.

```text
ATTACK: agent gets "comment_on_pr" approved (hash Ha), then tries "merge_pull_request" (hash Hb).
RESULT: SDK recomputes Hb != Ha -> FAIL CLOSED. Nothing runs. Receipt records the tamper attempt.
```

---

## 8. Workflow 5 — Memory / RAG trust (provenance + receipts; later)

Apply the same primitives to memory writes and RAG ingestion (AgentPoison/PoisonedRAG class): label each write/retrieval with source trust; block memory writes from untrusted sources unless approved; require provenance + receipts for knowledge-base updates; downgrade trust on unsigned/unknown sources. Reuses §6 provenance and §9 receipts — no new mechanism.

---

## 9. Workflow 6 — Audit & investigation (verifiable receipts)

Every protected action emits a **hash-chained verifiable receipt** (`receipt_hash = SHA-256(body || prev_receipt_hash)`), not just a log line. Investigation timeline reconstructs: run start → content consumed + source-trust labels → proposed actions + `action_hash` → policy/provenance decisions → approval (approver, bound hash) → executed hash → result → receipt chain.

`GET /v1/receipts/:id/verify` recomputes the chain and returns `verified | tampered`. Receipts export via OTel/webhook to SIEM and serve as SOC 2 / EU AI Act Article 14 evidence. The receipt format is **open and documented** (standards play).

---

## 10. Reliability / fail-closed behavior

| Component down | Behavior |
|---|---|
| Gateway/policy unreachable | SDK fails closed for mutating/high-risk; read-only may fail open only if explicitly configured |
| Approval channel down | Approval stays pending; fallback to dashboard; auto-deny on timeout |
| Receipt/audit pipeline down | Critical actions block until a receipt can be written; low-risk buffer + retry |
| `action_hash` mismatch (any cause) | FAIL CLOSED — never execute; record tamper attempt |

---

## 11. Framework integration

- **LangGraph:** HITL middleware interrupt on `require_approval`; resume only after SDK hash verification.
- **OpenAI Agents SDK:** tool guardrail computes `action_hash`, pauses for human review, verifies before side-effecting execution.
- **CrewAI / AutoGen:** before-tool-call hooks / tool wrappers calling the SDK; same fail-closed contract.
- **Layer-on:** when fronting an existing gateway, AegisAgent consumes that gateway's allow decision and *adds* the freeze→hash→bind→verify + receipt steps.

---

## 12. Workflow design principles

1. Decide close to the action; **enforce integrity at the last step (SDK).**
2. Provenance is deterministic; classifiers only tighten.
3. Humans approve risk, not routine (risk-based gating).
4. Every approval binds to exactly one frozen action.
5. Every protected action yields verifiable evidence.
6. Fail closed on any ambiguity for mutating/high-risk actions.

---

## 13. Workflow recommendation

Build the six workflows, but make Workflow 4 (approval integrity) and the provenance gate in Workflow 3 the parts you obsess over:

> **A pause-and-ask-a-human approval is table stakes. A pause-and-ask-a-human approval that is cryptographically bound to the exact executed action, deterministically gated on source provenance, and recorded as a verifiable receipt — that is AegisAgent.**
