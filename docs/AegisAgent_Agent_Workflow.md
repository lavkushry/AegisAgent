# AegisAgent — Deep Agent Workflow Design (June 2026 reset)

**Product:** AegisAgent
**Category:** Agent Action Integrity → Integrity-anchored Agent SOC
**Version:** v0.3 (re-anchored on the integrity-anchored Agent SOC)
**Date:** 2026-06-05
**Read first:** [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md) · **SOC architecture:** [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md)

> ⚠️ **Reset note (two layers).** v0.1 designed the generic "every action passes a runtime decision point" workflow — now commodity. v0.2 rebuilt the **Approval workflow** (§7) around frozen-action hashing + fail-closed SDK, the **Authorization workflow** (§6) around deterministic provenance, and added **verifiable receipts** to audit (§9). **v0.3 adds Workflow 7 (§10): the async SOC pipeline** — every decision emits an event that detection/correlation/response consume out-of-band. The action path is never slowed; the SOC rides the receipt + provenance spine.

---

## 1. Design thesis

> **Every meaningful agent action passes a runtime decision point — the decision is *provable* (executed action cryptographically bound to the human approval), *provenance-gated* (untrusted source cannot drive a privileged action), and *observable* (the decision streams asynchronously into a SOC that detects, correlates, contains, and proves).**

Baseline interception is necessary but no longer differentiating. AegisAgent's workflow engine adds three guarantees: **integrity** (approved == executed), **deterministic provenance** (untrusted source can't drive a privileged action), and **operability** (a SOC on the resulting tamper-evident evidence).

---

## 2. Core question (per risky action)

```text
Should THIS agent perform THIS action on THIS resource, via THIS tool, under THIS source-trust, right now —
if a human approves, can we prove the executed bytes are exactly the approved bytes —
and can the SOC later correlate and PROVE what happened across the whole run?
```

---

## 3. The seven workflows

1. Agent registration
2. Tool / MCP registration (+ manifest pinning)
3. **Runtime authorization** (provenance-gated) — §6
4. **Human approval** (frozen-action integrity) — §7
5. Memory / RAG trust (provenance + receipts; later) — §8
6. Audit & investigation (**verifiable receipts**) — §9
7. **SOC detection / correlation / response** (async, on the receipt stream) — §10

---

## 4. End-to-end flow

```text
INLINE (sync)                                          ASYNC SOC (out-of-band)
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
   ├─ Risk Engine               (enrich/route for display; never overrides forbid, never gates)
   ├─ Approval Integrity Engine (freeze -> hash -> bind -> single-use -> verify)
   ├─ Token Broker              (agents never hold raw tool creds)
   ├─ Receipt + Audit Writer    (hash-chained verifiable receipts)
   └─ Event emitter ───mpsc───► Normalize → Detect → Correlate → Alert
   v                                  → { Respond (freeze/revoke/quarantine), Notify, Index, RCA(LLM,box) }
External Tool / MCP Server               → SOC Console (provable incident timelines)
```

The SDK is part of the trust boundary: the final fail-closed `action_hash` check happens there. The event emitter is fire-and-forget: SOC work never blocks the action path (Design Law 3).

---

## 5. Workflows 1–2: registration & manifest pinning (table stakes)

- **Agent registration:** identity, owner, environment, framework, model, risk tier, status (active/disabled/**frozen/quarantined**); issue tenant-scoped token.
- **Tool/MCP registration:** register tools + per-action risk/mutation flags; register MCP servers, **discover + pin + hash manifests**; deny unknown tools by default. Manifest drift downgrades provenance to `unknown`/`malicious_suspected`, feeds §6, and raises a SOC drift detection (AEG-4002).

---

## 6. Workflow 3 — Runtime authorization (provenance-gated)

```text
1. Agent proposes tool call.
2. SDK canonicalizes {tool, action, resource, parameters} -> action_hash.
3. SDK -> POST /v1/authorize (with run's source_trust label).
4. Gateway resolves tenant/agent/user; Trust-Provenance Gate sets context.trust_level
   = lowest trust level of any content consumed in the run.
5. Cedar evaluates with trust_level + mutates_state + resource + environment:
      - mutating + untrusted_external/malicious_suspected/unknown -> DENY (deterministic forbid)
      - mutating + semi_trusted_customer                          -> REQUIRE_APPROVAL
      - read-only / trusted                                       -> ALLOW
6. Risk Engine enriches/routes for display (cannot override a forbid; never gates).
7. Decision + action_hash + source_trust returned; receipt written; ASE EMITTED (async).
```

**Determinism rule:** a classifier or SOC anomaly score may lower the trust label (tighten) but never raise it, and never re-open a deterministic gate (Design Law 1). The deny for "mutating + untrusted" is not overridable by a "looks benign" score.

```cedar
forbid (principal, action == Action::"tool_call", resource)
when {
  context.mutates_state == true &&
  (context.trust_level == "untrusted_external" || context.trust_level == "malicious_suspected" || context.trust_level == "unknown")
};
```

---

## 7. Workflow 4 — Human approval (frozen-action integrity) — **centerpiece**

```text
1. Decision = require_approval.
2. Approval Integrity Engine FREEZES the exact canonical action and stores:
      { action_hash, canonical_action, approver_group, expires_at, consumed_at=NULL }.
3. Agent execution pauses (LangGraph interrupt / OpenAI HITL / SDK block).
4. Slack/Teams/dashboard card renders the CANONICAL action + source_trust label,
   so the human approves exactly what will run. (Callback signature verified; approver role checked.)
5. Human decision:
      APPROVE -> approval bound to action_hash + approver identity + timestamp
      EDIT    -> edited params -> NEW canonical action -> NEW action_hash -> RE-EVALUATE (fresh decision)
      REJECT / ESCALATE / EXPIRE -> action never runs
6. SDK resumes: re-fetch approval -> CONSUME (single-use, atomic) -> recompute hash(about_to_run).
      hash == approved action_hash AND status == approved AND not expired AND consume succeeded
          -> execute via Token Broker proxy
      else -> FAIL CLOSED + emit tamper-attempt receipt.
7. Verifiable receipt written (hash-chained); ASE EMITTED on every transition (created/approved/
   edited/rejected/consumed) so the SOC sees the full approval lifecycle.
```

**Approval state machine:** `CREATED → NOTIFIED → {APPROVED→CONSUMED | EDITED→re-evaluate | REJECTED | ESCALATED | EXPIRED | CANCELLED}`. Single-use (`consumed_at`), time-boxed (`expires_at`), replay-checked.

**Threats this workflow closes** (and the SOC detections they raise): approve-then-swap → hash mismatch (T-A1, high-severity detection); post-approval param tampering (T-A2); replay/reuse → consume 409 (T-A3); render-vs-bytes (T-A4).

```text
ATTACK: agent gets "comment_on_pr" approved (hash Ha), then tries "merge_pull_request" (hash Hb).
RESULT: SDK recomputes Hb != Ha -> FAIL CLOSED. Nothing runs. Receipt records the tamper attempt;
        the SOC raises a T-A1 detection and (if repeated) freezes the agent.
```

---

## 8. Workflow 5 — Memory / RAG trust (provenance + receipts; later)

Apply the same primitives to memory writes and RAG ingestion (AgentPoison/PoisonedRAG class): label each write/retrieval with source trust; block memory writes from untrusted sources unless approved; require provenance + receipts for knowledge-base updates. Reuses §6 provenance and §9 receipts — and emits ASEs the SOC correlates (e.g., poisoned-memory-write → later privileged action).

---

## 9. Workflow 6 — Audit & investigation (verifiable receipts)

Every protected action emits a **hash-chained verifiable receipt** (`receipt_hash = SHA-256(canonicalize(body incl. prev_receipt_hash))`), not just a log line. Investigation timeline reconstructs: run start → content consumed + source-trust labels → proposed actions + `action_hash` → policy/provenance decisions → approval (approver, bound hash) → executed result → receipt chain.

`GET /v1/receipts/:id/verify` recomputes the chain and returns `verified | tampered`. Receipts export via OTel/webhook and serve as SOC 2 / Article 14 evidence. **Crucially, this receipt chain is the SOC's evidence spine (Workflow 7): every alert and incident references the `receipt_hash` links covering its events, which is what makes SOC incident timelines *provable* rather than merely logged** (see [`action-receipt-spec.md`](action-receipt-spec.md) §7).

---

## 10. Workflow 7 — SOC detection / correlation / response (async) — **new**

The decision (§6/§7) emits an Agent Security Event; the SOC consumes it out-of-band. **All detection is deterministic; the only LLM narrates closed incidents** (Design Laws 1–2).

```text
1. ASE on the bus -> Normalizer reshapes + enriches (data_access, destination, manifest_hash).
2. Atomic rules match a single event (e.g. AEG-1002 confused-deputy-mutation, level 12, ATLAS AML.T0051).
3. Correlation updates per-(agent_id, run_id) windows:
      - frequency: AEG-2010 deny-storm (5 denies / 60s) -> throttle + alert
      - sequence : AEG-3007 read-sensitive -> external-write (within 300s) -> exfil incident
4. On match: build alert (level, ATLAS/OWASP tags) + open/append an incident with evidence_receipts[]
   (the receipt_hash chain covering the events -> PROVABLE timeline).
5. Response Engine maps verdict -> deterministic action via the gateway control API:
      freeze_agent | revoke_token | quarantine_mcp_server | notify_slack | open_incident
   (tenant-scoped, fail-closed, reversible, audited; agents.status honored on the next action.)
6. On incident close: the sandboxed RCA narrator (LLM) drafts a human-readable summary from inert evidence.
7. SOC Console renders the live feed + the provable incident timeline (one-click receipt-chain verify).
```

**Automation levels (graduated):** L0 observe → L1 auto-enrich → L2 auto-triage/incident → L3 auto-contain safe/reversible actions (high-risk → approval, critical → deny) → L4 autonomous with human supervision. Reversible, low-blast-radius containment (deny, require-approval, throttle, freeze) may auto-fire early; destructive actions stay human-gated.

---

## 11. Reliability / fail-closed behavior

| Component down | Behavior |
|---|---|
| Gateway/policy unreachable | SDK fails closed for mutating/high-risk; read-only may fail open only if explicitly configured |
| Approval channel down | Approval stays pending; fallback to dashboard; auto-deny on timeout |
| Receipt/audit pipeline down | Critical actions block until a receipt can be written; low-risk buffer + retry |
| `action_hash` mismatch (any cause) | FAIL CLOSED — never execute; record tamper attempt; SOC detection |
| **SOC plane down** | **Action path UNAFFECTED (async by construction); events buffer/drop with metric; monitoring degrades, never the action** |

---

## 12. Framework integration

- **LangGraph:** HITL middleware interrupt on `require_approval`; resume only after SDK hash verification + consume.
- **OpenAI Agents SDK:** tool guardrail computes `action_hash`, pauses for human review, verifies before side-effecting execution.
- **CrewAI / AutoGen:** before-tool-call hooks / tool wrappers calling the SDK; same fail-closed contract.
- **Layer-on:** when fronting an existing gateway, AegisAgent consumes that gateway's allow decision and *adds* freeze→hash→bind→verify + receipt + the SOC event stream.
- **Agentless:** where the SDK can't be installed, ingest existing logs/traces/webhooks → normalize to ASE → same SOC pipeline (no inline enforcement, but full detection + provable evidence).

---

## 13. Workflow design principles

1. Decide close to the action; **enforce integrity at the last step (SDK).**
2. Provenance is deterministic; classifiers and scores only tighten, never gate.
3. Humans approve risk, not routine (risk-based gating).
4. Every approval binds to exactly one frozen action and is single-use.
5. Every protected action yields verifiable evidence — the SOC's spine.
6. **Detection is asynchronous and deterministic; the only LLM narrates closed incidents.**
7. Fail closed on any ambiguity for mutating/high-risk actions; SOC failure never fails the action path open.

---

## 14. Workflow recommendation

Build the seven workflows, but obsess over Workflow 4 (approval integrity), the provenance gate in Workflow 3, and the **async emission** that begins Workflow 7:

> **A pause-and-ask-a-human approval is table stakes. A pause-and-ask-a-human approval that is cryptographically bound to the exact executed action, deterministically gated on source provenance, recorded as a verifiable receipt, and streamed into a deterministic SOC that detects, correlates, contains, and *proves* — that is AegisAgent.**
