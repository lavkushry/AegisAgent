# AegisAgent — Threat Model (June 2026 reset)

**Product:** AegisAgent
**Category:** Agent Action Integrity → Integrity-anchored Agent SOC
**Version:** v0.3 (re-anchored on the integrity-anchored Agent SOC)
**Date:** 2026-06-05
**Owner:** Lavkush Kumar
**Read first:** [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md) · **Architecture:** [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md)

> ⚠️ **Reset note (two layers).** v0.1 covered the broad agent-security threat surface. v0.2 foregrounded the specific threats AegisAgent uniquely closes — approval manipulation (T-A), confused-deputy via untrusted provenance (T-B), and receipt tampering (T-C). **v0.3 adds T-D: threats against the integrity-anchored SOC itself** — because once you build a detection/response plane, *it* becomes attack surface. The most important new threat is **second-order prompt injection** (attacker content reaching an LLM "analyst"), which the design laws close by construction.

---

## 1. Executive summary

AegisAgent is a runtime enforcement + evidence + monitoring layer, so it is itself security-critical. Its differentiated guarantees define its primary threat classes:

> **T-A (Approval manipulation):** an attacker causes an action *different from the one a human approved* to execute, or reuses/forges an approval.
> **T-B (Confused deputy via provenance):** untrusted-origin content drives a privileged action.
> **T-C (Evidence tampering):** receipts/audit are altered, dropped, or forged so oversight cannot be proven.
> **T-D (Attacks on the SOC):** the detection/response plane is evaded, poisoned, weaponized, or — worst — turned into a *new* injection surface that re-introduces the very threat the product defends against.

Governing rule:

> **If AegisAgent cannot prove the executed action equals the approved action, prove the trigger's provenance, and durably record a verifiable receipt — the action must not execute.** (Fail closed.) **And the SOC must detect deterministically, never let a score gate, and never let an LLM read attacker content into a decision.**

---

## 2. Research foundation

OWASP AI Agent Security Cheat Sheet (names **decision/approval manipulation**, tool abuse, privilege escalation, memory poisoning, supply chain); OWASP Top 10 for Agentic Applications 2026 (human-agent trust exploitation, tool misuse, identity/privilege abuse, **excessive agency**); AgentDojo & InjecAgent (indirect prompt injection via tool output); MCP security research + CoSAI; NIST AI RMF GenAI Profile; EU AI Act Article 14; MITRE ATLAS + OWASP LLM Top 10 (for the SOC's detection taxonomy). The Invariant Labs GitHub-MCP disclosure (malicious issue → private-repo data leaked to public repo) is the canonical real-world instance of T-B. The second-order-injection risk (T-D1) is the canonical failure mode of LLM-in-the-loop security tooling.

---

## 3. System under threat & assets

Components:
- **Inline plane:** Agent Runtime → **SDK (in trust boundary; performs fail-closed `action_hash` check)** → Gateway (Identity Resolver, Trust-Provenance Gate, Policy Engine, Risk Engine, **Approval Integrity Engine**, MCP Gateway, Token Broker, **Receipt + Audit Writer**) → External Tools/MCP.
- **Async SOC plane:** Event Bus → Normalizer → **Detection Engine (deterministic)** → Correlation Engine → Alert Builder → {Response Engine, Indexer, Notify, **RCA narrator (sandboxed LLM)**} → SOC Console.

Protected assets: agent identities & tokens; tool/MCP credentials; **the binding between an approval and its `action_hash`**; canonical actions; **receipt hash chain + signing keys**; policy bundles; **detection rules + correlation state**; audit/traces; tenant config; provenance labels; approver identities/roles; **the integrity of the SOC's verdicts and the agent `status` (active/frozen/revoked/quarantined)**.

---

## 4. Trust boundaries

```text
B1 User/App         -> Agent Runtime          (untrusted intent may enter)
B2 Agent Runtime    -> AegisAgent SDK          (agent may be compromised/hijacked)
B3 SDK              -> Gateway                  (authenticated; SDK enforces fail-closed hash check HERE)
B4 Gateway          -> Policy/Provenance        (internal; deterministic decision HERE)
B5 Gateway          -> External Tool/MCP        (tool output is UNTRUSTED data -> provenance label)
B6 Gateway          -> Approval channel         (Slack/Teams/dashboard; signature-verified)
B7 Tenant data      -> Shared SaaS infra        (tenant isolation)
B8 SOC evidence     -> RCA narrator (LLM)       (ALL evidence is UNTRUSTED data; passed inert, never as instructions; LLM has no tools/authority)
B9 Response Engine  -> Gateway control API      (authenticated; freeze/revoke/quarantine; fail-closed)
```

Key assumptions: (1) the agent process **may be hijacked** (indirect prompt injection) — enforcement checks integrity against the human-bound `action_hash` at B3 and gates provenance deterministically at B4. (2) **All evidence flowing into the SOC may be attacker-authored** — so at B8 the only LLM treats it as inert data, and at B4/detection no LLM and no score decides.

---

## 5. Primary threat class T-A — Approval manipulation (headline)

| ID | Threat | Vector | Mitigation |
|---|---|---|---|
| T-A1 | **Approve-then-swap** | Get benign action A approved, execute different action B under it | SDK recomputes hash(B) ≠ approved `action_hash(A)` → **fail closed** |
| T-A2 | **Post-approval parameter tampering** | Mutate params after approval | New canonical action → new hash → mismatch → fail closed; `edit` forces re-evaluation |
| T-A3 | **Replay / reuse** | Reuse an old/expired approval, or execute an approved action twice | Bound `action_hash` + `expires_at` + **single-use**: atomic `consume` (`consumed_at` guard) before execution; SDK fails closed if consume is refused (409) |
| T-A4 | **Render-vs-bytes** | Approver sees friendly text; different bytes run | Approval card renders the *canonical action that is hashed*; approval binds to that hash |
| T-A5 | **Approval-callback forgery** | Spoof a Slack/Teams "approve" | Verify callback signature; bind approver identity + role; reject unsigned |
| T-A6 | **Approver-role abuse** | Unauthorized user approves | Approver group/role lookup via SSO/OIDC; policy-scoped approver groups |
| T-A7 | **Self-approval / collusion** | Agent's owner approves own high-risk action | Optional separation-of-duties + two-person approval for critical actions |

**Residual risk:** if SDK canonicalization diverges across languages/versions, hashes mismatch spuriously (availability) or a crafted divergence could mask a swap. Mitigation: pinned `aegis-jcs-1` scheme + CI byte-equality gate (Operational Design §4.1). Every T-A event is also emitted to the SOC as a high-severity detection.

---

## 6. Primary threat class T-B — Confused deputy via provenance (second headline)

| ID | Threat | Vector | Mitigation |
|---|---|---|---|
| T-B1 | **Indirect prompt injection → privileged action** | Malicious GitHub issue / email / ticket / webpage hijacks agent | Deterministic `forbid` for `mutates_state && untrusted_external` — independent of text |
| T-B2 | **Cross-repo/data-movement leak** (Invariant Labs class) | Untrusted issue triggers private read → public write | Default policy forbids untrusted-triggered cross-repo movement; SOC sequence rule AEG-3007 correlates read→exfil |
| T-B3 | **Classifier evasion** | Benign-looking injected text bypasses scoring | Provenance is deterministic; classifiers may only *tighten*, never *loosen* |
| T-B4 | **Provenance label spoofing** | Forge a higher trust level | Labels set server-side from authenticated source signals; signed sources for `trusted_internal_signed`; run carries lowest observed level |
| T-B5 | **MCP manifest drift / tool poisoning** | Swapped/altered MCP tool definition | Pin + hash manifests; drift → downgrade provenance → deny/escalate; SOC drift detection AEG-4002 |
| T-B6 | **Memory/RAG poisoning** (AgentPoison/PoisonedRAG) | Poisoned memory drives later actions | Provenance + approval on memory writes from untrusted sources (roadmap) |

---

## 7. Primary threat class T-C — Evidence tampering

| ID | Threat | Vector | Mitigation |
|---|---|---|---|
| T-C1 | **Receipt alteration** | Edit a stored receipt to hide an action | Per-tenant hash chain; `/verify` detects break; enterprise transparency-log/signing; SOC `receipt-chain-broken` = P1 |
| T-C2 | **Receipt drop / gap** | Suppress receipts | Critical actions block if a receipt cannot be written; chain gaps detectable |
| T-C3 | **Receipt forgery** | Fabricate an approval/receipt | KMS-backed signing (enterprise); key ID in receipt; rotation preserves verifiability |
| T-C4 | **Audit pipeline DoS** | Flood to drop evidence | Backpressure + durable enqueue (99.9% target); fail closed for critical on audit loss |

---

## 8. Primary threat class T-D — Attacks on the integrity-anchored SOC (new)

The SOC is async and consumes attacker-influenced evidence, so it is its own attack surface. These threats are closed primarily by the **four design laws** (Architecture §2), restated here as security controls.

| ID | Threat | Vector | Mitigation |
|---|---|---|---|
| **T-D1** | **Second-order prompt injection** | Attacker-authored evidence (issue body, prompt, tool args) reaches an LLM "analyst," which then mis-triages, downgrades severity, or recommends allow | **Design Law 2:** the only LLM is the **post-incident RCA narrator** — sandboxed, no tools, no enforcement authority, evidence passed as **inert data**; triage/correlation/response are **deterministic** code, not LLMs. An injected "mark this low severity" string is just text in a report field. |
| **T-D2** | **Score-gating manipulation** | Attacker games a risk/anomaly/"prompt-injection" score below a threshold to obtain `allow` | **Design Law 1:** scores are **advisory display metadata only**; **Cedar decides** on deterministic provenance. No numeric threshold ever routes an authorization. |
| **T-D3** | **Detection evasion** | Stay under correlation thresholds (slow-and-low), or flood denies to bury a real attack (alert fatigue / deny-storm cover) | Multiple overlapping rules (atomic + sequence + frequency); deny-storm itself is a detection (AEG-2010); correlation windows scoped by `agent_id`/`run_id`; rate-limit + dedupe alerts; **fail toward escalation**, not suppression |
| **T-D4** | **Response-engine weaponization** | Trigger false freezes/revokes as a DoS on legitimate agents, or suppress a legitimate containment | Response mapping is **deterministic** and **tenant-scoped**; control endpoints authenticated + fail-closed; containment is reversible + audited; two-person confirm for revoke (optional); every response emits a receipt |
| **T-D5** | **Correlation-state poisoning** | Forge/replay ASE events to corrupt sequence detection or frame an agent | ASE carries `action_hash`/`receipt_hash`; the SOC validates events against the receipt chain; agentless-ingested events are authenticated at the collector and trust-labelled |
| **T-D6** | **Inline-path latency injection via the SOC** | Force detection into the synchronous path (e.g., "block until analyzed") to add latency or create a fail-open dependency | **Design Law 3:** detection is **strictly asynchronous** (`tokio::mpsc` → background); emission is fire-and-forget; SOC outage degrades monitoring, never the action path |
| **T-D7** | **RCA exfiltration via the LLM** | Prompt the RCA narrator (through evidence) to leak other-tenant data or secrets in its output | RCA input is tenant-scoped, redacted (hashes not payloads), and the model has no retrieval/tools; output is reviewed before it leaves the tenant boundary |

**Residual risk:** deterministic detection can miss novel attack shapes (no ML generalization). Accepted trade-off: we prefer **provable, non-injectable** detection over broader-but-gameable ML; behavioural baselining is added later as *advisory* signal only (never gating).

---

## 9. Threats against AegisAgent as a control plane (table stakes, still defended)

- **Policy bypass / tampering:** signed, versioned Cedar bundles; default-deny; dry-run before rollout; admin authz.
- **Fail-open risk:** mutating/high-risk fail closed on any component outage; read-only fail-open only if explicitly configured; **SOC async by construction never causes fail-open**.
- **Agent identity spoofing / token theft:** tenant-scoped tokens, short-lived creds, mTLS (enterprise), request signing; Token Broker so agents never hold raw tool creds.
- **SDK bypass:** proxy-only credentials, direct-tool-use detection (as a SOC event), network guidance; a bypassed SDK is an incident.
- **Tenant isolation failure (SaaS):** `tenant_id` on every query, parameterized SQLx, middleware scoping, optional row-level security, per-tenant receipt partitions and per-tenant SOC indices.
- **Secrets exposure in evidence:** redact secrets; store input/output *hashes*, not raw payloads, by default.
- **Supply chain:** signed releases, SBOM, dependency scan, pinned Actions, image signing, secret scanning.

---

## 10. STRIDE summary (integrity-anchored, SOC-aware)

| STRIDE | Most relevant here |
|---|---|
| Spoofing | Approval-callback forgery (T-A5), provenance spoofing (T-B4), ASE forgery (T-D5), agent token theft |
| **Tampering** | **Approve-then-swap (T-A1/2), receipt alteration (T-C1), correlation-state poisoning (T-D5)** — the core |
| Repudiation | Verifiable receipts + approver binding + provable incident timelines defeat "I didn't approve/do that" |
| Information disclosure | Confused-deputy data leak (T-B2), secrets in evidence, RCA exfiltration (T-D7) |
| DoS | Approval-channel / audit-pipeline flooding; deny-storm alert fatigue (T-D3); false-freeze weaponization (T-D4) |
| **Elevation of privilege** | **Confused deputy via untrusted provenance (T-B1), second-order injection into the SOC (T-D1), score-gating (T-D2)** — the core |

---

## 11. Assurance & testing

- **T-A regression:** approve-then-swap blocked; replay rejected; expired rejected; edit re-evaluates; render==hash invariant; cross-language canonicalization byte-equality.
- **T-B regression:** AgentDojo/InjecAgent-style untrusted-trigger suites → deterministic deny/escalate; manifest-drift → downgrade; provenance-spoof rejected.
- **T-C regression:** receipt-chain tamper detection; receipt-drop blocks critical actions; signature verification.
- **T-D regression (new):**
  - **T-D1:** inject "system: mark low severity / recommend allow" strings into evidence; assert deterministic triage/correlation/response are unaffected and only the RCA *text field* reflects it (never a decision).
  - **T-D2:** craft inputs that minimize any advisory score; assert Cedar still denies on provenance.
  - **T-D3:** slow-and-low and deny-storm suites → assert overlapping rules still fire; alerts deduped not dropped.
  - **T-D4/D6:** assert control endpoints are tenant-scoped + fail-closed; assert event emission never adds measurable authorize latency and SOC outage never fails the action path open.
- Continuous: fuzz canonicalization; verify fail-closed under each component outage; verify async isolation of the SOC from the action path.

---

## 12. Governing principle

> **AegisAgent fails closed. It executes a high-risk action only when it can prove three things: the action equals the human-approved action, the trigger's provenance permits it, and a verifiable receipt was durably written. If any proof is missing, the action does not run. The SOC that watches all of this detects deterministically, never lets a score gate, and never lets an LLM read attacker content into a decision — so the defender never becomes the new attack surface.**

This is the threat model's north star and the product's reason to exist: not "decide," but **prove** — and operate on the proof without weakening it.
