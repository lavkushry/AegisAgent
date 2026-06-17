# AegisAgent — Threat Model (June 2026 reset)

**Product:** AegisAgent
**Category:** Agent Action Integrity → Integrity-anchored Agent SOC
**Version:** v0.4 (adds per-threat Impact/Likelihood/Residual ratings, #1200)
**Date:** 2026-06-17
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

Impact and Likelihood are rated **pre-mitigation** (inherent severity if the threat were entirely unaddressed); Residual is the rating **after** the listed mitigation.

| ID | Threat | Vector | Impact | Likelihood | Mitigation | Residual |
|---|---|---|---|---|---|---|
| T-A1 | **Approve-then-swap** | Get benign action A approved, execute different action B under it | Critical | Medium | SDK recomputes hash(B) ≠ approved `action_hash(A)` → **fail closed** | Low |
| T-A2 | **Post-approval parameter tampering** | Mutate params after approval | High | Medium | New canonical action → new hash → mismatch → fail closed; `edit` forces re-evaluation | Low |
| T-A3 | **Replay / reuse** | Reuse an old/expired approval, or execute an approved action twice | High | Medium | Bound `action_hash` + `expires_at` + **single-use**: atomic `consume` (`consumed_at` guard) before execution; SDK fails closed if consume is refused (409) | Low |
| T-A4 | **Render-vs-bytes** | Approver sees friendly text; different bytes run | Critical | Medium | Approval card renders the *canonical action that is hashed*; approval binds to that hash | Low |
| T-A5 | **Approval-callback forgery** | Spoof a Slack/Teams "approve" | High | Medium | Verify callback signature (constant-time HMAC); bind approver identity + role; reject unsigned | Low |
| T-A6 | **Approver-role abuse** | Unauthorized user approves | Medium | Medium | Approver group/role lookup via SSO/OIDC; policy-scoped approver groups | Medium — depends on the operator's IdP/group config, which is outside AegisAgent's control |
| T-A7 | **Self-approval / collusion** | Agent's owner approves own high-risk action | Medium | Medium | Optional separation-of-duties + two-person approval for critical actions | Medium — two-person approval is opt-in, not enforced by default |

**Residual risk (class-wide):** if SDK canonicalization diverges across languages/versions, hashes mismatch spuriously (availability) or a crafted divergence could mask a swap. Mitigation: pinned `aegis-jcs-1` scheme + CI byte-equality gate (Operational Design §4.1). Every T-A event is also emitted to the SOC as a high-severity detection.

---

## 6. Primary threat class T-B — Confused deputy via provenance (second headline)

| ID | Threat | Vector | Impact | Likelihood | Mitigation | Residual |
|---|---|---|---|---|---|---|
| T-B1 | **Indirect prompt injection → privileged action** | Malicious GitHub issue / email / ticket / webpage hijacks agent | Critical | High | Deterministic `forbid` for `mutates_state && untrusted_external` — independent of text | Low |
| T-B2 | **Cross-repo/data-movement leak** (Invariant Labs class) | Untrusted issue triggers private read → public write | Critical | Medium | Default policy forbids untrusted-triggered cross-repo movement; SOC sequence rule AEG-3007 correlates read→exfil | Low |
| T-B3 | **Classifier evasion** | Benign-looking injected text bypasses scoring | High | Medium | Provenance is deterministic; classifiers may only *tighten*, never *loosen* | Medium — tighten-only governs propagation across a chain, but the *initial* trust label still depends on the accuracy of whatever classifier assigns it; a misclassified-as-trusted label at the source is not caught by this rule alone |
| T-B4 | **Provenance label spoofing** | Forge a higher trust level | Critical | Low | Labels set server-side from authenticated source signals; signed sources for `trusted_internal_signed`; run carries lowest observed level | Low |
| T-B5 | **MCP manifest drift / tool poisoning** | Swapped/altered MCP tool definition | High | Medium | Pin + hash manifests; drift → downgrade provenance → deny/escalate; SOC drift detection AEG-4002 | Low |
| T-B6 | **Memory/RAG poisoning** (AgentPoison/PoisonedRAG) | Poisoned memory drives later actions | High | Medium | Provenance + approval on memory writes from untrusted sources (roadmap) | **High — not yet built.** Tracked as its own epic ([#1397](https://github.com/lavkushry/AegisAgent/issues/1397)); until it ships, AegisAgent has no enforcement point on memory/RAG writes specifically |

---

## 7. Primary threat class T-C — Evidence tampering

| ID | Threat | Vector | Impact | Likelihood | Mitigation | Residual |
|---|---|---|---|---|---|---|
| T-C1 | **Receipt alteration** | Edit a stored receipt to hide an action | High | Medium | Per-tenant hash chain; `/verify` detects break; enterprise transparency-log/signing; SOC `receipt-chain-broken` = P1 | Low |
| T-C2 | **Receipt drop / gap** | Suppress receipts | High | Medium | Critical actions block if a receipt cannot be written; chain gaps detectable | Low |
| T-C3 | **Receipt forgery** | Fabricate an approval/receipt | High | Medium | Optional Ed25519 signing (`sign.rs`); key ID in receipt; rotation preserves verifiability | Medium — the default signing key is a local file, not yet HSM/KMS-backed; KMS-backed signing is tracked separately ([#1311](https://github.com/lavkushry/AegisAgent/issues/1311)) and is the harder bar a well-resourced attacker with host access would need to clear |
| T-C4 | **Audit pipeline DoS** | Flood to drop evidence | Medium | Low | Backpressure + durable enqueue (99.9% target); fail closed for critical on audit loss | Low |

---

## 8. Primary threat class T-D — Attacks on the integrity-anchored SOC (new)

The SOC is async and consumes attacker-influenced evidence, so it is its own attack surface. These threats are closed primarily by the **four design laws** (Architecture §2), restated here as security controls.

| ID | Threat | Vector | Impact | Likelihood | Mitigation | Residual |
|---|---|---|---|---|---|---|
| **T-D1** | **Second-order prompt injection** | Attacker-authored evidence (issue body, prompt, tool args) reaches an LLM "analyst," which then mis-triages, downgrades severity, or recommends allow | Critical | Medium | **Design Law 2:** the only LLM is the **post-incident RCA narrator** — sandboxed, no tools, no enforcement authority, evidence passed as **inert data**; triage/correlation/response are **deterministic** code, not LLMs. An injected "mark this low severity" string is just text in a report field. | Low |
| **T-D2** | **Score-gating manipulation** | Attacker games a risk/anomaly/"prompt-injection" score below a threshold to obtain `allow` | Critical | Low | **Design Law 1:** scores are **advisory display metadata only**; **Cedar decides** on deterministic provenance. No numeric threshold ever routes an authorization. | Low |
| **T-D3** | **Detection evasion** | Stay under correlation thresholds (slow-and-low), or flood denies to bury a real attack (alert fatigue / deny-storm cover) | Medium | High | Multiple overlapping rules (atomic + sequence + frequency); deny-storm itself is a detection (AEG-2010); correlation windows scoped by `agent_id`/`run_id`; rate-limit + dedupe alerts; **fail toward escalation**, not suppression | Medium — slow-and-low is a structurally hard problem for any threshold-based detector, deterministic or not |
| **T-D4** | **Response-engine weaponization** | Trigger false freezes/revokes as a DoS on legitimate agents, or suppress a legitimate containment | Medium | Low | Response mapping is **deterministic** and **tenant-scoped**; control endpoints authenticated + fail-closed; containment is reversible + audited; two-person confirm for revoke (optional); every response emits a receipt | Low |
| **T-D5** | **Correlation-state poisoning** | Forge/replay ASE events to corrupt sequence detection or frame an agent | Medium | Low | ASE carries `action_hash`/`receipt_hash`; the SOC validates events against the receipt chain; agentless-ingested events are authenticated at the collector and trust-labelled | Low |
| **T-D6** | **Inline-path latency injection via the SOC** | Force detection into the synchronous path (e.g., "block until analyzed") to add latency or create a fail-open dependency | High | Low | **Design Law 3:** detection is **strictly asynchronous** (`tokio::mpsc` → background); emission is fire-and-forget; SOC outage degrades monitoring, never the action path | Low |
| **T-D7** | **RCA exfiltration via the LLM** | Prompt the RCA narrator (through evidence) to leak other-tenant data or secrets in its output | Medium | Low | RCA input is tenant-scoped, redacted (hashes not payloads), and the model has no retrieval/tools; output is reviewed before it leaves the tenant boundary | Low |

**Residual risk (class-wide):** deterministic detection can miss novel attack shapes (no ML generalization). Accepted trade-off: we prefer **provable, non-injectable** detection over broader-but-gameable ML; behavioural baselining is added later as *advisory* signal only (never gating).

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
