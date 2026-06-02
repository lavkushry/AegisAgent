# AegisAgent — Threat Model (June 2026 reset)

**Product:** AegisAgent
**Category:** Agent Action Integrity (integrity + provenance layer for agent actions)
**Version:** v0.2 (re-anchored)
**Date:** 2026-06-02
**Owner:** Lavkush Kumar
**Read first:** [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md)

> ⚠️ **Reset note.** v0.1 covered the broad agent-security threat surface. This version keeps that coverage but **foregrounds the specific threats AegisAgent uniquely closes** — approval manipulation (TOCTOU / approve-then-swap / replay / render-vs-bytes), confused-deputy via untrusted provenance, and receipt tampering — because those are the product's reason to exist. The broad threats (§7) are still defended but are no longer the headline.

---

## 1. Executive summary

AegisAgent is a runtime enforcement + evidence layer, so it is itself security-critical. Its differentiated guarantees define its primary threat classes:

> **T-A (Approval manipulation):** an attacker causes an action *different from the one a human approved* to execute, or reuses/forges an approval.
> **T-B (Confused deputy via provenance):** untrusted-origin content drives a privileged action.
> **T-C (Evidence tampering):** receipts/audit are altered, dropped, or forged so oversight cannot be proven.

Governing rule:

> **If AegisAgent cannot prove the executed action equals the approved action, prove the trigger's provenance, and durably record a verifiable receipt — the action must not execute.** (Fail closed.)

---

## 2. Research foundation

OWASP AI Agent Security Cheat Sheet (names **decision/approval manipulation**, tool abuse, privilege escalation, memory poisoning, supply chain); OWASP Top 10 for Agentic Applications 2026 (human-agent trust exploitation, tool misuse, identity/privilege abuse); AgentDojo & InjecAgent (indirect prompt injection via tool output); MCP security research + CoSAI (lifecycle, delegation, integrity, HITL); NIST AI RMF GenAI Profile; EU AI Act Article 14 (provable human oversight). The Invariant Labs GitHub-MCP disclosure (malicious issue → private-repo data leaked to public repo) is the canonical real-world instance of T-B.

---

## 3. System under threat & assets

Components: Agent Runtime → **SDK (in trust boundary; performs fail-closed `action_hash` check)** → Gateway (Identity Resolver, Trust-Provenance Gate, Policy Engine, Risk Engine, **Approval Integrity Engine**, MCP Gateway, Token Broker, **Receipt + Audit Writer**, Dashboard/Admin) → External Tools/MCP.

Protected assets: agent identities & tokens; tool/MCP credentials; **the binding between an approval and its `action_hash`**; canonical actions; **receipt hash chain + signing keys**; policy bundles; audit/traces; tenant config; provenance labels; approver identities/roles.

---

## 4. Trust boundaries

```text
B1 User/App        -> Agent Runtime         (untrusted intent may enter)
B2 Agent Runtime   -> AegisAgent SDK         (agent may be compromised/hijacked)
B3 SDK             -> Gateway                 (authenticated; SDK enforces fail-closed hash check HERE)
B4 Gateway         -> Policy/Provenance       (internal)
B5 Gateway         -> External Tool/MCP       (tool output is UNTRUSTED data -> provenance label)
B6 Gateway         -> Approval channel        (Slack/Teams/dashboard; signature-verified)
B7 Tenant data     -> Shared SaaS infra       (tenant isolation)
```

Key assumption: the agent process **may be hijacked** (indirect prompt injection). Therefore enforcement cannot trust the agent's intent — integrity is checked against the human-bound `action_hash` at B3, and provenance is gated deterministically at B4.

---

## 5. Primary threat class T-A — Approval manipulation (the headline)

| ID | Threat | Vector | Mitigation |
|---|---|---|---|
| T-A1 | **Approve-then-swap** | Get benign action A approved, execute different action B under it | SDK recomputes hash(B) ≠ approved `action_hash(A)` → **fail closed** |
| T-A2 | **Post-approval parameter tampering** | Mutate params after approval | New canonical action → new hash → mismatch → fail closed; `edit` forces re-evaluation |
| T-A3 | **Replay / reuse** | Reuse an old/expired approval, or execute an approved action twice | Bound `action_hash` (no reuse for a different action) + `expires_at` + **single-use**: atomic `consume` (`consumed_at` guard) before execution; the SDK fails closed if consume is refused (409) |
| T-A4 | **Render-vs-bytes** | Approver sees friendly text; different bytes run | Approval card renders the *canonical action that is hashed*; approval binds to that hash |
| T-A5 | **Approval-callback forgery** | Spoof a Slack/Teams "approve" | Verify callback signature; bind approver identity + role; reject unsigned |
| T-A6 | **Approver-role abuse** | Unauthorized user approves | Approver group/role lookup via SSO/OIDC; policy-scoped approver groups |
| T-A7 | **Self-approval / collusion** | Agent's owner approves own high-risk action | Optional separation-of-duties + two-person approval for critical actions |

**Residual risk:** if SDK canonicalization diverges across languages/versions, hashes mismatch spuriously (availability) or, worse, a crafted divergence could mask a swap. Mitigation: pinned `canon_version` + CI byte-equality gate (see Operational Design §4.1).

---

## 6. Primary threat class T-B — Confused deputy via provenance (the second headline)

| ID | Threat | Vector | Mitigation |
|---|---|---|---|
| T-B1 | **Indirect prompt injection → privileged action** | Malicious GitHub issue / email / ticket / webpage hijacks agent | Deterministic `forbid` for `mutates_state && untrusted_external` — independent of text |
| T-B2 | **Cross-repo/data-movement leak** (Invariant Labs class) | Untrusted issue triggers private read → public write | Default policy forbids untrusted-triggered cross-repo movement; require approval |
| T-B3 | **Classifier evasion** | Benign-looking injected text bypasses scoring | Provenance is deterministic; classifiers may only *tighten*, never *loosen* |
| T-B4 | **Provenance label spoofing** | Forge a higher trust level | Labels set server-side from authenticated source signals; signed sources for `trusted_internal_signed`; run carries lowest observed level |
| T-B5 | **MCP manifest drift / tool poisoning** | Swapped/altered MCP tool definition | Pin + hash manifests; drift → downgrade provenance to `unknown`/`malicious_suspected` → deny/escalate |
| T-B6 | **Memory/RAG poisoning** (AgentPoison/PoisonedRAG) | Poisoned memory drives later actions | Provenance + approval on memory writes from untrusted sources (roadmap) |

---

## 7. Primary threat class T-C — Evidence tampering

| ID | Threat | Vector | Mitigation |
|---|---|---|---|
| T-C1 | **Receipt alteration** | Edit a stored receipt to hide an action | Per-tenant hash chain; `/verify` detects break; enterprise transparency-log/signing |
| T-C2 | **Receipt drop / gap** | Suppress receipts | Critical actions block if a receipt cannot be written; chain gaps are detectable |
| T-C3 | **Receipt forgery** | Fabricate an approval/receipt | KMS-backed signing (enterprise); key ID in receipt; rotation preserves verifiability |
| T-C4 | **Audit pipeline DoS** | Flood to drop evidence | Backpressure + durable enqueue (99.9% target); fail closed for critical on audit loss |

---

## 8. Threats against AegisAgent as a control plane (table stakes, still defended)

- **Policy bypass / tampering:** signed, versioned Cedar bundles; default-deny; dry-run before rollout; admin authz.
- **Fail-open risk:** mutating/high-risk fail closed on any component outage; read-only fail-open only if explicitly configured.
- **Agent identity spoofing / token theft:** tenant-scoped tokens, short-lived creds, mTLS (enterprise), request signing; Token Broker so agents never hold raw tool creds.
- **SDK bypass:** proxy-only credentials, direct-tool-use detection, network guidance; a bypassed SDK is an incident.
- **Tenant isolation failure (SaaS):** `tenant_id` on every query, parameterized SQLx, middleware scoping, optional row-level security, per-tenant receipt partitions.
- **Secrets exposure in evidence:** redact secrets; store input/output *hashes*, not raw payloads, by default.
- **Supply chain:** signed releases, SBOM, dependency scan, pinned Actions, image signing, secret scanning.

---

## 9. STRIDE summary (integrity-anchored)

| STRIDE | Most relevant here |
|---|---|
| Spoofing | Approval-callback forgery (T-A5), provenance spoofing (T-B4), agent token theft |
| **Tampering** | **Approve-then-swap (T-A1/2), receipt alteration (T-C1)** — the core |
| Repudiation | Verifiable receipts + approver binding defeat "I didn't approve that" |
| Information disclosure | Confused-deputy data leak (T-B2), secrets in evidence |
| DoS | Approval-channel / audit-pipeline flooding |
| **Elevation of privilege** | **Confused deputy via untrusted provenance (T-B1)** — the core |

---

## 10. Assurance & testing

- **T-A regression:** approve-then-swap blocked; replay rejected; expired rejected; edit re-evaluates; render==hash invariant; cross-language canonicalization byte-equality.
- **T-B regression:** AgentDojo/InjecAgent-style untrusted-trigger suites → deterministic deny/escalate; manifest-drift → downgrade; provenance-spoof attempts rejected.
- **T-C regression:** receipt-chain tamper detection; receipt-drop blocks critical actions; signature verification.
- Continuous: fuzz canonicalization; verify fail-closed under each component outage.

---

## 11. Governing principle

> **AegisAgent fails closed. It executes a high-risk action only when it can prove three things: the action equals the human-approved action, the trigger's provenance permits it, and a verifiable receipt was durably written. If any proof is missing, the action does not run.**

This is the threat model's north star and the product's reason to exist: not "decide," but **prove**.
