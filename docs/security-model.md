# AegisAgent — Security Model

**Version:** v1.0  
**Date:** 2026-06-16  
**Issue:** [#1404](https://github.com/lavkushry/AegisAgent/issues/1404)  
**Read first (detailed threats + assurance):** [`AegisAgent_Threat_Model.md`](AegisAgent_Threat_Model.md)

This document states what AegisAgent **guarantees**, what it **does not guarantee**, where every trust boundary sits, which threat actors it models, and how those map to OWASP LLM Top 10 and MITRE ATLAS. The companion threat model enumerates specific threat IDs (T-A through T-D) with mitigations; this document is the structured policy reference a deployer or security reviewer reads first.

---

## 1. Trust boundaries

Every request crosses one or more of the following trust boundaries. Each boundary has a specific security control.

| ID | Boundary | Control |
|----|----------|---------|
| **B1** | User / App → Agent Runtime | Out of scope for AegisAgent; the caller is untrusted by assumption |
| **B2** | Agent Runtime → AegisAgent SDK | SDK intercepts every tool call before execution; agent process is assumed potentially compromised (indirect prompt injection) |
| **B3** | SDK → Gateway (`POST /v1/authorize`) | Mutual authentication via hashed agent tokens + tenant ID header; TLS in production; SDK enforces fail-closed `action_hash` check locally before execution |
| **B4** | Gateway → SQLite / PostgreSQL | Private localhost bind (`127.0.0.1`); parameterized SQLx queries; `tenant_id` on every row and every query; WAL isolation |
| **B5** | Gateway → External Tool / MCP Server | Tool output is untrusted data; MCP manifest pinned and hashed; drift triggers downgrade + SOC event |
| **B6** | Gateway → Approval channel (Slack / Teams / dashboard) | HMAC-SHA256 callback signature; approval bound to `action_hash`; approver identity verified via SSO/OIDC |
| **B7** | Tenant A data → Tenant B data | `tenant_id` filter on every SQL query; parameterized SQLx only; middleware-layer scoping; per-tenant SOC indices and receipt partitions |
| **B8** | SOC evidence → RCA narrator (LLM) | Evidence passed as inert structured data, never as instructions; narrator has no tools and no enforcement authority; output is display-only |
| **B9** | Response Engine → Gateway control API (`/freeze`, `/revoke`, `/quarantine`) | Authenticated; tenant-scoped; every containment action is audited + reversible; optional two-person confirm for revoke |

### How boundaries compose

```text
[User / external content]
        ↓  B1 (untrusted)
[Agent Runtime]
        ↓  B2 (SDK intercept — fail-closed action_hash check)
[Gateway — authorize / policy / risk]
    ↙  B4 (DB — tenant-scoped)
[SQLite / PG]
    ↘  B5 (MCP / tools — manifest-pinned)
[External Tool]
        ↓  B6 (approval callback — HMAC-verified)
[Human Approver]
        ↑  B9 (response engine — freeze / revoke / quarantine)
[SOC plane] ← B7 (tenant isolation) → B8 (LLM narrator — inert data only)
```

---

## 2. Threat actors

| Actor | Description | Primary threat class |
|-------|-------------|----------------------|
| **Malicious agent** | An agent that has been prompt-injected or is intentionally trying to execute unauthorized actions (approve-then-swap, replay, parameter tampering) | T-A: Approval manipulation |
| **Indirect prompt injection attacker** | External content (GitHub issue, email, webpage, MCP tool output) that hijacks an honest agent to perform a privileged action on the attacker's behalf | T-B: Confused deputy via provenance |
| **Compromised MCP server** | A third-party MCP server whose manifest has been tampered with or whose tool definitions have been silently swapped to new, more-permissive ones | T-B5: MCP manifest drift / tool poisoning |
| **Insider / tenant admin** | A user with legitimate access who attempts to tamper with receipts, alter audit logs, approve their own actions, or access cross-tenant data | T-C: Evidence tampering; T-A7: Self-approval; B7: Tenant isolation |
| **SOC poisoner** | An attacker who crafts evidence (event bodies, alert payloads, RCA inputs) to manipulate the detection/response plane — either to evade detection, trigger false containment, or inject into the RCA LLM | T-D: Attacks on the SOC |
| **External network attacker** | An attacker with network access to the gateway who tries to replay approvals, forge callback signatures, or brute-force agent tokens | T-A3: Replay; T-A5: Callback forgery |

---

## 3. Security guarantees

These are properties AegisAgent enforces by construction — not by configuration or policy best-effort.

### G1 — Fail closed

Every unrecoverable uncertainty produces a **deny**:

- Unknown agent → deny (no registration row)
- Unknown tool or MCP tool → deny (not in tool registry)
- Gateway unreachable → SDK refuses to execute mutating / high-risk actions
- `action_hash` mismatch → SDK refuses to execute (approve-then-swap blocked)
- Approval expired → deny (gateway returns `EXPIRED`)
- Approval already consumed → deny (gateway returns 409; SDK fails closed)
- Audit writer unavailable → high-risk action denied with `audit_writer_unavailable` reason
- `source_trust` ∈ {`untrusted_external`, `malicious_suspected`} + `mutates_state` → deterministic Cedar `forbid`

### G2 — Hash-bound approval integrity

Every human approval is cryptographically bound to the exact canonical action that was presented to the approver (`aegis-jcs-1` JCS — keys sorted by Unicode code point, compact separators, raw UTF-8, rejects non-finite floats). The SHA-256 hash is stored at approval time and re-verified by the SDK before execution. The hash cannot be stripped, replaced, or forged without breaking the approval chain.

Three additional sub-guarantees:

| Sub-guarantee | Mechanism |
|---------------|-----------|
| **No approve-then-swap** | SDK recomputes `action_hash` at execution time; mismatch → fail closed |
| **No replay** | Approvals are single-use; atomic `consume` with `consumed_at` guard; 409 on re-use |
| **No expiry bypass** | `expires_at` enforced at both gateway (`GET /v1/approvals/:id`) and SDK |

Canonicalization must remain byte-identical across all SDKs and the gateway. This is locked by the shared corpus (`tests/canonical_action_vectors.json`) and a CI byte-equality gate.

### G3 — Deterministic trust-provenance gating

Authorization is gated on the **source trust level** of the triggering content — a 6-level deterministic label, not a score:

```
trusted_internal_signed → trusted_internal_unsigned → semi_trusted_customer
→ untrusted_external → malicious_suspected → unknown
```

Classifiers may only **tighten** a label, never loosen it. Cedar policies enforce at the policy level: mutating actions from `untrusted_external` or `malicious_suspected` are `forbid`-ed regardless of any ML score or advisory metadata. This is the confused-deputy defense — it closes the Invariant Labs class of attacks by construction.

### G4 — Verifiable, hash-chained receipts

Every authorization decision that executes produces a receipt: `receipt_id`, `action_hash`, `decision_hash`, `prev_hash`, `timestamp`, optional Ed25519 signature. Receipts form a per-tenant hash chain. Alteration, gap, or forgery is detectable via `GET /v1/receipts/:id/verify` and `POST /v1/receipts/verify-chain`. This provides compliance evidence for SOC 2 and EU AI Act Article 14.

### G5 — SOC is out-of-band and deterministic

The detection / correlation / response pipeline is strictly asynchronous (`tokio::mpsc` fire-and-forget). Four design laws are enforced by construction:

| Law | Statement |
|-----|-----------|
| **Law 1** | Advisory scores (`composite_risk_score`, graph data, incident metadata) are display/audit metadata only — they **never** gate the `allow / deny / require_approval` decision. Cedar and trust-provenance decide. |
| **Law 2** | Only one LLM exists in the system: the post-incident RCA narrator. It is sandboxed, has no tools or enforcement authority, and receives evidence as inert structured data only. All triage, correlation, and response are deterministic code. |
| **Law 3** | SOC processing is always out-of-band. An SOC outage degrades monitoring; it can never make the action path fail-open. |
| **Law 4** | Every agent containment action (freeze / revoke / quarantine) is tenant-scoped, authenticated, audited, and reversible. |

### G6 — Multi-tenant isolation

All data is partitioned by `tenant_id`. Every SQL query in the gateway binds `tenant_id` as a parameterized argument. There are no raw string concatenation queries. Middleware extracts and validates `tenant_id` from authenticated headers before any data access. Cross-tenant requests return `404`, not `403` (no information leakage about existence).

---

## 4. Non-guarantees

AegisAgent explicitly does **not** guarantee the following:

| What AegisAgent does NOT protect against | Why / notes |
|------------------------------------------|-------------|
| **Agent intent or correctness** | AegisAgent is an integrity and oversight layer, not an intent classifier. It enforces whether an approved action runs as approved, not whether the action was a good idea. |
| **Prompt injection into the agent LLM itself** | AegisAgent detects and blocks the *downstream tool actions* that a prompt-injected agent would take, but it does not sanitize or filter the agent's inputs. Provenance gating reduces blast radius; it does not prevent the injection. |
| **A compromised SDK binary** | If the SDK itself is replaced with a malicious version that skips the `action_hash` check, the fail-closed guarantee breaks at B2–B3. Mitigation: signed releases, SBOM, supply-chain verification. |
| **Correctness of Cedar policies** | Incorrect policies (e.g., a policy that accidentally allows a high-risk action) will be enforced as written. AegisAgent enforces whatever policy is loaded; policy authoring is the operator's responsibility. |
| **Availability under adversarial load** | AegisAgent is not a DDoS mitigator. Under extreme load, the gateway may reject requests (429) or become unavailable; the SDK fails closed (denies execution) for mutating/high-risk actions, which is safe but impacts availability. |
| **Confidentiality of action parameters** | By default, action parameters are hashed and stored; raw payloads are not persisted. However, AegisAgent does not encrypt data at rest beyond what the host platform provides. |
| **Novel attack shapes not yet in detection rules** | Deterministic detection rules catch known patterns; they do not generalize to novel attack shapes. Behavioral baselining (SOC-007) adds anomaly signal as advisory-only. |
| **Integrity of the host operating system** | If the OS is compromised, the gateway process or DB files may be altered. AegisAgent assumes a trusted host. |
| **Single-agent environments without a gateway** | AegisAgent requires the gateway to be reachable. Offline or air-gapped deployments must pre-configure the SDK to fail closed and use a local gateway instance. |

---

## 5. OWASP LLM Top 10 mapping

| OWASP LLM | Name | AegisAgent coverage |
|-----------|------|---------------------|
| **LLM01** | Prompt Injection | **Closes via provenance.** Indirect prompt injection drives a tool action → provenance label is `untrusted_external` → Cedar `forbid` for mutating actions (T-B1). Direct injection into the agent LLM is out of scope (see Non-guarantees). |
| **LLM02** | Sensitive Information Disclosure | **Mitigates.** Action parameters are hashed, not stored as plaintext. `source_trust=untrusted_external` cannot trigger cross-repo data movement (T-B2). RCA evidence is redacted before the LLM sees it (T-D7). |
| **LLM03** | Supply Chain Vulnerabilities | **Partial.** MCP manifest pinning + hash verification detects server-side supply chain compromise (T-B5). SDK and gateway release signing + SBOM address the software supply chain. Runtime compromise of the SDK binary is a residual risk. |
| **LLM04** | Data and Model Poisoning | **Advisory coverage.** Memory/RAG poisoning is a roadmap item (T-B6). Current coverage: provenance-gating writes that originate from untrusted sources; SOC correlation for suspicious read-then-write sequences. |
| **LLM05** | Improper Output Handling | **Closes via approval integrity.** Tool output from an LLM that has been hijacked must still pass the `action_hash` check and Cedar evaluation before executing. Unfiltered output cannot bypass B3. |
| **LLM06** | Excessive Agency | **Closes via fail-closed + approval.** High-risk and mutating actions require explicit human approval bound to a specific action hash. Unknown tools are denied by default. Runaway agents are detected (SOC `runaway` incident, ≥10 actions in 30s). |
| **LLM07** | System Prompt Leakage | **Out of scope.** AegisAgent does not inspect or protect LLM system prompts. |
| **LLM08** | Vector and Embedding Weaknesses | **Out of scope (roadmap).** AegisAgent does not currently inspect RAG inputs. Provenance gating limits blast radius of a poisoned retrieval result (T-B6). |
| **LLM09** | Misinformation | **Out of scope.** AegisAgent does not evaluate the factual accuracy of agent outputs. |
| **LLM10** | Unbounded Consumption | **Mitigates.** Per-agent rate limiting (token bucket: `AEGIS_RATE_LIMIT_CAPACITY` + `AEGIS_RATE_LIMIT_REFILL_RATE`). SOC `runaway` and `deny_storm` incidents detect and auto-contain runaway agents. |

---

## 6. MITRE ATLAS mapping

MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) tactics mapped to AegisAgent's threat classes and controls.

| ATLAS Tactic | Relevant techniques | AegisAgent control |
|--------------|--------------------|--------------------|
| **Initial Access** | Phishing via LLM, supply chain compromise of ML artifacts | MCP manifest pinning (T-B5); SDK signing; provenance gating entry point (B1) |
| **Execution** | LLM prompt injection (direct/indirect), exploit public-facing ML API | Trust-provenance deterministic `forbid` (G3); fail-closed B3 (G1) |
| **Persistence** | Backdoor ML model, poison training data | Out of scope (roadmap); memory/RAG provenance (T-B6) |
| **Privilege Escalation** | Prompt injection → privilege escalation, abuse agent function calls | Confused-deputy defense (T-B1–T-B4); approval integrity (G2); Cedar `forbid` for untrusted-triggered mutations |
| **Defense Evasion** | Evade ML detection, craft adversarial examples against ML classifiers | Deterministic detection (Law 2); provenance labels are not ML outputs (G3); score-gating prohibited (Law 1) |
| **Credential Access** | Steal ML API keys, hijack model endpoints | Token Broker pattern (agents never hold raw tool credentials); hashed agent tokens; short-lived credentials |
| **Discovery** | Discover AI model APIs, enumerate ML pipeline | 404 (not 403) for cross-tenant requests; no information leakage about other tenants' resources |
| **Collection** | Exfiltrate training data via model inversion, LLM data leakage | Provenance gating prevents untrusted-triggered read→public-write (T-B2); receipts provide audit trail |
| **Exfiltration** | Data exfiltration via LLM outputs | Action-level gating: cross-boundary data movement requires approval + provenance; SOC sequence correlation (AEG-3007) |
| **Impact** | Manipulate ML model output, denial of ML service | Approval integrity (G2) prevents execute-different-action; SOC response engine contains runaway agents (G5 Law 4) |

---

## 7. Security controls summary

The following table maps security properties to their implementation location for auditors.

| Property | Implementation |
|----------|---------------|
| Fail-closed on gateway unreachable | `sdk-python/aegisagent/decorator.py`, `sdk-go/aegis/protect.go`, `sdk-typescript/src/protect.ts` |
| `action_hash` canonicalization | `sdk-python/aegisagent/canon.py`, `sdk-go/canon/canon.go`, `sdk-typescript/src/canon.ts`, `gateway/src/routes.rs` |
| Byte-equality gate | `tests/canonical_action_vectors.json`, cross-language CI |
| Single-use approval (replay defense) | `gateway/src/db.rs` → `consume_approval`; `gateway/src/routes.rs` → `consume_approval` handler |
| Approval expiry | `gateway/src/routes.rs` → `get_approval` (`EXPIRED` state); SDK decorator expiry check |
| Trust-provenance Cedar evaluation | `gateway/src/policy.rs`; `gateway/policies.cedar` |
| Tenant-scoped SQL | `gateway/src/db.rs` — every query binds `tenant_id` |
| Receipt hash chain | `gateway/src/routes.rs` → `emit_action_receipt`; `gateway/src/sign.rs` (Ed25519) |
| SOC out-of-band isolation | `gateway/src/events.rs` → `tokio::mpsc` channel; `drain` runs in dedicated Tokio task |
| Deterministic detection (no LLM) | `gateway/src/detect.rs`; `gateway/src/rule_dsl.rs` |
| RCA LLM sandboxing | `gateway/src/narrate.rs` — no tools, no authority, display-only output |
| Advisory-only composite risk | `gateway/src/risk.rs` — score written to `decisions` row and response; never read by Cedar |
| MCP manifest pinning | `gateway/src/routes.rs` → `discover_mcp_tools`; `mcp_servers.manifest_hash` column |
| Redaction of secrets | `gateway/src/main.rs` → `redact_secrets`; hashes stored, not raw payloads |

---

## 8. Deployment security notes

- **Binding:** The gateway binds `127.0.0.1:8080` by default (`AEGIS_BIND_ADDR`). Never expose the gateway on `0.0.0.0` in production without a reverse proxy and mTLS.
- **Agent tokens:** Stored as SHA-256 hashes (`agents.token_hash`). The plaintext token is returned once at registration and never again.
- **Webhook secrets:** Callback `secret` is stored as `sha256(secret)` (`approvals.callback_secret_hash`). The plaintext secret is never persisted.
- **Secrets in logs:** The `redact_secrets` middleware strips bearer tokens, API keys, and passwords from log lines before emission.
- **Ed25519 receipt signing:** Optional. Set `AEGIS_SIGN_RECEIPTS=true` + `AEGIS_SIGNING_KEY_PATH`. Without signing, receipt integrity relies on the hash chain alone (tamper-evident, not tamper-proof against a full DB compromise).
- **Rate limiting:** Default token bucket is 100 burst / 10 refill per second per tenant. Increase via `AEGIS_RATE_LIMIT_CAPACITY` / `AEGIS_RATE_LIMIT_REFILL_RATE` for production load.
- **SQLite ceiling:** SQLite WAL mode caps `/v1/authorize` at ~130–150 req/s per instance. For higher throughput, migrate to PostgreSQL (see [`docs/performance-baseline.md`](performance-baseline.md)).

---

*For threat IDs (T-A1–T-D7), STRIDE analysis, assurance regression tests, and the governing principle, see [`AegisAgent_Threat_Model.md`](AegisAgent_Threat_Model.md).*
