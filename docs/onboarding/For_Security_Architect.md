# Onboarding: Security Architect

**Goal:** understand the trust boundaries and security guarantees in ~15 minutes, and know exactly where each claim is enforced in code.

> **Status:** Known-agent integrity controls are largely production-ready. Unknown-agent cage, sensor collection, forced egress, broker force path, ban/quarantine propagation, and multi-replica HA remain Partial.

## Overview

Audit AegisAgent as a chain of deployed enforcement points, not as a feature list. For every claim, identify the principal, tenant binding, canonical bytes, decision authority, durable evidence, failure behavior, bypass path, and test that proves the negative case.

## 1. Read first

1. [../Architecture_Overview.md](../Architecture_Overview.md) §2 (choke points), §5 (trust boundaries), §6 (fail-closed paths)
2. [../AegisAgent_Threat_Model.md](../AegisAgent_Threat_Model.md) — T-A approval manipulation · T-B confused deputy · T-C evidence tampering · T-D attacks on the SOC
3. [../Implementation_Status.md](../Implementation_Status.md) — the honest ledger; anything 📐 is a paper control

## 2. The two claims worth auditing hardest

| Claim | Enforcement | Verify yourself |
|---|---|---|
| An approval can only execute the exact approved bytes | `action_hash` binding + single-use atomic consume + SDK re-check | `src/src/routes/approval.rs`, `lib/storage/src/db/approvals.rs`; run `examples/approve_then_swap_demo.py` |
| Untrusted content cannot authorize mutating actions | channel-derived trust labels, tighten-only, `trust_chain::propagate`, Cedar forbid rules | `lib/policy/src/trust_chain.rs`, `policies.cedar`; deny tests in `lib/policy` |

## 3. Boundary-by-boundary checklist

- **B1 ingest:** HMAC on GitHub webhooks (`AEGIS_GITHUB_WEBHOOK_SECRET`); unlabeled = `unknown`, treated as untrusted.
- **B2 agent process:** the SDK is a *cooperating* fail-closed enforcement point, not a trust anchor — the gateway recomputes hashes and consumes approvals server-side.
- **B3 authn:** bearer/JWT (rotatable, `jwt_secret_candidates`), optional mTLS (`src/src/mtls.rs`, CRL support, unknown CN → 401); `AEGIS_JWT_REQUIRED=true` for production.
- **B4 approval:** per-IP rate limit + per-approval-id brute-force tracker (#1307).
- **B5 tenant isolation:** every query binds `tenant_id` — audit `lib/storage/src/db/*`; isolation tests exist; CWE-284 runbook in `.claude/rules/security_scan.md`.
- **Evidence:** hash-chained receipts + hash-chained policy audit log; optional Ed25519; parity vectors in `tests/`.
- **Supply chain:** cosign keyless signing, SLSA L3 provenance, SBOMs (`release-publish.yml`); cargo-deny license gate; Semgrep/secret/container scans.
- **Runtime plane (Partial):** signed control commands, process enforcement, cage/egress/sensor/broker skeletons exist; real collectors and complete force paths remain. See [../flows/Control_Command_Flow.md](../flows/Control_Command_Flow.md).

## 4. Fail-closed spot checks

`get_agent_by_token` excludes quarantined **and** deleted agents · encryption-at-rest fails startup if key set without sqlcipher build · policy-bundle endpoint 501s without a verifying key · Slack callback 404s without a signing secret · SDK refuses on gateway-unreachable for mutating calls. Catalogue: [../fail-closed-behavior.md](../fail-closed-behavior.md).

## 5. Residual risks to keep on your register

- SDK-side enforcement assumes the agent process is cooperating; the partial cage/runtime plane addresses hostile workloads only in supported deployments.
- The egress proxy exists, but forced transparent cage integration is incomplete; known-agent traffic can bypass it unless the deployment makes it mandatory.
- SQLite single-writer: availability (not integrity) consideration until Postgres GA (#1194).
- Prompt/model ingest and the LLM gateway exist, but broader provider adapters and prompt/model query UI remain incomplete; verify lineage coverage for the deployed path.

## 6. Where to poke

`grep -rn "unwrap()" src/src/ lib/` (should be tests only) · `grep -ri "0.0.0.0"` (deploy configs only) · run `cargo deny check licenses` · read the ADRs ([../adr/index.md](../adr/index.md)) for why Cedar/SQLite/JCS/Ed25519 were chosen.

## 7. Verification Example

```bash
python3 examples/approve_then_swap_demo.py
cargo tree --workspace
node scripts/validate-docs.mjs
```

The first proves the headline negative case, the second exposes dependency direction/cycles, and the third checks documentation/status/traceability integrity.

## 8. Security and Failure Handling

Assume the agent, external content, tool output, and network are untrusted. Treat SDK enforcement as cooperative, receipt signing keys and policy bundles as high-value assets, and the database as evidence infrastructure. Require explicit residual-risk documentation for every partial force path.

## 9. Operations and Troubleshooting

For every production topology, trace identity and evidence across listener, gateway, storage, SDK, SOC, and runtime components. Exercise gateway loss, storage loss, policy parse failure, expired/mismatched approvals, replay, cross-tenant access, receipt corruption, sensor silence, and command replay. Findings update the threat model, status ledger, runbooks, and architecture map together.

## 10. References

[Security Model](../security-model.md) · [Threat Model](../AegisAgent_Threat_Model.md) · [Fail-Closed Behavior](../fail-closed-behavior.md) · [Implementation Status](../Implementation_Status.md)
