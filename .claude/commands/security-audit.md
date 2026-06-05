---
description: Run the AegisAgent security audit — tenant isolation, SQL parameterization, fail-closed defaults, 127.0.0.1 bind, secret redaction, and the secure-defaults checklist.
allowed-tools: Bash, Read, Grep
---

Audit the current changes (or the whole gateway) against the security runbook. Report findings grouped by
severity, each with `file:line`.

1. **Tenant isolation (CWE-284):** every query on `agents/tools/decisions/approvals/receipts/mcp_*` filters `tenant_id`.
2. **SQL injection (CWE-89):** no `format!`/`+`/f-strings building SQL with dynamic input; parameterized SQLx only.
3. **Fail-closed:** unknown agent/tool/MCP → deny; critical → deny; high-risk → approval; approval timeout/expiry → auto-deny; audit/receipt write failure on high-risk → deny.
4. **Local bind:** `grep -ri "0.0.0.0" gateway/` → flag any outside deploy scripts (Helm/Docker).
5. **Secrets:** redacted from logs/receipts (store input/output hashes, not payloads).
6. **Provenance deterministic:** classifiers/scores may only tighten, never gate.

Optionally run `cargo clippy --manifest-path gateway/Cargo.toml -- -D warnings` and `bandit -r sdk-python/`.
For the full procedure see `.claude/rules/security_scan.md`.
