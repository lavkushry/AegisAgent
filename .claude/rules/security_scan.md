---
globs:
  - "gateway/src/**/*.rs"
  - "src/**/*.rs"
  - "lib/storage/**/*.rs"
  - "lib/policy/**/*.rs"
  - "SECURITY.md"
---

# AI Skill: Security Audit & Scan Runbook (`skills/security_scan.md`)

This skill defines the procedures and verification steps for performing security audits, scanning code, and validating dependencies when modifying the AegisAgent codebase.

---

## 1. Dependency Validation

### Purpose
Ensure no malicious, vulnerable, or unauthorized libraries are added to the Rust gateway or Python SDK.

### Runbook Steps:
1. **Pre-Import Verification:** Before importing or adding any library dependency, the agent must check current security alerts or use dependency audit tools (e.g., `cargo audit` in Rust, `safety` or `pip-audit` in Python).
2. **Locked Dependencies:** Always verify that locks (`Cargo.lock` or `requirements.txt`) are updated and commit them.
3. **No Wildcard Versions:** Never use wildcard (`*`) dependencies. Always define precise semantic versions.

---

## 2. Multi-Tenant Data Isolation Audit (CRITICAL)

### Purpose
To prevent cross-tenant data exposure (CWE-284). Since AegisAgent is a multi-tenant gateway, a tenant must never be allowed to access, modify, or view another tenant's agents, tools, approvals, or audit logs.

### Runbook Steps:
1. **Verify Query Constraints:** Every SQL query executed within the gateway must filter by `tenant_id`. Verify this constraint by checking the query strings:
   - **Correct (Filters by Tenant):**
     ```rust
     sqlx::query("SELECT * FROM agents WHERE id = ? AND tenant_id = ?")
         .bind(agent_id)
         .bind(tenant_id)
     ```
   - **Incorrect (Omit Tenant constraint - DANGEROUS):**
     ```rust
     sqlx::query("SELECT * FROM agents WHERE id = ?") // Fails to partition by tenant!
         .bind(agent_id)
     ```
2. **Review Handler Context:** Ensure that handlers extract the `tenant_id` from the authenticated request credentials or session token and pass it down to the database access layer.
3. **Write Tenant Isolation Tests:** When testing, always verify that queries attempted with tenant A's token cannot retrieve data belonging to tenant B.

---

## 3. Parameterization & SQL Injection Prevention

### Purpose
To prevent SQL injection (CWE-89) in SQLite database queries.

### Runbook Steps:
1. **Never Concatenate:** Inspect all SQL queries. Ensure there are absolutely no string concatenations (`format!`, `+`, or f-strings) involving user-supplied or agent-supplied input inside SQL queries.
2. **Query Verification:**
   - **Correct (SQLx Parameterized Query):**
     ```rust
     sqlx::query("SELECT * FROM agents WHERE id = ? AND tenant_id = ?")
         .bind(agent_id)
         .bind(tenant_id)
         .fetch_optional(pool)
         .await
     ```
   - **Correct (SQLx Query Macro with compile-time check):**
     ```rust
     sqlx::query!(
         "SELECT name, type FROM tools WHERE tenant_id = ? AND tool_key = ?",
         tenant_id,
         tool_key
     )
     .fetch_optional(pool)
     .await
     ```

---

## 4. Network Interface Binding

### Purpose
To prevent unauthorized access to local services during testing.

### Runbook Steps:
1. **Localhost Binding:** Verify that the gateway's server listener config binds strictly to the loopback interface (`127.0.0.1`) for testing and local development, avoiding wildcard bindings (`0.0.0.0`).
2. **Verification Command:** Inspect `gateway/src/config.rs` and `gateway/src/main.rs`. Search for bind targets:
   ```bash
   grep -ri "0.0.0.0" gateway/
   ```
   If any matches are found outside production deployment scripts (like Helm/Docker), flag them as policy violations.

---

## 5. Running the Static Security Scanner

### Purpose
Detect common software vulnerabilities in source code before merging.

### Runbook Steps:
1. **Run the Scanner:** Proactively run the security scanner (such as `cargo-clippy`, `bandit` for Python, or integrated MCP scanners) on all modified files.
2. **Scan Command Example:**
   ```bash
   cargo clippy --manifest-path gateway/Cargo.toml -- -D warnings
   # And for python
   bandit -r sdk-python/
   ```

---

## 6. Security Audit Log Compilation

### Purpose
Produce a clean report detailing design boundaries and verified parameters.

### Runbook Steps:
1. **Generate Audit Report:** After completing major changes, compile a markdown security audit report.
2. **Audit Checklist:**
   - [ ] Parameterized all database inputs.
   - [ ] Verified `tenant_id` filtering constraints on all database operations.
   - [ ] Bound TCP listeners to `127.0.0.1` for tests.
   - [ ] Verified dependencies.
   - [ ] Ensured token generation uses cryptographically secure random number generators (e.g., `rand` in Rust, `secrets` in Python).
   - [ ] **Secure Defaults Audit:**
     - [ ] Unknown agent request results in a fail-closed deny.
     - [ ] Unknown tool request results in a fail-closed deny.
     - [ ] Unknown MCP server/tool results in a fail-closed deny.
     - [ ] Critical risk action is forbidden/denied by default.
     - [ ] High-risk action triggers approval by default.
     - [ ] Approval callback endpoint verifies signature/token.
     - [ ] Sensitive payloads (secrets, tokens, credentials) are redacted from logs and events.

---

## 7. Agent Harness & Configuration Security Audit (AgentShield)

### Purpose
To scan agent harness configurations, rule files, and system settings to prevent prompt injection, excessive agent permissions, or leakage of sensitive API keys through local configuration files.

### Runbook Steps:
1. **Config File Auditing:** Regularly scan the `.claude/` directory and settings files for plaintext credentials or hardcoded keys.
2. **Scan Command:** Run configuration scanner to check for risks:
   ```bash
   npx ecc-agentshield scan .
   ```
3. **Audit Rules compliance:** Verify that `.cursorrules` and `.clauderules` are compiled without any user-overridden rules that bypass the Agent Firewall.
4. **Context Integrity Audit:** Verify that prompt templates or policy configurations do not contain user inputs embedded without escaping (preventing prompt injection).
