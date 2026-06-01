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

## 2. Parameterization & SQL Injection Prevention

### Purpose
To prevent SQL injection (CWE-89) in SQLite database queries.

### Runbook Steps:
1. **Never Concatenate:** Inspect all SQL queries in `/gateway/src/db.rs` (and other source files). Ensure there are absolutely no string concatenations (`format!`, `+`, or f-strings) involving user-supplied or agent-supplied input inside SQL queries.
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
   - **Incorrect (Vulnerable string formatting):**
     ```rust
     let query = format!("SELECT * FROM tools WHERE tool_key = '{}'", tool_key);
     sqlx::query(&query).fetch_all(pool).await // DANGEROUS!
     ```

---

## 3. Network Interface Binding

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

## 4. Running the Static Security Scanner

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
3. **Remediation:** If the scanner flags a potential vulnerability (e.g., dynamic command execution, unsafe operations, file path manipulation), immediately draft a fix plan, apply it, and rerun the scanner to confirm verification.

---

## 5. Security Audit Log Compilation

### Purpose
Produce a clean report detailing design boundaries and verified parameters.

### Runbook Steps:
1. **Generate Audit Report:** After completing major changes, compile a markdown security audit report.
2. **Audit Checklist:**
   - [ ] Parameterized all database inputs.
   - [ ] Bound TCP listeners to `127.0.0.1` for tests.
   - [ ] Verified dependencies.
   - [ ] Ensured token generation uses cryptographically secure random number generators (e.g., `rand` in Rust, `secrets` in Python).
