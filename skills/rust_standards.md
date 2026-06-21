---
globs:
  - "**/*.rs"
---

# AI Skill: Rust Coding Standards (`skills/rust_standards.md`)

This skill defines the coding standards, async idioms, serialization rules, and error handling conventions for writing Rust code in the AegisAgent gateway.

---

## 1. Async Tokio Patterns

We use the Tokio async runtime for high-performance concurrency.

### Guidelines:
- **Non-blocking Operations:** Never run synchronous, CPU-intensive, or blocking file operations directly in the async worker threads. Wrap them in `tokio::task::spawn_blocking`.
- **Tokio Timeouts:** Always wrap external network requests or lock-waits with `tokio::time::timeout` to prevent request hangs.
  ```rust
  let response = tokio::time::timeout(
      Duration::from_secs(5),
      client.post(url).send()
  ).await;
  ```

---

## 2. Error Handling (CWE-391 / CWE-397)

Avoid catching generic exceptions or ignoring errors. Code must use explicit, strongly-typed error propagation.

### Guidelines:
- **Never use `.unwrap()` or `.expect()`:** Except in tests, calling these panics the worker thread, causing service degradation. Use `?` or `.map_err()` to propagate errors.
- **Custom Error Types:** Use `thiserror` to define domain-specific errors in the library:
  ```rust
  #[derive(Debug, thiserror::Error)]
  pub enum AegisError {
      #[error("Database error occurred: {0}")]
      Database(#[from] sqlx::Error),
      #[error("Policy evaluation failed: {0}")]
      Policy(String),
      #[error("Authentication failed")]
      Unauthorized,
  }
  ```
- **Axum Integration:** Ensure application errors implement `axum::response::IntoResponse` to return clean, standardized JSON errors to clients.

---

## 3. Serialization (Serde)

Data models must use `serde` for serialization/deserialization.

### Guidelines:
- **Struct Derivations:** Derive `Serialize` and `Deserialize` on all payload models.
- **CamelCase Alignment:** Align JSON fields to snake_case or camelCase matching the API specification:
  ```rust
  #[derive(Debug, Serialize, Deserialize)]
  #[serde(rename_all = "camelCase")]
  pub struct AuthRequest {
      pub tenant_id: Uuid,
      pub agent_key: String,
      pub tool_call: ToolCall,
  }
  ```

---

## 4. Linting and Formatting

Ensure all Rust files pass clippy and format checks:
- Code must format with `cargo fmt`.
- All variables must use `snake_case`, structs and enums must use `PascalCase`.
- Run clippy before committing changes:
  ```bash
  cargo clippy --all-targets -- -D warnings
  ```
