# AegisAgent Developer Context (`CLAUDE.md`)

This guide outlines build, test, and style guidelines for working on the AegisAgent codebase. Follow these rules to ensure consistency and correct execution.

---

## 1. Build and Run Commands

### Gateway (Rust + Axum + SQLx + SQLite)
- **Check code compiles:** `cargo check --manifest-path gateway/Cargo.toml`
- **Build debug binary:** `cargo build --manifest-path gateway/Cargo.toml`
- **Build production release:** `cargo build --release --manifest-path gateway/Cargo.toml`
- **Run the local gateway server:** `cargo run --manifest-path gateway/Cargo.toml`

### SDK (Python)
- **Install in developer mode:** `pip install -e sdk-python/`
- **Verify package dependencies:** `pip check`

---

## 2. Test Execution Commands

### Gateway Tests (Rust)
- **Run all tests:** `cargo test --manifest-path gateway/Cargo.toml`
- **Run specific test:** `cargo test --manifest-path gateway/Cargo.toml -- <test_name>`

### SDK & Integration Tests (Python)
- **Run all tests:** `python -m unittest discover -s sdk-python`
- **Run the integration mock server test:** `python examples/mock_server.py`

---

## 3. Formatting and Linting

### Rust (Gateway)
- **Check formatting:** `cargo fmt --manifest-path gateway/Cargo.toml -- --check`
- **Apply formatting:** `cargo fmt --manifest-path gateway/Cargo.toml`
- **Run linter:** `cargo clippy --manifest-path gateway/Cargo.toml -- -D warnings`

### Python (SDK & Examples)
- **Check formatting:** `black --check sdk-python/ examples/`
- **Apply formatting:** `black sdk-python/ examples/`
- **Run linter:** `flake8 sdk-python/ examples/`

---

## 4. Coding Guidelines & Best Practices

### Security Standards (CRITICAL)
- **SQL Injection Prevention:** **NEVER** use string concatenation to build SQL queries. Always use parameterized queries via `sqlx::query` or compile-time verified queries (`sqlx::query!`).
- **Local Network Bindings:** In all tests and gateway default configurations, bind listeners to `127.0.0.1` instead of `0.0.0.0` to avoid exposing endpoints on open ports.
- **Dependency Safety:** Always run vulnerability checks on any library additions.

### Rust Style & Idioms
- **Async Runtime:** Use Tokio (`#[tokio::main]`) and Axum handlers.
- **Error Handling:** Avoid `.unwrap()` and `.expect()`. Use `?` propagates, map errors to custom HTTP status codes using an implementation of `IntoResponse` for custom errors.
- **Database Pooling:** Use `SqlitePool` from SQLx. Ensure WAL (Write-Ahead Logging) mode and busy timeout are configured on database initialization:
  ```rust
  let opts = SqliteConnectOptions::new()
      .filename("db/aegisagent.db")
      .create_if_missing(true)
      .journal_mode(SqliteJournalMode::Wal)
      .busy_timeout(Duration::from_secs(5));
  let pool = SqlitePool::connect_with(opts).await?;
  ```

### Python SDK Style
- **Type Hints:** Use type annotations for all public SDK interfaces.
- **Decorator Interception:** The `@protect_tool` decorator must transparently intercept calls, query the gateway's `/v1/authorize` endpoint, and perform a blocking-polling loop checking `/v1/approvals/{id}` if a `require_approval` decision is returned.
- **Exception Hierarchy:** Raise dedicated exceptions (e.g. `AegisAuthorizationDenied`, `AegisConnectionError`) rather than generic exceptions.
