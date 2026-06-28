# AegisAgent Architecture Patterns (Qdrant-Inspired)

> **MANDATORY:** Every AI agent working on this codebase MUST follow these patterns.
> These rules are inspired by [Qdrant](https://github.com/qdrant/qdrant) and are non-negotiable.

> **DUAL PROTOCOL:** AegisAgent serves both **REST (Axum)** and **gRPC (tonic + protobuf)** on
> separate ports, exactly like Qdrant serves actix-web REST and tonic gRPC. All new endpoints
> MUST be implemented on both interfaces. Protobuf is the source of truth for types.

---

## 1. Workspace Structure — Layered Crate Architecture

AegisAgent uses a **Cargo workspace with independent library crates** under `lib/`.
The binary entrypoint lives in `src/` and is deliberately thin.

```
AegisAgent/
├── Cargo.toml                    # workspace root
├── config/config.yaml            # YAML configuration (Qdrant pattern)
├── src/                          # binary crate (THIN — route wiring + startup only)
│   └── src/
│       ├── main.rs               # CLI (clap), config load, Axum router, dual-server startup, graceful shutdown
│       ├── grpc.rs               # gRPC service implementations (Tonic server)
│       ├── routes/               # REST handlers (parse → service → respond)
│       ├── admission.rs          # Admission webhook clients
│       ├── jobs.rs               # Periodic background cron jobs
│       ├── gh_checks.rs          # GitHub Checks API client
│       └── gh_comment.rs         # GitHub App PR commenter logic
│   └── Cargo.toml                # gateway binary manifest
├── lib/
│   ├── common/ (aegis-common)    # shared types, errors, crypto — NO domain logic
│   ├── api/ (aegis-api)          # protobuf definitions + generated code + OpenAPI models
│   │   ├── proto/                # .proto files (SOURCE OF TRUTH for all types)
│   │   │   ├── aegis.proto       # core service: Authorize, Approve, Agents
│   │   │   ├── soc.proto         # SOC service: Alerts, Incidents, Rules
│   │   │   └── admin.proto       # admin service: Tenants, MCP, Config
│   │   └── src/
│   │       ├── grpc/             # tonic-generated Rust code (build.rs + prost)
│   │       ├── models.rs         # REST request/response types (derive from proto where possible)
│   │       └── records.rs        # DB record types
│   ├── storage/ (aegis-storage)  # DB trait + SQLite/PostgreSQL implementations
│   ├── policy/ (aegis-policy)    # Cedar engine, trust chain, risk scoring
│   └── soc/ (aegis-soc)         # detection, correlation, response engine
├── sdk-python/
├── sdk-go/
├── sdk-typescript/
└── e2e/
```

### Rules:
- **`src/` is THIN.** It contains ONLY route wiring, CLI parsing, config loading, and server startup. Zero business logic.
- **All business logic lives in `lib/` crates.** REST handlers AND gRPC service impls call the same service methods from `lib/storage` and `lib/policy`.
- **Each `lib/` crate is independently compilable and testable** (`cargo test -p aegis-common`, etc.).
- **Dual-protocol startup:** `main.rs` spawns two servers — Axum REST (default port 8080) and tonic gRPC (default port 6334) — on separate Tokio tasks. Both share the same `AppState`.

---

## 2. Dependency Flow — Downward Only (NEVER upward)

```
aegis-common          ← depends on nothing internal
    ↑
aegis-api             ← depends on common only
    ↑
aegis-storage         ← depends on api + common
aegis-policy          ← depends on api + common (NEVER storage)
    ↑
aegis-soc             ← depends on storage + api + common
    ↑
src/ (binary)         ← depends on ALL lib/ crates
```

### Rules:
- `storage` and `policy` MUST NEVER depend on each other.
- `soc` may depend on `storage` (it needs DB access for detection rules), but never on the binary.
- `common` MUST have zero project-internal dependencies.
- Circular dependencies are a **hard build failure**. `cargo tree --workspace` must show a clean DAG.

---

## 3. Trait-Based Storage Backend (Pluggable Pattern)

Storage access is abstracted behind the `StorageBackend` trait in `lib/storage/src/traits.rs`.
HTTP handlers receive `Arc<dyn StorageBackend>`, never a raw `SqlitePool`.

```rust
#[async_trait::async_trait]
pub trait StorageBackend: Send + Sync + 'static {
    async fn get_agent_by_token(&self, tenant_id: &str, token: &str)
        -> Result<Option<AgentRecord>, AegisError>;
    async fn insert_decision(&self, record: &DecisionRecord)
        -> Result<(), AegisError>;
    // ... all DB operations are trait methods
}
```

### Rules:
- **New DB operations** → add a method to `StorageBackend` trait + implement on `SqliteBackend`.
- **Never use `sqlx::SqlitePool` directly** in handlers or service logic — always go through the trait.
- **Future PostgreSQL backend** → implement the same trait on `PgBackend`.

---

## 4. Type Ownership — Protobuf is the Source of Truth

All request/response types are defined as **Protocol Buffer messages** in `lib/api/proto/*.proto`.
`build.rs` generates Rust code via `tonic-build` + `prost`. REST models derive from or mirror proto types.
Both the binary (REST handlers + gRPC services) and the library crates import from `aegis-api`.

### Rules:
- **New API type?** → Define it as a protobuf message in `lib/api/proto/aegis.proto` first, then mirror in `models.rs` for REST JSON if needed.
- **New DB record struct?** → Define it in `lib/api/src/records.rs` (DB records are internal, not on the wire).
- **Never define types in handlers** that are used by lib crates — that creates upward dependencies.
- **gRPC types are auto-generated.** Never hand-write types that `tonic-build` should produce.
- **REST types mirror proto types** but may add `#[serde]` attributes for JSON compatibility.

---

## 5. Dual-Protocol Handler Pattern — REST (Axum) + gRPC (tonic)

Both REST handlers (`src/routes/`) and gRPC service impls (`src/grpc.rs`) call the **same service layer**.
Neither contains business logic — they are thin protocol adapters.

### REST Handler (Axum):
```rust
// src/routes/authorize.rs
pub async fn authorize_action(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let request: AuthorizeRequest = parse_or_400(&body)?;
    let decision = state.policy_engine.authorize(&request)?;
    let result = state.storage.insert_decision(&decision).await?;
    Json(AuthorizeResponse::from(result))
}
```

### gRPC Service Impl (tonic):
```rust
// src/grpc.rs
#[tonic::async_trait]
impl aegis_proto::aegis_service_server::AegisService for AegisGrpcService {
    async fn authorize(
        &self,
        request: tonic::Request<aegis_proto::AuthorizeRequest>,
    ) -> Result<tonic::Response<aegis_proto::AuthorizeResponse>, tonic::Status> {
        let req = request.into_inner();
        // Call the SAME service layer as REST
        let decision = self.state.policy_engine.authorize(&req.into())?;
        let result = self.state.storage.insert_decision(&decision).await
            .map_err(|e| tonic::Status::internal(e.to_string()))?;
        Ok(tonic::Response::new(result.into()))
    }
}
```

### Rules:
- Both protocols do THREE things: **parse → service call → respond**. Nothing else.
- **REST and gRPC call the same `lib/` service methods.** No code duplication.
- **No SQL queries in handlers or gRPC impls.** Call `state.storage.method()` instead.
- **No Cedar evaluation in handlers or gRPC impls.** Call `state.policy_engine.authorize()` instead.
- **Every new endpoint MUST be implemented on both REST and gRPC.**
- **gRPC errors use `tonic::Status`; REST errors use `AegisError → IntoResponse`.**

---

## 6. Configuration — YAML + Env Override (Qdrant Pattern)

Configuration is loaded from `config/config.yaml` with env var overrides.

```yaml
storage:
  backend: sqlite
  sqlite:
    path: ./aegis.db
    busy_timeout_ms: 5000

gateway:
  host: "127.0.0.1"
  rest_port: 8080           # Axum REST API
  grpc_port: 6334           # tonic gRPC API (Qdrant uses 6334)
  tls:
    enabled: false
    cert_path: null
    key_path: null

policy:
  cedar_path: ./policies.cedar
```

### Rules:
- **Config struct** lives in `src/settings.rs` (binary crate). Uses `config` crate with YAML + env layers.
- **Never scatter env var reads** across lib crates. Config is loaded once at startup and passed down.
- **Each lib crate accepts config via constructor parameters**, not by reading env vars internally.
- **Both REST and gRPC ports are configurable.** Env overrides: `AEGIS_REST_PORT`, `AEGIS_GRPC_PORT`.

---

## 7. Error Types — `AegisError` in `aegis-common`

All crates use a shared `AegisError` enum from `lib/common/src/errors.rs`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum AegisError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Policy evaluation failed: {0}")]
    Policy(String),
    #[error("Tenant not found: {0}")]
    TenantNotFound(String),
    #[error("Authentication failed")]
    Unauthorized,
    // ...
}
```

### Rules:
- **Never use `anyhow` in library crates.** `anyhow` is for the binary only.
- **All lib functions return `Result<T, AegisError>`**, never `Result<T, sqlx::Error>` directly.
- **Handlers convert `AegisError` → HTTP status code** via `IntoResponse` impl.

---

## 8. Performance Rules (from `/v1/authorize` Latency Analysis)

- **Parallelize independent DB reads** with `tokio::join!` (#1510).
- **Debounce write-heavy heartbeats** (`touch_agent_last_seen`) to background batches (#1511).
- **Fire-and-forget post-decision writes** that don't affect the response body (#1512).
- **Cache rarely-changing config** (risk weights, tenant settings) with TTL (#1513).
- **The inline path is sacred** — `POST /v1/authorize` has a <75ms budget (Law 3).
- **Detection is asynchronous** — emit events via non-blocking channel, consume out-of-band.

---

## 9. Testing Patterns

- **Unit tests** live inside each lib crate's source files (`#[cfg(test)] mod tests { ... }`).
- **Integration tests** live in the binary crate's `tests/` directory.
- **E2E tests** (Playwright) live in `/e2e/` — test REST endpoints.
- **gRPC integration tests** use `tonic::transport::Channel` to test the gRPC interface directly.
- **Cross-language corpus tests** verify `aegis-jcs-1` byte parity across all SDKs.
- **Proto contract tests** verify that `.proto` files and REST `models.rs` stay in sync.
- **Verify commands** (must all pass before merge):
  ```bash
  cargo check --workspace
  cargo test --workspace
  cargo fmt --all -- --check
  cargo clippy --workspace -- -D warnings
  ```

---

## 10. The Four Design Laws (NEVER violate)

1. **Deterministic policy decides; scores never gate.** Cedar evaluates trust level. `risk_score` is advisory only.
2. **The LLM investigates; it never decides.** Only the RCA narrator uses an LLM, sandboxed.
3. **The inline path is sacred; detection is asynchronous.** `/v1/authorize` < 75ms. SOC is out-of-band.
4. **Every moat primitive is preserved end-to-end.** `aegis-jcs-1` canonicalization, hash-bound approvals, hash-chained receipts.
