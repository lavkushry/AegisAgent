```markdown
# AegisAgent Development Patterns

> Auto-generated skill from repository analysis — updated for Qdrant-inspired architecture

## Overview
This skill teaches the core architecture, coding conventions, and workflows used in AegisAgent.
AegisAgent follows a **Qdrant-inspired layered Cargo workspace** with dual-protocol serving
(REST via Axum + gRPC via tonic). **Read `docs/ARCHITECTURE.md` first** — it is the source of truth.

## Architecture (Qdrant-Inspired)

### Workspace Layout
```
AegisAgent/
├── Cargo.toml                    # workspace root
├── config/config.yaml            # YAML config
├── src/                          # THIN binary crate (handlers + startup only)
│   ├── handlers/                 # REST handlers (Axum, port 8080)
│   ├── grpc/                     # gRPC service impls (tonic, port 6334)
│   ├── axum_app.rs               # REST route wiring
│   ├── tonic_app.rs              # gRPC service wiring
│   └── main.rs                   # CLI + dual-server startup
├── lib/
│   ├── common/ (aegis-common)    # errors, crypto, metrics — NO domain logic
│   ├── api/ (aegis-api)          # proto/ defs + generated code + REST models
│   │   └── proto/*.proto         # SOURCE OF TRUTH for API types
│   ├── storage/ (aegis-storage)  # StorageBackend trait + SQLite impl
│   ├── policy/ (aegis-policy)    # Cedar engine, trust chain, risk
│   └── soc/ (aegis-soc)         # detection, correlation, response
└── sdk-python/ sdk-go/ sdk-typescript/
```

### Dependency Rule (downward only — NEVER upward)
```
common ← api ← storage/policy ← soc ← binary
```

### Dual Protocol (Qdrant Pattern)
- **REST** (Axum) on port 8080, **gRPC** (tonic + protobuf) on port 6334
- Both share the same `AppState` and call the same `lib/` service methods
- **Every new endpoint MUST be implemented on both REST and gRPC**
- **Protobuf is the source of truth** for API types — define `.proto` messages first

## Coding Conventions

### File Naming
- Use **snake_case** for Rust file names (e.g., `agent_service.rs`, `trust_chain.rs`)
- Proto files: `aegis.proto`, `soc.proto`, `admin.proto`

### Import Style
- Use `crate::` for binary-crate imports, crate name for cross-crate imports:
  ```rust
  use aegis_common::errors::AegisError;
  use aegis_api::models::AuthorizeRequest;
  use aegis_storage::traits::StorageBackend;
  ```

### Handler Pattern (both REST and gRPC)
```rust
// THREE steps only: parse → service call → respond
// REST (src/handlers/):
let request = parse_or_400(&body)?;
let result = state.storage.some_method(&request).await?;
Json(result)

// gRPC (src/grpc/):
let req = request.into_inner();
let result = self.state.storage.some_method(&req.into()).await
    .map_err(|e| tonic::Status::internal(e.to_string()))?;
Ok(tonic::Response::new(result.into()))
```

### Error Handling
- All lib functions return `Result<T, AegisError>` (from `aegis-common`)
- REST: `AegisError` → `IntoResponse` (HTTP status)
- gRPC: `AegisError` → `tonic::Status`
- **Never use `.unwrap()`/`.expect()`** in production paths

### Commit Messages
- Follow **Conventional Commits**: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`

## Workflows

### Creating a New API Endpoint
1. Define the proto message in `lib/api/proto/aegis.proto`
2. Run `cargo build -p aegis-api` to regenerate code
3. Add REST model mirror in `lib/api/src/models.rs` if needed
4. Add `StorageBackend` trait method in `lib/storage/src/traits.rs`
5. Implement on `SqliteBackend` in `lib/storage/src/sqlite/`
6. Create REST handler in `src/handlers/`
7. Create gRPC service impl in `src/grpc/`
8. Wire both in `axum_app.rs` and `tonic_app.rs`
9. Write tests in the lib crate + gRPC integration test

### Creating a New DB Operation
1. Add trait method to `StorageBackend`
2. Implement on `SqliteBackend`
3. Write unit test inside `lib/storage/`
4. Call from handler/gRPC via `state.storage.method()`

### Writing and Running Tests
```bash
# All workspace tests
cargo test --workspace

# Single crate
cargo test -p aegis-storage

# Lint
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
```

## Commands
| Command        | Purpose                                   |
|----------------|-------------------------------------------|
| /new-feature   | Start a new feature implementation        |
| /fix-bug       | Begin work on a bug fix                   |
| /run-tests     | Run all tests in the codebase             |
```
