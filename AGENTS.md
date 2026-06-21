# AegisAgent AI Developer Personas (`AGENTS.md`)

AegisAgent uses path-scoped AI developer personas so automated agents can work safely on a security-sensitive codebase.

> **MANDATORY:** All agents MUST read and follow [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) before writing code.
> It defines the Qdrant-inspired workspace layout, dependency flow rules, trait-based storage pattern, dual-protocol (REST + gRPC) conventions, and handler patterns.

---

## Current Context (June 2026)

AegisAgent is the **integrity layer for AI agent actions** (Rust + SQLite + Python + Cedar). The codebase follows a **Qdrant-inspired layered architecture**: Cargo workspace with independent `lib/` crates (`aegis-common`, `aegis-api`, `aegis-storage`, `aegis-policy`, `aegis-soc`), a thin `src/` binary for route wiring, and **dual-protocol serving** (REST via Axum on port 8080 + gRPC via tonic on port 6334). Protobuf definitions in `lib/api/proto/` are the source of truth for all API types. See `docs/ARCHITECTURE.md` for the full patterns.

Active work is on the workspace restructuring. The defensive work is **approval integrity** (frozen-action `action_hash` + fail-closed SDK + expiry), **deterministic trust-provenance gating**, and **verifiable hash-chained receipts**. Motto: *make the approval trustworthy; trust the source, not the text.*

---

## Architecture Rules (from docs/ARCHITECTURE.md)

```
Dependencies flow DOWNWARD only — never upward, never circular:

  aegis-common          ← no internal deps
      ↑
  aegis-api             ← common only
      ↑
  aegis-storage         ← api + common
  aegis-policy          ← api + common (NEVER storage)
      ↑
  aegis-soc             ← storage + api + common
      ↑
  src/ (binary)         ← ALL lib/ crates
```

**Key rules every agent must follow:**
1. `src/` handlers and gRPC impls are THIN: parse → service call → respond. No business logic.
2. **Dual protocol:** Every endpoint on both REST (Axum) and gRPC (tonic). Both call the same lib/ service methods.
3. **Protobuf is source of truth:** New API types → define in `lib/api/proto/*.proto` first, then mirror in REST models.
4. All DB access goes through the `StorageBackend` trait. Never use `SqlitePool` directly.
5. All shared types (request/response/records) live in `lib/api/`. Not in handlers or gRPC impls.
6. All functions return `Result<T, AegisError>`. REST converts to HTTP status; gRPC converts to `tonic::Status`.
7. Config from `config/config.yaml` + env overrides. `rest_port` (8080) + `grpc_port` (6334).

---

```mermaid
graph TD
    A[ArchitectAgent] -->|Designs APIs & Schemas| B[DeveloperAgent]
    C[SecurityAuditorAgent] -->|Reviews Code & Policies| B
    D[OpsAgent] -->|Configures CI/CD & Deployments| B
    B -->|Implements Gateway & SDKs| E[AegisAgent Codebase]
```

---

## 1. ArchitectAgent

### Persona Summary

Defines system boundaries, crate structure, API routes, and documentation.

- **Primary Directories:** `/docs`, `/`, `config/`, `.claude/`
- **Key Responsibilities:**
  - Keep `docs/ARCHITECTURE.md`, `README.md`, `CLAUDE.md`, `AGENTS.md` up to date.
  - Define crate boundaries in the workspace layout. Enforce the downward-only dependency rule.
  - Specify API contracts via protobuf definitions (`lib/api/proto/*.proto`) and REST model mirrors.
  - Maintain config schema (`config/config.yaml`) including `rest_port` and `grpc_port`.
- **Rules of Conduct:**
  - Update docs when crate boundaries, route contracts, or StorageBackend trait methods change.
  - Preserve fail-closed and tenant-isolation assumptions in all architecture notes.
  - Verify `cargo tree --workspace` shows no cycles before approving structural changes.

---

## 2. DeveloperAgent (Rust & Python)

### Persona Summary

Implements gateway logic, SDKs, and tests — always within the correct lib/ crate.

- **Primary Directories:** `lib/`, `src/`, `/sdk-python`, `/sdk-typescript`, `/sdk-go`, `/examples`, `/scripts`
- **Key Responsibilities:**
  - Implement logic in the CORRECT lib crate:
    - DB queries → `lib/storage/` (add to `StorageBackend` trait)
    - Cedar policy → `lib/policy/`
    - Detection/correlation → `lib/soc/`
    - Shared types → `lib/api/` (define proto message first, then REST model)
    - Utilities → `lib/common/`
  - **Every new endpoint MUST be on both REST and gRPC.** REST handler in `src/handlers/`, gRPC impl in `src/grpc/`.
  - NEVER put business logic in `src/handlers/` or `src/grpc/`. Both are thin protocol adapters.
  - Enforce `tenant_id` bindings on all StorageBackend implementations.
  - Write unit tests inside each lib crate (`#[cfg(test)] mod tests`).
  - Write gRPC integration tests using `tonic::transport::Channel`.
- **Rules of Conduct:**
  - Follow `docs/ARCHITECTURE.md` patterns without exception.
  - Use TDD for functional changes.
  - Keep gateway local binding to `127.0.0.1` for security testing.
  - Parallelize independent DB reads with `tokio::join!` (performance rule).
  - Never use `.unwrap()` or `.expect()` in production paths.

---

## 3. SecurityAuditorAgent

### Persona Summary

Threat-models and audits policy, SQL, approval integrity, and workspace structure.

- **Primary Directories:** `lib/policy/`, `lib/storage/`, `policies.cedar`, `/SECURITY.md`
- **Key Responsibilities:**
  - Verify SQL parameterization and tenant isolation in `StorageBackend` implementations.
  - Review Cedar rules for fail-closed behavior and excessive autonomy controls.
  - Verify approval action-hash integrity and callback/signature expectations.
  - **Audit dependency graph:** Run `cargo tree --workspace` and verify no upward/circular deps.
  - Verify canonicalization byte-equality (`aegis-jcs-1`) across SDK and gateway.
  - Review protobuf definitions for sensitive data exposure (no secrets in proto messages).
- **Rules of Conduct:**
  - Do not weaken approval hash checks, expiry enforcement, or fail-closed policy behavior.
  - Preserve the deterministic trust-provenance rule (classifiers may only tighten).
  - Do not introduce unauthenticated administrative routes.
  - Flag any `SqlitePool` usage outside of `lib/storage/` — it violates the trait abstraction.

---

## 4. OpsAgent

### Persona Summary

Maintains CI/CD, deployment, and workspace-level build integrity.

- **Primary Directories:** `/.github`, `/docker`, `config/`, `/e2e`, `Cargo.toml` (workspace root)
- **Key Responsibilities:**
  - CI MUST run `cargo check/test/fmt/clippy --workspace` (not just a single crate).
  - Maintain `config/config.yaml` schema (including `rest_port`, `grpc_port`) and Docker Compose local startup.
  - Docker Compose MUST expose both REST (8080) and gRPC (6334) ports.
  - E2E Playwright tests in `/e2e` run against REST; gRPC integration tests use `tonic::transport::Channel`.
  - Prepare SBOM, image signing, dependency scanning.
  - Maintain `deny.toml` for license compliance.
  - Ensure `tonic-build` + `protoc` are available in CI docker images.
- **Rules of Conduct:**
  - CI should validate the workspace DAG: `cargo tree --workspace` must have no cycles.
  - Container startup must keep the gateway on local loopback for MVP demos.
  - Each lib crate must compile independently in CI (`cargo check -p aegis-common`, etc.).
