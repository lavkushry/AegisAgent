---
globs:
  - "**/*.md"
  - "*"
---

# AI Skill: Codebase Onboarding Tour (`skills/code_tour.md`)

This skill provides AI developer agents with a step-by-step tour of the AegisAgent codebase structure.

> **READ `docs/ARCHITECTURE.md` FIRST** — it defines all mandatory patterns.

---

## 1. Directory Tree Architecture (Qdrant-Inspired Workspace)

```text
AegisAgent/
├── .claude/              # Runtime rules & project metadata
├── docs/
│   ├── ARCHITECTURE.md   # *** MANDATORY — all patterns defined here ***
│   └── ...
├── config/
│   └── config.yaml       # YAML config (Qdrant pattern, rest_port + grpc_port)
├── src/                  # Binary crate (THIN — route wiring ONLY)
│   ├── main.rs           # CLI (clap), dual-server startup (REST + gRPC)
│   ├── settings.rs       # YAML config deserialization
│   ├── axum_app.rs       # REST Router wiring (port 8080)
│   ├── tonic_app.rs      # gRPC Server wiring (port 6334)
│   ├── handlers/         # REST handlers (parse → service → respond)
│   ├── grpc/             # gRPC service impls (tonic::Request → service → tonic::Response)
│   ├── middleware.rs      # ETag, compression, TLS
│   └── startup.rs        # graceful shutdown (both servers)
├── lib/
│   ├── common/           # aegis-common: errors, crypto, metrics (NO domain logic)
│   ├── api/              # aegis-api: proto/ definitions + generated code + REST models
│   │   ├── proto/        # .proto files (SOURCE OF TRUTH for API types)
│   │   │   ├── aegis.proto   # core: Authorize, Approve, Agents
│   │   │   ├── soc.proto     # SOC: Alerts, Incidents, Rules
│   │   │   └── admin.proto   # admin: Tenants, MCP, Config
│   │   └── src/
│   │       ├── grpc/     # tonic-generated code (via build.rs + prost)
│   │       ├── models.rs # REST request/response types (mirror proto)
│   │       └── records.rs # DB record types
│   ├── storage/          # aegis-storage: StorageBackend trait + SQLite/PG impls
│   ├── policy/           # aegis-policy: Cedar, trust chain, risk scoring
│   └── soc/              # aegis-soc: detection, correlation, response engine
├── sdk-python/           # Python SDK (@protect_tool, approval polling)
├── sdk-go/               # Go SDK
├── sdk-typescript/       # TypeScript SDK (alpha)
├── e2e/                  # E2E Playwright tests (REST) + gRPC integration tests
├── policies.cedar        # Cedar policy rules
└── scripts/
```

---

## 2. Onboarding Workflow for Developer Agents

When exploring the codebase, study modules in this order:

1. **Architecture Rules (`docs/ARCHITECTURE.md`):**
   Read this FIRST. It defines the Qdrant-inspired workspace layout, dependency rules,
   trait-based storage, dual-protocol (REST + gRPC) pattern, and handler conventions.

2. **Protobuf Definitions (`lib/api/proto/*.proto`):**
   These are the source of truth for all API types. Understand the service definitions
   and message types before looking at Rust code.

3. **Storage Trait (`lib/storage/src/traits.rs`):**
   The `StorageBackend` trait defines ALL database operations. Both REST handlers and
   gRPC impls call these methods through `Arc<dyn StorageBackend>`.

4. **Policy Engine (`lib/policy/src/cedar.rs`):**
   How Cedar evaluates trust level, action classification, and policy decisions.
   Deterministic — scores never gate.

5. **Binary Startup (`src/main.rs`):**
   How config is loaded, both servers (REST + gRPC) are spawned on separate Tokio tasks,
   and `AppState` (shared between both) is constructed.

6. **REST Handlers (`src/handlers/`) + gRPC Impls (`src/grpc/`):**
   Both are THIN — parse → service call → respond. They call the same `lib/` methods.
   Every endpoint exists on both protocols.

7. **SOC Pipeline (`lib/soc/`):**
   Asynchronous detection, correlation, and response. NEVER in the inline authorize path.

8. **Client SDK (`sdk-python/aegisagent/decorator.py`):**
   The `@protect_tool` wrapper, authorization requests, and approval polling.
