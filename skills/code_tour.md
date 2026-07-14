---
globs:
  - "**/*.md"
  - "*"
---

# AI Skill: Codebase Onboarding Tour (`skills/code_tour.md`)

This skill provides AI developer agents with a step-by-step tour of the AegisAgent codebase structure.

> **READ `docs/architecture.md` FIRST** — it defines all mandatory patterns.

---

## 1. Directory Tree Architecture (Qdrant-Inspired Workspace)

```text
AegisAgent/
├── .claude/              # Runtime rules & project metadata
├── docs/
│   ├── architecture.md   # *** MANDATORY — all patterns defined here ***
│   └── ...
├── config/
│   └── config.yaml       # YAML config (Qdrant pattern, rest_port + grpc_port)
├── src/src/              # Gateway binary crate (adapters stay THIN)
│   ├── main.rs           # startup, config/env resolution, dual-server spawn (REST 8080 + gRPC 6334)
│   ├── routes/           # REST handlers (parse → typed service → respond)
│   ├── grpc.rs           # gRPC service impls (tonic::Request → typed service → tonic::Response)
│   ├── authorize_service.rs  # wire map + GatewayAuthorizeService (Week 3)
│   ├── decision_runtime.rs   # GatewayDecisionRuntime (DecisionRuntime ports)
│   ├── sign.rs, mtls.rs, oidc.rs, policy_watcher.rs, …   # focused gateway modules
│   └── bin/              # auxiliary binaries
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
│   ├── decision/         # aegis-decision: run_authorize_pipeline + DecisionRuntime ports
│   ├── event/            # aegis-event: unwired ADR-0006..0010 prototypes (no production traffic)
│   └── soc/              # aegis-soc: detection, correlation, response engine
├── sdk-python/           # Python SDK (@protect_tool, approval polling)
├── sdk-go/               # Go SDK
├── sdk-typescript/       # TypeScript SDK (alpha)
├── e2e/                  # E2E Playwright tests (REST) + gRPC integration tests
├── policies.cedar        # Cedar policy rules (repo root)
└── scripts/
```

---

## 2. Onboarding Workflow for Developer Agents

When exploring the codebase, study modules in this order:

1. **Architecture Rules (`docs/architecture.md`):**
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
   Deterministic — scores never gate. Policy pack lives at repo-root `policies.cedar`.

5. **Authorize pipeline (`lib/decision/`):**
   Protocol-neutral `run_authorize_pipeline` (admit → preflight → guard → metadata →
   evaluate) behind `DecisionRuntime` ports. Gateway adapters stay thin.

6. **Binary Startup (`src/src/main.rs`):**
   How config is loaded, both servers (REST + gRPC) are spawned on separate Tokio tasks,
   and `AppState` (shared between both) is constructed.

7. **REST Handlers (`src/src/routes/`) + gRPC Impls (`src/src/grpc.rs`):**
   Both are THIN — parse → service call → respond. They must call the same typed
   service seam (`docs/architecture.md` §5). gRPC must not bridge through REST handlers.

8. **SOC Pipeline (`lib/soc/`):**
   Asynchronous detection, correlation, and response. NEVER in the inline authorize path.

9. **Client SDK (`sdk-python/aegisagent/decorator.py`):**
   The `@protect_tool` wrapper, authorization requests, and approval polling.
