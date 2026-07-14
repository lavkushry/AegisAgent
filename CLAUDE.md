# AegisAgent Coding-Agent Context

This file is the compact operational context. Normative rules live in:

1. [docs/architecture.md](docs/architecture.md) — mandatory repository law;
2. [ARCHITECTURE.md](ARCHITECTURE.md) — target HLD and performance contract;
3. [docs/LLD.md](docs/LLD.md) — byte layouts, ownership and algorithms;
4. [MIGRATION_MATRIX.md](MIGRATION_MATRIX.md) — current audit and cutover gates;
5. [CONTRIBUTING.md](CONTRIBUTING.md) — ADR, unsafe, SIMD, test and benchmark requirements.

## Product and status

AegisAgent is the integrity, guardrail, SIEM, and SOC layer for autonomous-agent actions. Current code is a Rust Cargo workspace using Axum/Tokio/tonic/SQLx/Cedar, SQLite/PostgreSQL, Python/TypeScript/Go fail-closed SDKs, a React SOC console, and sensor/cage/proxy/tool-broker binaries.

The approved **target** is Thread-Per-Core decision/ingestion, cache-padded SPSC rings, Arrow-compatible HCMT telemetry, Aho-Corasick guardrails, owned HNSW+PQ, isolated INT8 ONNX, eBPF containment, and Arrow/WASM/WebGL UI. Target does not mean shipped. Use `current`, `shadow`, `target`, and `qualified` exactly as defined in `docs/architecture.md`.

Performance targets are `<1 ms p99` warm deterministic authorization compute, `>=1M events/s/node` telemetry ingest, `<100 ms p99` first deterministic detection, and 60 FPS qualified UI. Current measured results remain in `docs/performance-baseline.md`; never present targets as measurements.

## Invariants

- `aegis-jcs-1` bytes are identical across Rust/Python/TS/Go.
- Approval binds SHA-256 to the exact post-admission executable action.
- Hash mismatch, expiry, replay, unavailable required authority, or failed protected receipt commit blocks execution.
- Trust only tightens; unknown is least trusted.
- Cedar decides. Scores, Aho, vector search, ONNX, and LLM output cannot create allow or loosen trust.
- Every tenant-owned read/write/index/cache/receipt binds authenticated tenant context.
- Protected actions are durable before execution acknowledgement.
- No raw credentials or secrets in agent payloads, telemetry, logs, receipts, models, or browser schemas.

## Current workspace

```text
src/                       gateway binary/library, REST/gRPC adapters
src/src/authorize_service.rs  Week-3 typed authorize seam (gRPC authorize always uses it)
src/canon/                 current aegis-jcs-1 crate
lib/common/                errors, crypto helpers, metrics
lib/api/                   protobuf and shared current models
lib/decision/              aegis-decision: authorize context, DecisionRuntime/admit, AuthorizeService trait
lib/storage/               StorageBackend, SQLite/PostgreSQL, migrations
lib/policy/                Cedar and trust provenance
lib/soc/                   detection, correlation, response, Qdrant adapter
lib/event/                 unwired ADR-0006..0010 event-fabric prototypes (target crate; no production traffic)
lib/tool-broker-*          canonical actions, credentials, connectors
bins/aegis-node-sensor/    polling sensor, durable spool, signed commands
bins/aegis-cage-runner/    sandbox execution
bins/aegis-egress-proxy/   network choke point
bins/aegis-tool-broker/    standalone credential-owning connector executor
bins/aegis-llm-gateway/    prompt/model metadata proxy
ui-next/                   React SOC console
sdk-{python,typescript,go}/ fail-closed SDKs
```

Target modules are introduced only through the ADR process (a Proposed ADR permits only unwired prototypes; production wiring requires acceptance) and the sequence in `ROADMAP.md`.

## Coding rules

- Read `docs/architecture.md` before editing.
- Keep protocol adapters thin and call a protocol-neutral typed service.
- Public control types are protobuf-first; FlatBuffers is internal telemetry; Arrow IPC is analytical output.
- Do not make HCMT authoritative for approvals, replay claims, control generations, receipt heads, or protected commits.
- In target hot crates, no `tokio::spawn`, blocking lock, JSON tree, normal telemetry SQL row, unbounded work, or shared mutable cross-core state.
- Existing transitional code may keep Tokio/JSON/SQL behind current boundaries; do not expand those patterns into target crates.
- All production paths return typed `Result`; no `.unwrap()`/`.expect()`.
- Use parameterized SQL and closed enums for dynamic columns/order.
- Preserve unrelated dirty worktree changes.
- Stateful changes include migration, shadow comparison, crash recovery and tested rollback.
- Unsafe/SIMD/lock-free/eBPF/wire/disk/UI-memory changes require the evidence in `CONTRIBUTING.md`.

## Standard commands

```bash
cargo check --workspace
cargo test --workspace -- --test-threads=1
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo tree --workspace

python3 -m unittest discover -s sdk-python/tests
(cd sdk-typescript && npm ci && npx tsc --noEmit && npm test)
(cd sdk-go && go test ./...)
node scripts/validate-docs.mjs
```

Current local gateway defaults to `127.0.0.1`, REST `8080`, gRPC `6334`. `protoc` is required. Linux-specific io_uring/eBPF work uses separate target/toolchain gates as those crates land.

## Where to record changes

- architecture or invariant: HLD + LLD + ADR;
- byte/wire/disk schema: LLD + golden corpus + compatibility matrix;
- current shipped status: `docs/Implementation_Status.md` only after code lands;
- measured performance: `docs/performance-baseline.md` plus raw artifacts;
- migration/cutover/delete gate: `MIGRATION_MATRIX.md`;
- weekly sequencing: `ROADMAP.md`.
