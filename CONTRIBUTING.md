# Contributing to AegisAgent

AegisAgent accepts changes that preserve action integrity while moving the system toward the benchmark-gated Thread-Per-Core and HCMT architecture. Contributions are licensed under the [MIT License](LICENSE) and governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Required reading

Before changing code, read in order:

1. [docs/architecture.md](docs/architecture.md) — mandatory repository law;
2. [ARCHITECTURE.md](ARCHITECTURE.md) — target HLD, performance model, and security boundaries;
3. [docs/LLD.md](docs/LLD.md) — byte layouts, ownership, storage, protocol, and test contracts;
4. [MIGRATION_MATRIX.md](MIGRATION_MATRIX.md) — current evidence and cutover gates;
5. the relevant [ADR](docs/adr/) and component documentation.

If code and documentation disagree, stop and resolve the contract in an ADR before broad implementation.

## Non-negotiable security invariants

A pull request MUST NOT weaken:

- byte-identical `aegis-jcs-1` canonicalization across Rust, Python, TypeScript, and Go;
- SHA-256 approval binding to the exact post-admission action;
- approval expiry, atomic single-use consumption, and replay rejection;
- fail-closed SDK behavior for mutating/high-risk actions;
- deterministic six-level trust provenance, with unknown least trusted and tightening only;
- Cedar as the authority for allow/deny; scores and models cannot create an allow;
- tenant binding in authentication, routing, storage, indexes, cache keys, and receipt chains;
- per-tenant receipt ordering, hash linkage, verification, and required durability;
- Ed25519 signature and signed-command verification;
- the rule that untrusted agents never receive raw credentials.

Changes to canonical bytes, receipt fields, signature input, trust ordering, or approval state require a versioned migration ADR and updates to every language corpus in the same pull request. Silent wire or hash drift is a release blocker.

## Architecture rules

### Dependency direction

Dependencies flow downward as defined in [the target DAG](ARCHITECTURE.md#17-target-workspace-and-dependency-direction). In particular:

- `aegis-policy` MUST NOT depend on storage, networking, Axum, tonic adapters, or SOC;
- `aegis-hcmt` MUST NOT evaluate Cedar or mutate approvals;
- query operators MUST NOT mutate control state;
- service crates MUST NOT depend on protocol adapters or binaries;
- handlers and RPC implementations are parse → typed service call → response mapping;
- all storage access uses the appropriate trait: `ControlStore`, `ReceiptLog`, `EventStore`, or a documented transitional `StorageBackend` method.

Run `cargo tree --workspace` and inspect internal edges for every crate-boundary change.

### Protocol law

- Public control request/response types are defined in protobuf first.
- REST compatibility models mirror protobuf and call the same typed service.
- Internal telemetry frames are FlatBuffers with generated verification before access.
- Analytical batches are Arrow IPC with schema fingerprint and generation.
- A gRPC method MUST NOT invoke a REST handler, collect an Axum body, or parse its JSON.
- New public behavior requires REST and gRPC parity until an accepted deprecation ADR says otherwise.
- Every field number, enum value, FlatBuffer slot, Arrow field, and schema ID follows compatibility rules and corpus tests.

### Hot-path law

The target hot crates are `aegis-reactor`, `aegis-event`, `aegis-decision`, and `aegis-hcmt`. Their steady-state authorize/ingest paths MUST NOT contain:

- `tokio::spawn`, a work-stealing executor, or detached work;
- blocking `Mutex`/`RwLock` or a contended global atomic;
- `serde_json::Value` or per-event JSON serialization;
- SQLx or a row transaction for normal telemetry;
- unbounded queue, collection, retry, body, decompression, or query;
- request-sized heap allocation after warm-up unless the allocation budget explicitly permits it;
- hidden cross-NUMA access or thread migration;
- blocking filesystem, DNS, KMS, webhook, model, or control-store call on a reactor core.

Tokio, locks, and JSON remain permitted in compatibility/control code when they are outside the claimed performance envelope and bounded. Annotate the boundary; do not disguise control code as hot-path code.

## Architecture Decision Records

An ADR is mandatory before implementing any change to:

- reactor/runtime, core or NUMA placement, event ring, slab, epoch, or allocator;
- HCMT WAL/segment/manifest ABI, codec, compaction, retention, or recovery;
- public protobuf, FlatBuffer, Arrow, eBPF, canonicalization, receipt, or signature schema;
- control-store consistency, receipt partitioning, replication, RPO/RTO, or failover;
- guardrail enforcement authority, Aho normalization, model, tokenizer, HNSW, or PQ codebook;
- eBPF hooks, capabilities, policy maps, fallback assurance, or break-glass path;
- browser transport, copy ledger, WASM memory ownership, or GPU renderer;
- an unsafe code boundary or new SIMD implementation;
- a performance target, durability class, or overload behavior.

Use [docs/adr/template.md](docs/adr/template.md). An ADR includes context, alternatives, invariants, data/byte layout, failure modes, security impact, performance hypothesis, benchmark method, migration, rollback, and rejected options. “Faster” is not evidence.

## Rust systems-programming standard

### Ownership and mechanical sympathy

- Mutable hot state has one owner thread.
- Cross-core traffic transfers bounded descriptors or immutable generations.
- Producer and consumer cursors occupy separate cache lines; assert layout in tests.
- Structure-of-arrays is preferred for scan/vector workloads; array-of-structs requires measured justification.
- Hot structs document size, alignment, cache-line sharing, allocation lifetime, and NUMA owner.
- Branches order common cases first only when profile evidence supports it.
- Batch size is selected from measured cache, latency, and I/O behavior; do not maximize throughput by violating tail or fairness budgets.
- Epoch pins cannot span I/O, callbacks, `.await`, or user-controlled duration.

### Lock-free structures

Lock-free is not automatically correct or faster. A new structure MUST document:

- single/multiple producer/consumer model;
- linearization point;
- Acquire/Release/Relaxed ordering proof;
- wraparound and ABA strategy;
- ownership transfer and drop behavior;
- shutdown and partially initialized slots;
- progress property: wait-free, lock-free, or obstruction-free;
- cache-line layout and false-sharing proof;
- overload/full behavior;
- Loom state-space test and long native stress test.

Use an existing reviewed primitive when it meets the ownership model. Do not introduce a generic MPMC queue into an SPSC edge for convenience.

### Unsafe Rust

The workspace default is safe Rust. Unsafe code is allowed only when it is necessary for FFI, mmap/Arrow views, eBPF ABI, SIMD, or a proven concurrency primitive.

Every `unsafe` block MUST have an adjacent `// SAFETY:` statement naming all preconditions. Every module containing unsafe code MUST begin with an `# Safety invariants` section covering:

- pointer provenance, alignment, initialized bytes, aliasing and lifetime;
- thread ownership and memory ordering;
- valid bit patterns and endian assumptions;
- bounds/overflow validation before pointer arithmetic;
- destruction, panic, cancellation and partial initialization;
- external ABI/version assumptions.

Required verification:

- focused safe reference implementation and differential tests;
- Miri for supported unit tests;
- ASan and UBSan; TSan where the primitive/toolchain supports it;
- fuzzing of every parser/decoder boundary;
- Loom for atomics and publication protocols;
- code review by at least one maintainer designated for unsafe/concurrency.

`unsafe` used merely to remove a bounds check without profile evidence will be rejected.

### SIMD intrinsics

- Keep a scalar implementation as the correctness oracle.
- Select instruction sets at runtime unless the deployment profile guarantees them.
- Test every tail length, alignment, null bitmap, NaN, signed boundary, and empty input.
- Compare scalar and SIMD outputs bit-for-bit where semantics require it.
- Benchmark end-to-end and inspect generated assembly; a microbenchmark alone is insufficient.
- Never read past an allocation, even if the CPU instruction would mask unused lanes.
- WASM SIMD128 and native AVX2/AVX-512/NEON implementations require separate feature/capability paths.

## Zero-copy and allocation claims

A change may use “zero-copy” only with a named boundary and a copy ledger. The ledger includes:

- source and destination owner/lifetime;
- every DMA, kernel/user, TLS, decompression, browser/WASM, and CPU/GPU transfer;
- payload clones, reference-count increments, buffer growth, dictionary rebuild, and alignment copy;
- bytes/event and allocations/event from instrumentation.

Decode-free FlatBuffer or Arrow views are not proof of end-to-end zero-copy. Compression necessarily decodes. Current browser WebSocket data generally needs one copy into WASM linear memory; WebGL2 needs a GPU upload. Hiding those copies is a documentation defect.

## HCMT changes

Any WAL, segment, manifest, Gorilla, bitmap, Bloom, HNSW, or PQ modification MUST include:

- versioned format and forward/backward compatibility behavior;
- golden byte corpus and independent decoder or reference test;
- checksums, length/overflow validation, corruption behavior;
- crash points before/after every publication operation;
- recovery and rollback path;
- tenant-range and schema-generation verification;
- compaction and retention interaction;
- read/write amplification, compression ratio, memory and p99 benchmark;
- no acknowledged protected evidence loss.

Never “repair” an interior corrupt WAL by scanning for plausible bytes. Quarantine it and report data loss.

## Guardrail and model changes

- Aho patterns use the same versioned normalization at compile and scan.
- Automaton pattern bytes, state count, resident memory, output count, and compilation time are bounded.
- Deterministic matches map to stable rule IDs and explicit Cedar/control actions.
- HNSW/PQ changes report recall@k against exact search, p99, memory/vector, build/rebuild time and deletion debt.
- Model/tokenizer/quantizer/codebook artifacts are signed or content-addressed.
- Attacker-controlled telemetry cannot retrain a live codebook or model.
- Model failure, timeout, queue saturation, or disagreement cannot produce allow or increase trust.
- Embeddings are sensitive derived data and require tenant isolation, encryption, retention and deletion tests.

## eBPF changes

- eBPF and user-space ABI sizes/offsets/endian are generated or asserted in both workspaces.
- Programs pass the minimum/supported kernel verifier matrix.
- Hook availability, capabilities, BPF LSM, lockdown, and fallback assurance are explicit.
- Maps publish through a versioned atomic generation switch.
- Control updates verify Ed25519 signature, tenant/node binding, key generation, nonce, expiry and monotonic generation.
- Ring-buffer loss counters and policy-map failures raise security telemetry.
- A fallback is never documented as equivalent enforcement when it is observe-only.

## UI changes

- React owns controls and bounded semantic views, not one component per point.
- High-cardinality panels render through WASM + WebGL2 instancing.
- Arrow schema, dictionary and resume generations are validated.
- Worker and server queues are credit-bounded and cancel obsolete work.
- 60 FPS means p95 frame `<=16.67 ms` under a published dataset/viewport; p99 and >50 ms frames are also reported.
- GPU context loss, reconnect, stale WASM view, memory growth, query cancel, and reduced-motion behavior are tested.
- Canvas/WebGL content has keyboard-accessible summaries, focus behavior and selected-item semantics.

## Testing and benchmark requirements

### Standard checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1
cargo tree --workspace
python -m black --check sdk-python/ examples/
python -m unittest discover -s sdk-python/tests
(cd sdk-typescript && npm ci && npm test && npx tsc --noEmit)
(cd sdk-go && go test ./...)
node scripts/validate-docs.mjs
```

The eBPF, WASM, Miri, Loom, sanitizer, fuzz, recovery, and performance matrices are added as their crates land.

### Performance evidence

A performance PR includes:

- hypothesis and stage expected to change;
- exact before/after commit and build flags;
- CPU/kernel/NUMA/RAM/NIC/disk/filesystem/firmware manifest;
- core, IRQ and frequency configuration;
- input size/cardinality/tenant/policy/query/durability distributions;
- warm-up, duration, repetitions and raw HDR histograms;
- p50, p95, p99, p99.9, throughput, errors and saturation point;
- allocations/event, copied bytes/event, context switches, migrations, L1/LLC/branch misses;
- WAL sync, compaction debt, write amplification and recovery results where applicable;
- integrity verification proving no missing/duplicate protected record;
- negative result disclosure and raw artifact location.

Do not compare a durable Aegis run to an asynchronously acknowledged competitor, or replicated data to unreplicated data. Durability, replication, retention, schema and loss policy must match.

## Development setup

```bash
make setup
make doctor

python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e "sdk-python[dev]"

cargo build --workspace
cargo test --workspace -- --test-threads=1
```

The current workspace requires Rust 1.88+ and `protoc`. Linux is required for io_uring/eBPF target work; portable control and SDK work remains supported on the existing CI platforms.

## Branches, commits, and pull requests

- Branch from `main` and target `main`.
- Use `feat/`, `fix/`, `perf/`, `refactor/`, `docs/`, `test/`, or `chore/` prefixes.
- Use Conventional Commit titles, for example `perf(hcmt): cache-pad writer sequences`.
- Keep a PR within one architectural decision and its tests.
- Update implementation status and docs only for behavior the PR actually ships.
- Link the ADR and migration/rollback gate for core changes.
- Include security impact, copy/allocation impact, and failure/overload behavior in the PR description.
- Never commit benchmark data containing customer identifiers, prompts, secrets or credentials.

## Review blockers

A PR will not merge if it:

- weakens an integrity invariant or lacks a fail-closed failure path;
- adds business logic to a handler/RPC adapter;
- adds a hot-path lock, unbounded queue, hidden clone, JSON tree, or detached task without an accepted ADR and evidence;
- introduces unsafe code without a safety proof and required tests;
- changes a byte/wire/disk ABI without versioning and corpus coverage;
- claims a target as measured without raw reproducible evidence;
- crosses a tenant boundary or logs sensitive payloads;
- lacks migration and tested rollback for a stateful cutover.

## Security reports and releases

Report vulnerabilities privately through [SECURITY.md](SECURITY.md), never a public issue. Releases use release-please after all blocking CI, compatibility, security, and migration gates pass.
