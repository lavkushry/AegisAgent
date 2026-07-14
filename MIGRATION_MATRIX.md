# AegisAgent Performance Architecture Migration Matrix

**Status:** normative migration blueprint; target components are not shipped until their exit gates pass

**Audit date:** 2026-07-13

**Scope:** repository state at this checkout versus the Thread-Per-Core + HCMT target

**Audited baseline HEAD:** `f027d07` (`feat(tool-broker): extract connector execution into standalone aegis-tool-broker binary`)

**Post-audit delta:** the `current` branch adds unwired `aegis-event` SPSC,
sealed generation-tagged slab-page, append-only published-prefix, and
failure-atomic single-page slab/ring admission prototypes under ADR-0006
through ADR-0009. The lexical counts below remain the frozen baseline so future
excision is measured against one reproducible commit.

**Companion documents:** [HLD](ARCHITECTURE.md), [LLD](docs/LLD.md), [Roadmap](ROADMAP.md)

> This document distinguishes observed implementation, proposed architecture, and measured performance. The `<1 ms p99` authorization-compute and `1,000,000 events/s/node` ingestion figures are targets. The current checked-in baseline is approximately 130–150 sustained authorizations/s on SQLite, 17.58 ms HTTP p99 at 10 requests/s, and 6.71 ms mean in-process authorization. See `docs/performance-baseline.md`.

## 1. Migration laws

1. `aegis-jcs-1`, frozen-action `action_hash`, approval expiry, atomic single-use consumption, deterministic trust tightening, tenant isolation, and hash-chained receipts cannot regress.
2. HCMT is the telemetry and analytical event store. It is not a substitute for transactions required by approvals, replay claims, control generations, or protected receipt commits.
3. Cedar remains the authoritative inline policy engine. Aho-Corasick and semantic models may deny, quarantine, or tighten trust under an explicit deterministic policy; they never turn a deny into an allow.
4. Every queue is bounded. Each overflow path is declared as `reject`, `spool`, `shed`, or `synchronous durability`; silent loss is forbidden for integrity evidence.
5. Public control types remain protobuf-first and REST/gRPC compatible during migration. FlatBuffers is the internal telemetry frame; Arrow IPC is the analytical result format.
6. No component is deleted until parity, replay, recovery, performance, and rollback gates are green for two consecutive releases.
7. “Zero-copy” means no avoidable application-level materialization inside a declared boundary. It does not erase DMA, TLS, kernel/user, browser/WASM, decompression, or GPU-upload copies.

## 2. Reproducible forensic snapshot

The following lexical counts include production code and inline Rust tests. They are an architectural inventory, not a defect count.

| Surface | Observed | Reproduce |
|---|---:|---|
| Tracked files | 948 | `git ls-files \| wc -l` |
| Rust source files outside `target/` | 207 | `rg --files -g '*.rs' -g '!**/target/**'` |
| `tokio::spawn` occurrences | 120 across 28 files | `rg -n 'tokio::spawn' -g '*.rs' -g '!**/target/**' .` |
| `spawn_blocking` occurrences | 2 | `rg -n 'spawn_blocking' -g '*.rs' -g '!**/target/**' .` |
| `Mutex<T>` / `RwLock<T>` occurrences, including aliases such as `StdMutex<T>` | 61 across 32 files | `git grep -E -n '(Mutex\|RwLock)<' HEAD -- '*.rs'` |
| Axum `Json` occurrences | 663 | `rg -n '\bJson[<(]' -g '*.rs' src lib bins` |
| `serde_json::` occurrences | 1,147 | `rg -n 'serde_json::' -g '*.rs' src lib bins` |
| Unique REST route path literals in the v1 router | 146 | inspect `src/src/main.rs` router construction |
| Protobuf RPC declarations | 28 | `rg -n '^\s*rpc ' lib/api/proto/*.proto` |
| `StorageBackend` async methods | 245 | inspect `lib/storage/src/traits.rs` |
| SQLite tables across migrations | 48 | `rg '^CREATE TABLE' lib/storage/migrations/*.sql` |
| PostgreSQL tables across migrations | 50 | `rg '^CREATE TABLE' lib/storage/migrations_postgres/*.sql` |
| SQLx query calls in `lib/storage` | 279 | `rg -n 'sqlx::query' lib/storage -g '*.rs'` |

### What the counts mean

- Tokio, locks, JSON, and SQLx are not intrinsically unsafe. They are unsuitable as unbounded or contended primitives in the claimed million-event data plane.
- The 146 REST route paths versus 28 protobuf RPCs show that current dual-protocol coverage is incomplete.
- `StorageBackend` combines transactional control state, append telemetry, analytical queries, jobs, and projections in one 1,475-line trait. That prevents independent latency and durability contracts.
- Handler size contradicts the intended thin-adapter rule: `src/src/routes/authorize.rs` is 8,316 lines, `soc.rs` 4,367, `main.rs` 3,924, and `routes/mod.rs` 3,229, including substantial inline tests.

## 3. Current repository map

| Current component | Evidence | Current role | Primary debt | Disposition |
|---|---|---|---|---|
| `src/src/main.rs` | Axum router, Tokio startup, 24 `tokio::spawn` sites | REST/gRPC wiring plus job orchestration | One process owns protocol, jobs, batching, SOC, and lifecycle; multi-thread runtime has no core affinity | Rewrite launcher; retain compatibility server during shadow phase |
| `src/src/routes/authorize.rs` | `authorize_action_impl` returns typed `AuthorizedOutcome` (still hosts Cedar/storage orchestration); REST handler maps via `outcome_to_response` | Full authorization transaction | Business logic still lives in the gateway binary rather than `aegis-decision` | Move orchestration to `aegis-decision::AuthorizeService`; handler becomes parse → call → map |
| `src/src/grpc.rs` | **Typed via AuthorizedOutcome** for control/MCP/query/close; **storage-direct** SOC RPCs map DB errors through `aegis_error_to_tonic` (StatusError → tonic codes) | gRPC adapter | Business logic still in gateway binary | Later `aegis-decision` extraction |
| `src/src/routes/mod.rs` | shared `AppState`; rate-limit/cache `Mutex<HashMap<...>>`; Tokio channels | Process-global state | Contended shared maps and global background task handles | Split immutable snapshots, reactor-local state, and control-plane coordinator |
| `lib/policy/src/cedar.rs` | `PolicyEngine` with `RwLock<Arc<PolicySet>>` and tenant `HashMap` | Deterministic Cedar authorization | Every evaluation traverses shared locks; policy set is rebuilt centrally | Preserve semantics; publish immutable per-core snapshots with `ArcSwap`/epochs |
| `lib/policy/src/trust_chain.rs` | six-level tighten-only propagation | Deterministic provenance | None in algorithm; string representation costs and schema drift risk | Preserve byte-for-byte behavior; encode trusted enum on internal wire |
| `src/canon/src/lib.rs` | `aegis-jcs-1` recursive JSON canonicalization | Cross-SDK action bytes | Located under binary tree; JSON object allocation/sort; error collapses to empty string | Move to bottom-layer `lib/canon`; preserve v1 corpus; add typed v2 canonical bytes only under a version bump |
| `lib/tool-broker-core/src/action.rs` | canonical broker action and SHA-256 `action_hash` | Approval binding | Depends on JSON representation | Preserve v1; introduce generated wire conversion that proves equal v1 bytes |
| `lib/common/src/receipt_signer.rs` | Ed25519 sign/verify and signer trait | Third-party-verifiable receipts | Process-global `OnceLock`; signer failure represented by empty string in some backends | Preserve Ed25519; make signing fallible and reactor-safe; protected commits fail closed when signing is required |
| `lib/storage/src/traits.rs` | 245 async methods | All persistence abstraction | God trait; every call allocates an async future; analytical and transactional semantics mixed | Split `ControlStore`, `ReceiptLog`, `EventStore`, `ProjectionStore` |
| `lib/storage/src/db/*` | parameterized SQLx modules and tenant filters | SQLite/PostgreSQL row persistence | Row materialization, TEXT timestamps, JSON-in-TEXT, many indexes, serialized SQLite writer | Retain for control state; dual-write telemetry to HCMT; retire telemetry tables after verification |
| SQLx coupling outside storage | gateway and SOC manifests depend on SQLx; route/SOC files contain direct queries primarily inside large inline test modules | seeding, failure injection and some shared DB-oriented SOC plumbing | tests embedded after `#[cfg(test)]` keep protocol/domain crates coupled to concrete pools; `SqlDbStorage.pool` exposes the backend | move pool tests to storage/integration fixtures; remove SQLx from adapters/SOC as focused traits land |
| `lib/storage/src/audit_batch.rs` | bounded Tokio MPSC, Vec batch, synchronous fallback | Audit batching | MPSC atomics and async scheduler; full queue pushes DB work back onto hot path | Replace hot lane with per-reactor SPSC rings and a protected WAL lane |
| `lib/storage/src/receipt_batch.rs` | receipt batching task | Ordinary receipt throughput | Receipt ordering and batch scheduling share runtime | Preserve chain algorithm; route tenant-affine chain appends to durable writer shard |
| `lib/soc/src/events.rs` | Tokio MPSC `EventSink`; single drain does DB reads, rules, correlation, webhooks; per-event spawns | Async SOC pipeline | Serial consumer, rule DB read per event, task fan-out, best-effort persistence | Replace with partitioned reactor graph and immutable compiled rule snapshots |
| `lib/soc/src/detect.rs` / `rule_dsl.rs` | scalar per-rule matching | Deterministic detection | O(number of rules × fields) comparisons; allocation-heavy strings | Compile literal families into Aho-Corasick DFA; retain structured predicates |
| `lib/soc/src/qdrant.rs` | Qdrant client; optional `fastembed` ONNX | Semantic search | Network hop and external index; `spawn_blocking`; no local PQ ownership | Replace with tenant-partitioned HNSW+PQ; isolate ONNX sessions per inference core |
| `bins/aegis-node-sensor` | `/proc` collectors, checksummed spool, polling HTTP client, POSIX signal enforcement | Host telemetry/containment | Polling misses short-lived activity; mutexed sets; shell `kill`; no eBPF | Preserve signed commands and spool semantics; add Linux eBPF CO-RE fast path and explicit fallback |
| `bins/aegis-cage-runner` | Docker runtime, HTTP JSON gateway client | Sandbox execution | Tokio tasks and JSON transport; Docker socket deployment risk | Retain isolation contract; move telemetry to FlatBuffers; replace Docker-socket mode before production |
| `bins/aegis-egress-proxy` | Tokio per-connection tasks and JSON decision client | Egress choke point | Per-connection scheduling, remote JSON authorization | Core-pin acceptors; cache deny-safe immutable policy; typed gRPC control call |
| `bins/aegis-tool-broker` | standalone Axum/JSON executor added at audited HEAD; gateway HTTP client in `src/src/tool_broker_client.rs` | credential-owning connector execution boundary | separate-process isolation is correct, but transport is JSON/Tokio and gateway/client adds a network materialization boundary | Preserve process/credential boundary; migrate commands to typed protobuf and telemetry to FlatBuffers |
| SDKs | Python/TypeScript/Go HTTP JSON clients and v1 canonical corpus | Fail-closed enforcement | JSON encoding and network round trips; no binary streaming | Preserve v1 APIs; add gRPC/FlatBuffer transport without weakening local hash checks |
| `ui-next` | React 19, JSON `fetch`, polling stream, row-to-column conversion, SVG panels | SOC console | JSON parse, duplicate row/column materialization, DOM/SVG cost O(points) | Keep React chrome; replace data worker with Arrow/WASM and plots with WebGL2 instancing |
| `src/dashboard` | legacy JavaScript dashboard and vendored graph library | Legacy console | Duplicate UI and JSON polling | Delete after `ui-next` feature/accessibility parity and two-release rollback window |
| `.github/workflows/ci.yml` | workspace tests, SDK parity, fuzz, mean regression gates | Build integrity | No isolated core/NUMA benchmarks, no tail histogram gate, no copy/alloc gate | Add hardware benchmark lane, Loom/Miri/sanitizers, Arrow corpus, recovery/chaos gates |

## 4. Mandatory preservation ledger

| Primitive | Source of truth today | Adaptation rule | Migration proof |
|---|---|---|---|
| Canonical action bytes | `src/canon`, `tests/canonical_action_vectors.json` | v1 bytes never change; new wire types convert to the same logical action before v1 hashing | Rust/Python/TS/Go plus FlatBuffer/protobuf corpus byte equality |
| Frozen action hash | gateway, SDK protect wrappers, tool broker | Compute after all authorized mutation and before approval; execute only the exact hash | approve-then-swap and property tests on every transport |
| Approval expiry/single use | approval storage transaction and SDK consume | Consumption remains an atomic transactional compare-and-set | crash/retry/replay test under concurrent consumers |
| Trust provenance | `lib/policy/src/trust_chain.rs` | Unknown stays least trusted; downstream can only tighten | exhaustive six-level lattice test plus unknown values |
| Cedar authority | `lib/policy`, `policies.cedar` | No model or risk score can allow; policy snapshots are immutable per request | differential tests old engine versus per-core engine |
| Receipt chain | `lib/storage/src/db/receipts.rs`, receipt corpus | Per-tenant total order, durable chain head, canonical hash and optional signature | concurrent append, crash recovery, range verification, signature corpus |
| Ed25519 commands/receipts | `lib/common/src/receipt_signer.rs`, `src/src/sign.rs` | Keep strict verification; key identifiers and rotations are versioned | old/new verifier cross-tests and invalid-key fail-closed tests |
| Tenant isolation | every control query | Tenant is authenticated context, never trusted from payload alone | cross-tenant fuzz/property tests for every store implementation |

## 5. Concurrency excision ledger

### `tokio::spawn`

The hot-path ban applies to `aegis-reactor`, `aegis-event`, `aegis-decision`, and `aegis-hcmt`. Tokio remains permitted in compatibility adapters, administrative APIs, and migration jobs until they are removed from the performance envelope.

| Concentration | Occurrences | Migration |
|---|---:|---|
| `src/src/main.rs` | 24 | Replace startup fan-out with one pinned OS thread per reactor and a supervised control thread |
| `src/src/jobs.rs` | 15 | Move jobs to a separate control runtime/process; never co-schedule with decision reactors |
| `src/src/routes/mod.rs` | 11 | Remove handler-owned drains; inject service handles only |
| `src/src/routes/authorize.rs` | 8 | Extract and use reactor-local continuations; no detached decision work |
| cage/sensor gateway clients | 15 total | Use bounded connection-local state machines and batch streams |
| `src/src/routes/soc.rs` | 6 | Move streams to query/stream reactors |
| storage batch writers | 8 | Replace with SPSC sequence barriers and dedicated writer cores |
| SOC event/webhook/notify modules | 11 | Partition consumers; isolate blocking delivery pools |
| broker route/client | 3 | Keep connector execution out of the gateway; replace detached JSON/HTTP work with bounded typed RPC state machines |

Exit criterion: `rg 'tokio::spawn' lib/reactor lib/event lib/decision lib/hcmt` returns no matches, and perf tests prove no work migrates between OS threads.

Exact audited `tokio::spawn` file inventory (production and inline tests combined):

| Files | Occurrences |
|---|---:|
| `src/src/main.rs` | 24 |
| `src/src/jobs.rs` | 15 |
| `src/src/routes/mod.rs` | 11 |
| `src/src/routes/authorize.rs`, `bins/aegis-cage-runner/src/gateway_client.rs` | 8 each |
| `bins/aegis-node-sensor/src/gateway_client.rs` | 7 |
| `src/src/routes/soc.rs` | 6 |
| `lib/storage/src/{receipt_batch,audit_batch}.rs`, `lib/soc/src/{webhook_export,events}.rs`, `bins/aegis-egress-proxy/src/proxy.rs` | 4 each |
| `lib/soc/src/notify.rs` | 3 |
| `src/src/routes/broker.rs`, `src/src/gh_checks.rs`, `bins/aegis-cage-runner/src/http_event_sink.rs` | 2 each |
| `src/src/{tool_broker_client,policy_watcher,gh_comment,admission}.rs`, `src/src/routes/{receipts,oidc}.rs` | 1 each |
| `lib/tool-broker-connectors/src/http.rs`, `lib/storage/src/db/{mod,agent_runs}.rs` | 1 each |
| `bins/aegis-node-sensor/src/shipper.rs`, `bins/aegis-egress-proxy/src/decider.rs`, `bins/aegis-cage-runner/src/main.rs` | 1 each |

### `Mutex` / `RwLock`

| Current lock family | Risk | Replacement |
|---|---|---|
| Policy `RwLock<HashMap<tenant, Arc<PolicySet>>>` | shared read cache lines and writer stalls | immutable generation table per reactor; epoch/`ArcSwap` publication |
| Handler token buckets and caches | global contention and poisoning recovery complexity | reactor-local bounded tables; tenant routed to a stable owner |
| Metrics maps | hot atomic/lock contention | per-core counters padded to cache lines; scrape-time aggregation |
| Sensor collector `Mutex<HashSet/HashMap>` | polling and shared collector state | eBPF per-CPU maps; single-owner user-space aggregator |
| Spool lane locks | append/ack contention | one writer per lane; command mailbox for compaction |
| Test environment locks | not production debt | retain where deterministic test isolation requires them |

Exit criterion: no blocking lock is reachable from authorize, ingest, seal, query-scan, or render-worker flame graphs.

Exact audited lock-file inventory:

| Files | `Mutex<T>` / `RwLock<T>` occurrences |
|---|---:|
| `src/src/routes/mod.rs` | 12 |
| `lib/storage/src/db/test_utils.rs` | 6 |
| `lib/common/src/budget.rs` | 5 |
| `lib/soc/src/notify.rs`, `lib/policy/src/cedar.rs` | 3 each |
| `lib/common/src/metrics.rs`, `bins/aegis-node-sensor/src/spool.rs`, `bins/aegis-llm-gateway/src/gateway_client.rs`, `bins/aegis-cage-runner/src/{main,docker_runtime}.rs` | 2 each |
| `src/src/routes/authorize_canon.rs`, `src/src/{otel,jobs,gh_comment,gh_checks,airgap}.rs`, `src/benches/policy_eval_benchmark.rs` | 1 each |
| `lib/soc/src/{webhook_export,permission_review}.rs` | 1 each |
| `lib/soc/src/events.rs` (`StdMutex` test alias) | 1 |
| `bins/aegis-node-sensor/src/{secret_collector,process_enforcer,process_collector,net_collector,fs_collector,command_receiver}.rs` | 1 each |
| `bins/aegis-llm-gateway/src/events.rs`, `bins/aegis-egress-proxy/src/events.rs` | 1 each |
| `bins/aegis-cage-runner/src/{runtime,http_event_sink,events,command_receiver}.rs` | 1 each |

## 6. JSON and protocol excision ledger

| Surface | Current | Target | Deletion gate |
|---|---|---|---|
| Authorization SDK path | REST JSON | protobuf gRPC request/response; REST JSON compatibility remains off the benchmark path | all SDKs support binary path and v1 canonical hash corpus |
| Runtime ingestion | REST JSON | bidirectional gRPC stream carrying verified FlatBuffer frames | sensor/cage dual-write and loss/replay tests |
| Internal event bus | owned Rust structs and clones | fixed descriptor + FlatBuffer/arena view | no per-event allocation in steady-state benchmark |
| SOC query | REST JSON rows | Arrow IPC record batches over gRPC Flight for native clients and Arrow-IPC WebSocket bridge for browsers | query differential and UI parity |
| gRPC implementation | protobuf → REST handler → JSON → protobuf | protobuf → typed service → protobuf | 112-route contract inventory reconciled with protobuf services |
| UI frame construction | JSON rows → JS records → JS column arrays | one bounded browser-to-WASM copy, then Arrow buffer views | allocation/copy instrumentation and 60 FPS stress test |
| Admin/compatibility | JSON REST | retained, rate-limited, not part of performance claims | may remain indefinitely if maintenance cost is bounded |

The REST compatibility layer is not allowed to invoke a gRPC adapter or vice versa. Both call the same typed service.

The v1 router’s 146 path literals cover agents, tools, MCP, authorization, ingestion, webhooks, decisions, policies, rules, graph, API keys, approvals, receipts, alerts, incidents, SOC queries/streams/dashboards/notifications, cage runs, runtime/prompt/model events, bans, quarantine, control commands, egress, sensors, broker execution, tenant administration, evidence export, OIDC, health/debug and static-dashboard families. The authoritative exhaustive registration is `src/src/main.rs`; JSON-heavy implementations concentrate in `src/src/routes/{authorize,soc,approval,webhooks,mcp,tenant,runtime,agents,policy}.rs`. Route extraction/protobuf parity tooling MUST generate the cutover list from code so a hand-maintained list cannot silently omit an endpoint.

## 7. Row-store split

### Remains transactional

- tenants, agents, credentials/key references, policy generations;
- approvals, approval edits, expiry, consumption and replay nonces;
- bans, quarantines, control commands and command acknowledgements;
- receipt chain heads, protected decision commits and signer metadata;
- idempotency keys and schema/lease metadata.

### Moves to HCMT

- runtime events, prompt/model metadata, agent security events;
- high-volume audit projections after the protected receipt is durable;
- SOC alert/incident timelines and derived analytical projections;
- time-series counts, field facets, text/pattern scan candidates;
- vector codes and HNSW adjacency sidecars.

### Retired only after cutover

- `runtime_events`, `prompt_events`, `model_call_events` row tables;
- bulk `audit_events`/archive rows, while integrity anchors remain in the control store;
- Qdrant event collections and `docker-compose.full.yml` Qdrant service;
- FTS5 telemetry index after equivalent query and relevance tests.

## 8. Target component map

| New crate/module | Owns | Depends on | Must not depend on |
|---|---|---|---|
| `aegis-common` | errors, IDs, bounded sizes, time primitives | external utilities only | domain crates |
| `aegis-canon` | v1 canonicalization and versioned typed canonical forms | common | transports/storage |
| `aegis-wire` | protobuf, FlatBuffer, Arrow schemas and conversions | common, canon | storage/policy |
| `aegis-crypto` | SHA-256, Ed25519, chain/checkpoint verification | common, canon | protocol adapters |
| `aegis-policy` | Cedar compile/evaluate and trust lattice | common, wire | storage, network |
| `aegis-event` | cache-padded SPSC ring, slabs, sequence barriers | common, wire | Tokio, SQLx |
| `aegis-reactor` | pinned thread, io_uring, admission, deadlines | common, event | SQLx, UI |
| `aegis-decision` | typed authorize/approve services and snapshot publication | common, canon, crypto, policy, wire | Axum, tonic |
| `aegis-control-store` | transactional traits and SQLite/Postgres adapters | common, wire, crypto | SOC/query |
| `aegis-hcmt` | WAL, memtable, Arrow SSTables, compaction, recovery | common, event, wire | policy, Axum |
| `aegis-query` | predicate planning, bitmap pruning, vector/text operators | common, hcmt, wire | control mutation |
| `aegis-guardrails` | Aho DFA, HNSW/PQ, ONNX inference | common, wire | authorization allow path |
| `aegis-soc` | detection/correlation/response orchestration | query, guardrails, control-store, wire | protocol adapters |
| `aegis-containment` | signed command state, eBPF map protocol | common, crypto, wire | UI, policy authoring |
| binaries/adapters | REST, gRPC, WebSocket, CLI, process supervision | service crates | business logic |

## 9. Sequenced migration without breaking authorization

| Gate | Change | Read path | Write path | Rollback |
|---|---|---|---|---|
| M0 Baseline | Freeze corpus, latency, throughput, crash and tenant tests | current | current | n/a |
| M1 Service extraction | Move authorize logic out of handlers | typed service via current runtime | current SQL transaction | route flag selects old/new service |
| M2 Snapshot decision reads | Per-core immutable agent/tool/policy generation | snapshot, DB on cold miss only | transactional store + invalidation log | disable snapshot flag |
| M3 Binary telemetry frame | SDK/sensors optionally send FlatBuffers | current queries | JSON-normalized event and binary event both feed old store | negotiate v1 JSON |
| M4 HCMT shadow writes | Create WAL/memtable/L0 | old SQL queries | synchronous integrity commit, asynchronous HCMT telemetry dual-write | stop HCMT consumer; retain WAL |
| M5 Shadow reads | Run query differential tests | SQL response served; HCMT compared | dual-write | disable shadow query |
| M6 Query cutover | Serve selected tenants from HCMT | HCMT with SQL fallback | dual-write | per-tenant backend generation flip |
| M7 SOC partitioning | Replace single drain with shard graph | HCMT/query | bounded rings and protected lane | replay WAL through old drain |
| M8 UI Arrow | Browser consumes Arrow stream | Arrow/WASM/WebGL; JSON fallback | unchanged | runtime feature flag |
| M9 eBPF | CO-RE sensor enabled on capable Linux | signed control maps | eBPF ring + durable sensor spool | procfs/fanotify observe-only fallback |
| M10 Retirement | Remove redundant telemetry rows/Qdrant/legacy UI | HCMT only after retention window | HCMT | release artifact retains migration reader |

## 10. Gap analysis against target

| Target capability | Current evidence | Gap |
|---|---|---|
| Thread-per-core reactor | Tokio multi-thread runtime; no affinity crate/config | No core ownership, per-core listener, NUMA allocation, or io_uring reactor |
| Disruptor/SPSC event fabric | Tokio bounded MPSC remains `current`; unwired `lib/event` adds 64-byte-separated cursors, Acquire/Release sequences, 32-byte descriptors, bounded closure/drop, cancelable producer permits, commit-delayed consumer claims, a safe sealed-page oracle, an append-only published prefix, and `VolatileAdmissionChannel` composition. The composite validates before reservation, publishes the page before the ring, withholds capacity until a validated frame lease commits, and distinguishes clean, faulted, and orphaned-prefix termination. Test sources include safe short-trace differential coverage, native tiny-ring stress, shipping-algorithm Loom models, Miri-oriented lifetime cases, defined ASan/TSan CI lanes, and zero-allocation admission/claim checks. | The production fabric remains `target`, neither `shadow` nor `qualified`, carries no protected evidence, and has no performance result. Blockers are formal ADR acceptance/security review, green hosted sanitizer artifacts, real UBSan support, authenticated registry lookup, bounded page rotation/outstanding pages, WAL durability/replay, generation reuse/epochs, NUMA-owner reclamation, priority lanes, production shadow wiring, release-artifact rollback, and qualification. |
| HCMT/Arrow SSTables | SQLite/PostgreSQL rows; JSON/TEXT payloads | No Arrow dependency, WAL format, memtable, segment manifest, compactor, or mmap query path |
| Gorilla timestamp codec | none | Codec, block restart points, fallback-to-raw rule, corpus absent |
| Roaring pruning | none | Bitmap build/serialization/planner absent |
| Aho-Corasick DFA | scalar YAML rule checks; transitive crate only | No compiled tenant automata, memory caps, normalization contract, or atomic publication |
| HNSW + PQ | Qdrant remote HNSW; optional local ONNX embedding | No owned index, PQ training/versioning, deletion/rebuild, or tenant partition |
| ONNX INT8 | optional `fastembed`; `spawn_blocking` | No fixed INT8 model contract, per-core session, preallocated tensors, or latency gate |
| eBPF containment | procfs polling and POSIX signals | No CO-RE programs, cgroup/LSM hooks, per-CPU maps, verifier CI, or kernel matrix |
| WASM Arrow views | React JSON fetch and JS row-to-column conversion | No Rust WASM crate, Arrow IPC parser, worker ring, SIMD path, or schema negotiation |
| WebGL2 rendering | SVG/DOM panels | No instanced buffers, GPU picking, level-of-detail, or frame-time gate |
| Arrow browser stream | JSON polling/SSE/WebSocket JSON | No binary stream framing, flow control, resume cursor, or dictionary delta handling |

## 11. Files to create, rewrite, retain, and eventually delete

### Create

- `lib/{wire,event,reactor,decision,control-store,hcmt,query,guardrails,crypto,containment}/`;
- `lib/wire/{proto,fbs,arrow}/` schemas and cross-format corpus;
- `bins/aegis-dataplane/`, `bins/aegis-compactor/`, `bins/aegis-query/`;
- `bins/aegis-node-sensor-ebpf/` as a separate `bpfel-unknown-none` workspace;
- `ui-wasm/` for Arrow validation/filtering/layout and typed-array exports;
- `benches/{reactor,ring,hcmt,query,guardrails,end_to_end}/` plus hardware manifests;
- ADRs for reactor, HCMT, wire/copy budget, eBPF trust boundary, and semantic guardrails.

### Rewrite in place

- `src/src/main.rs`, `src/src/grpc.rs`, and route handlers into thin adapters;
- `lib/policy/src/cedar.rs` snapshot ownership without changing policy semantics;
- `bins/aegis-node-sensor` around eBPF events and the existing durable command/spool invariants;
- `ui-next/src/datasources` and high-cardinality panels;
- configuration, Helm topology, CI, benchmark, deployment and recovery docs.

### Retain

- current cross-language canonical and receipt vector corpora;
- Cedar policies and trust-chain tests;
- approval/receipt/control transactional migrations through cutover;
- SDK fail-closed wrappers and their tamper/replay tests;
- PostgreSQL/SQLite adapters as the control-store compatibility implementation.

### Delete after gates

- `src/dashboard/` after `ui-next` + WASM parity;
- `lib/soc/src/qdrant.rs`, Qdrant docs/config/service after local semantic index parity;
- retired telemetry migrations/tables only through an explicit archival migration, never by destructive startup logic;
- JSON bridging inside `src/src/grpc.rs` immediately after typed service parity;
- Tokio MPSC event/batch sinks after WAL replay and load/chaos parity;
- duplicate or superseded HLD/LLD documents only after maintainers resolve existing uncommitted edits.

## 12. Documentation map

| Document | Role after this change | Action |
|---|---|---|
| `README.md` | product entry point and honest current/target status | rewrite |
| `ARCHITECTURE.md` | canonical target HLD and performance model | create |
| `docs/LLD.md` | canonical implementation contract and skeletons | create |
| `docs/architecture.md` | concise mandatory contributor law and transition rules | rewrite to point at canonical HLD/LLD |
| `CONTRIBUTING.md` | systems-programming, safety, benchmark and ADR gates | rewrite |
| `ROADMAP.md` | 36-week gated execution plan | rewrite |
| `MIGRATION_MATRIX.md` | repository-backed audit and cutover ledger | create |
| `docs/performance-baseline.md` | historical measured evidence | retain; never rewrite targets as measurements |
| `docs/action-receipt-spec.md` | cryptographic evidence contract | retain |
| `docs/adr/*` | accepted decisions | add ADRs; do not rewrite historical decisions |
| `docs/AegisAgent_World_Class_HLD.md` / `LLD.md` | pre-existing, currently modified working documents | leave untouched; reconcile/archive in maintainer-owned follow-up |

## 13. Final retirement gates

A component can be removed only when all applicable checks pass:

- differential result equality over production-shaped replay corpora;
- canonical/action/receipt byte parity across Rust, Python, TypeScript, Go, protobuf and FlatBuffers;
- crash recovery at every WAL and manifest write boundary;
- no lost protected evidence during process kill, disk-full, short write, checksum failure, or queue saturation;
- cross-tenant isolation fuzzing and authorization snapshot-generation consistency;
- p50/p95/p99/p99.9 histograms under steady state, burst, compaction, policy reload and failure injection;
- allocation, copy, context-switch, cache-miss and branch-miss budgets on the declared hardware profile;
- rollback exercised from the release artifact, not merely described;
- two consecutive releases with shadow mismatch rate exactly zero for integrity fields.
