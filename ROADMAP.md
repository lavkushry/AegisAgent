# AegisAgent 36-Week Architecture Roadmap

**Status:** execution plan for the target architecture; not a shipped-feature list

**Start:** week 1 begins only after maintainers accept the foundation ADR set

**Canonical design:** [ARCHITECTURE.md](ARCHITECTURE.md) and [docs/LLD.md](docs/LLD.md)

**Current-to-target audit:** [MIGRATION_MATRIX.md](MIGRATION_MATRIX.md)

## Program rules

1. Every week ends with a demonstrable artifact and a binary pass/fail gate.
2. The existing authorization path remains deployable until typed-service, integrity, performance, recovery, and rollback gates pass.
3. Approval, replay, tenant, Cedar, action-hash, receipt, and Ed25519 invariants are release blockers in every phase.
4. HCMT initially shadows telemetry only. It does not replace transactional control state.
5. `<1 ms p99` authorization compute and `>=1M events/s/node` ingestion remain targets until raw qualification artifacts are published.
6. Feature flags and per-tenant generations support dual write, shadow read, cutover, and rollback.
7. No phase borrows unbounded CPU, memory, I/O, queue capacity, or retry time from another plane.

## Phase summary

| Phase | Weeks | Outcome | Exit gate |
|---|---:|---|---|
| Foundation | 1–6 | frozen contracts, typed service seam, reactor/ring proof, benchmark harness | old/new authorization differential equality; ring safety suite |
| Core Engine | 7–16 | io_uring reactors, immutable snapshots, WAL, HCMT, vectorized query, dual write/read | crash-safe HCMT; zero shadow mismatches; qualified ingest target attempted honestly |
| SOC Plane | 17–24 | compiled deterministic guardrails, owned semantic index, INT8 inference, correlation, eBPF | deterministic `<100 ms p99` detection target; containment safety/kernel matrix |
| UI Layer | 25–30 | Arrow browser stream, WASM transforms, WebGL2 panels | 60 FPS stress profile, accessibility and reconnect correctness |
| Integration | 31–36 | SDK/protocol migration, HA/NUMA hardening, chaos, comparative benchmark, cutover | all integrity/performance/recovery/rollback release gates |

## Phase 1 — Foundation (Weeks 1–6)

### Week 1 — Freeze evidence and decisions

Deliverables:

- capture current repository, route/RPC, dependency, storage, task/lock, SDK, UI and performance inventories;
- preserve canonical, receipt, approval replay, trust-lattice and tenant-isolation corpora;
- accept ADRs for target dependency DAG, performance classes, copy ledger, benchmark hardware profile and migration switches;
- add a machine-readable implementation-status vocabulary: `current`, `shadow`, `target`, `qualified`.

Gate: baseline commands reproduce; docs never label targets as measurements; current CI remains green.

### Week 2 — Establish wire and compatibility contracts

Deliverables:

- define protobuf v2 control skeleton and FlatBuffer telemetry v2;
- define Arrow logical schema, schema fingerprinting, FlatBuffer verification limits and error codes;
- build logical-event conversion corpus across REST model, protobuf, FlatBuffer and Arrow;
- configure protobuf `bytes` fields as `Bytes` and reserve field numbers.

Gate: round-trip/differential corpus equality; malformed length/depth/version fuzz seeds rejected without allocation spikes.

### Week 3 — Extract typed authorization service

Deliverables:

- introduce protocol-neutral `AuthorizeService` and domain command/outcome;
- route REST and gRPC through the typed service behind a feature flag;
- remove the gRPC → REST handler → JSON body round trip for the first authorization method;
- preserve current transactional storage and receipt behavior.

Progress (2026-07-14): Week-3 Phases A–D complete for the first authorize
method. `src/src/authorize_service.rs` holds the protocol-neutral seam
(`AuthorizeContext`, `AuthCredential`, `AuthorizedOutcome`,
`error_reason_to_tonic_code` / `http_error_to_tonic`, `authorize` /
`authorize_raw`). gRPC `authorize` always resolves real `remote_addr`, tenant,
and credential into `AuthorizeContext`, calls the shared service entry (no
forged `127.0.0.1:0`), and maps `StatusError` / HTTP failures to faithful tonic
codes — the JSON-bridge round-trip and `AEGIS_TYPED_AUTHORIZE` flag are
**deleted** (Phase D). Phase C equality corpus (`equality_*` tests) covers
allow / deny / require_approval / dry-run / frozen agent / bad token / missing
tenant / replay-nonce conflict, plus approval `action_hash` length parity.
Follow-on progress: typed `AuthorizedOutcome` seam covers authorize,
approve/reject, register_agent, create_tenant, register/discover MCP,
soc_query, and close_incident. Storage-direct SOC gRPC errors map via
`aegis_error_to_tonic`. **`lib/decision` (`aegis-decision`)** holds context
types + `AuthorizeService` trait; gateway **`GatewayAuthorizeService`**
implements the trait and gRPC authorize calls `evaluate` through it.
**Full authorize pipeline** lives in `aegis-decision::run_authorize_pipeline`
(admit → preflight → guard → metadata → evaluate) behind `DecisionRuntime`
ports, including idempotent-replay reconstruction. Gateway REST/gRPC adapters
build `AuthorizeContext`, call the pipeline, and map `DecisionOutcome` /
`AuthorizedOutcome` only — Week-3 evaluation extraction **complete**.
Packaging: stage + pipeline tests use shared `MockRuntime`; gateway wire helpers
live in `authorize_service(_tests).rs` (no Axum body bridge); route tests remain
in `authorize_tests.rs`.

Gate: legacy versus typed authorization decisions, hashes, approvals, receipts and errors match over replay corpus — **met** by `equality_*` tests.

### Week 4 — SPSC ring and slab prototype

Progress (2026-07-14): the `current` checkout has unwired ring, safe sealed-page
oracle, append-only published-prefix, and failure-atomic single-page admission
prototypes under Proposed ADR-0006 through ADR-0009, and Proposed ADR-0010
bounded page rotation with generation-tagged reuse (fixed pool of P slots,
epoch-addressed, single released-epoch reclamation edge, typed
PageQuotaExhausted backpressure) with an unwired `RotatingAdmissionChannel`
prototype (rotation seams, quota refusal, seam-shortfall/generation-skip
terminal fixtures, caught-unwind rotation fault, Loom seam model, cross-thread
rotation stress). **In-place pool rebind landed:** construction preallocates
`P` pages; rotation uses exclusive `PublishedSlabPage::rebind` (zero allocation
after `new`). Native rotating stress is `cfg(not(feature = "loom"))` so
all-features CI does not run std-thread stress on Loom atomics. **Diagnostic
criterion bench** `lib/event/benches/rotating.rs` (compile-checked in CI with
the other event benches) covers rotation claim/commit, quota refusal, and
multi-epoch pool rebind — not a qualification result. The volatile composite
validates before reservation, Release-publishes the page before the ring,
withholds capacity until a must-use validated frame lease commits, and reports
clean, faulted, and orphaned-prefix terminal states. Test sources include safe
differential oracles, native tiny-ring stress, shipping-algorithm Loom,
Miri-oriented borrow/drop cases, defined ASan/TSan CI lanes, and
zero-allocation admission/claim checks. It carries no production or `shadow`
traffic, cannot carry protected evidence, is not `qualified`, and has no
published performance result. The production fabric remains `target`. Formal
ADR acceptance/security review, green hosted sanitizer artifacts, real UBSan
support, authenticated registry, WAL durability/replay, NUMA-owner
reclamation, priority lanes, production shadow wiring, release-artifact
rollback, and qualification remain blockers.

Deliverables:

- implement cache-padded SPSC ring, 32-byte descriptor, bounded slab, and single-page volatile admission prototype;
- document linearization, memory ordering, shutdown, wrap, drop and epoch rules
  (**in progress / partial:** ADR-0006..0010 narrative + LLD §5 rotating
  admission linearization `[A]/`[S]`/`[R]`/`[E]`, wrap/drop/terminal notes);
- add safe differential oracles, Loom models, Miri tests and native stress benchmark;
- instrument allocations, copied bytes, cache misses and cycles/op
  (diagnostic criterion benches for ring/slab/admission/rotating compile in CI;
  no qualification numbers published).

Gate: zero lost/duplicated/reordered descriptors; validation before tail
acknowledgement; zero steady-state allocations; safety suite and hosted
sanitizer evidence green; no false sharing in layout/perf evidence. These gates
do not make the volatile prototype durable or authorize protected evidence.

### Week 5 — CoreReactor prototype

Deliverables:

- pin one OS thread per selected core;
- own one io_uring, listener, admission budget, request arena and ring producers per reactor;
- prove connection completion remains on its owner core;
- isolate REST/admin jobs on reserved control cores.

Gate: scheduler migration count zero for reactor threads under load; bounded overload response; clean shutdown with no leaked in-flight ownership.

### Week 6 — Qualification harness

Deliverables:

- create hardware manifest, core/IRQ/frequency setup, HDR histogram and coordinated-omission-correct load generator;
- add stage timing for validation, canonicalization, snapshot lookup, Cedar, commit, ring publish and response;
- publish current control run on the same qualified machine;
- add loss/duplicate/receipt verification to throughput tests.

Gate: one command produces raw artifacts and integrity report; mean-only results cannot pass a p99 gate.

## Phase 2 — Core Engine (Weeks 7–16)

### Week 7 — Immutable tenant snapshots

Deliverables:

- build immutable agent/tool/policy/trust snapshots off hot cores;
- publish complete generations to every decision reactor;
- add emergency revocation acknowledgement and fail-closed expiry;
- differential-test current `RwLock` engine against snapshots.

Gate: zero decision mismatches; one request never mixes generations; revocation propagation meets declared deadline.

### Week 8 — Split persistence contracts

Deliverables:

- introduce `ControlStore`, `ReceiptLog`, `EventStore` and `ProjectionStore` seams;
- map existing SQLite/PostgreSQL operations without changing semantics;
- move normal telemetry callers behind `EventStore`;
- record consistency/durability class at every call site.

Gate: no raw pool access in services; protected action transaction tests remain green; dependency DAG is acyclic.

### Week 9 — WAL and recovery

Deliverables:

- implement `AEGWAL02` format, CRC32C, sequence validation and bounded record parser;
- use registered io_uring files/buffers; implement protected/critical/normal acknowledgement classes;
- add group commit, critical reserve and disk-full behavior;
- inject crash/short-write/corruption at every record boundary.

Gate: acknowledged protected records survive every injected crash; interior corruption quarantines; torn tail truncates deterministically.

### Week 10 — HCMT memtable and L0 segment

Deliverables:

- implement preallocated structure-of-arrays memtable and spare-buffer swap;
- seal into aligned Arrow-compatible column buffers;
- implement exact segment metadata, hashes, granule index and atomic manifest publication;
- create golden segment corpus and independent inspection tool.

Gate: SQL/HCMT row equality on corpus; no row materialization during append; crash-safe segment publication.

### Week 11 — Timestamp and filter codecs

Deliverables:

- implement independently restartable Gorilla delta-of-delta blocks with raw fallback;
- implement zone maps, dictionary generations, Roaring indexes and blocked Bloom filters;
- fuzz codecs, overflow, corrupt lengths, dictionary mismatch and conservative pruning;
- report compression ratio and decode/prune cost by distribution.

Gate: no false-negative pruning; decoder equals raw timestamps; corrupted blocks never escape bounds.

### Week 12 — Compaction and retention

Deliverables:

- implement L0 overlap and non-overlapping L1+ leveled compaction;
- unify dictionaries, rebuild filters, deduplicate IDs and preserve evidence roots;
- add I/O/CPU token budgets, tenant fairness and debt throttling;
- implement whole-segment retention and manifest epoch retirement.

Gate: 24-hour accelerated soak with compaction active; bounded debt; query equality; measured write amplification.

### Week 13 — Vectorized query engine

Deliverables:

- implement manifest snapshot, partition/segment/granule pruning and residual vector operators;
- support time range, equality, set, trust/decision/severity, count, count-by and count-over-time;
- emit bounded Arrow batches with cancellation and memory/scanned-byte limits;
- shadow current SOC queries.

Gate: zero shadow mismatches for supported queries; budgets cancel safely; prune/decode statistics are correct.

### Week 14 — Binary telemetry ingestion

Deliverables:

- implement bidirectional gRPC ingest stream with FlatBuffer frames, CRC, credit and contiguous/durable ACKs;
- add sensor/cage dual protocol negotiation and durable replay until ACK;
- feed verified descriptors into per-writer rings without payload cloning;
- rate-limit/authenticate by trusted stream context, not frame tenant alone.

Gate: reorder/duplicate/loss/reconnect tests; authenticated tenant mismatch rejected; bounded memory under malicious stream.

### Week 15 — Dual write and shadow read

Deliverables:

- dual-write telemetry to row store and HCMT by per-tenant generation;
- compare query results and evidence linkage online by hashes;
- expose mismatch, lag, WAL, segment and compaction telemetry;
- exercise rollback to row reads and WAL replay into the legacy SOC drain.

Gate: two full replay corpora and a sustained staging interval with zero integrity-field mismatch.

### Week 16 — Core qualification checkpoint

Deliverables:

- run 30-minute steady and burst ingest with compaction/query load active;
- run warm authorization compute and separate protected-commit profiles;
- publish raw histograms, cycles/event, copies, allocations, cache/branch/NUMA misses and write amplification;
- file gaps instead of weakening durability or loss policy.

Gate: target passes or is explicitly recorded as unmet with bottleneck evidence. No marketing claim changes without pass.

## Phase 3 — SOC Plane (Weeks 17–24)

### Week 17 — Guardrail normalization and Aho compiler

Deliverables:

- version Unicode/case/newline/whitespace normalization and original-offset mapping;
- compile tenant pattern sets to bounded Aho-Corasick DFAs;
- enforce pattern/state/resident/output caps;
- atomically publish automaton generation with policy snapshots.

Gate: Aho equals naive reference across Unicode fuzz corpus; scan is `O(n+z)` and memory cap failure is explicit.

### Week 18 — Structured rule compiler

Deliverables:

- compile existing YAML predicates into typed field operations;
- combine DFA matches, Arrow dictionaries and bitmap predicates;
- eliminate per-event rule DB reads and stringly typed hot comparisons;
- preserve stable rule IDs and evidence references.

Gate: old/new detector differential equality; deterministic rules never create allow; first-stage latency histogram published.

### Week 19 — Product Quantization

Deliverables:

- implement/version PQ codebooks, fixed codes and exact reference distance;
- isolate training to approved content-addressed corpora;
- add tenant/model/tokenizer/codebook compatibility checks;
- measure quantization error, memory and scan throughput.

Gate: quality threshold accepted in ADR; cross-tenant/codebook mismatch rejected; deletion/retention defined.

### Week 20 — HNSW index

Deliverables:

- implement immutable HNSW generation plus mutable delta/rebuild path;
- integrate PQ distance tables and exact-search verification harness;
- implement tombstone/deletion debt and generation rollback;
- shadow current Qdrant results without serving them.

Gate: recall@k, p99, bytes/vector, build/rebuild and worst-case safeguards meet declared profile.

### Week 21 — INT8 ONNX inference

Deliverables:

- select signed/content-addressed model/tokenizer and calibration report;
- own one preallocated ORT session per inference core with one internal thread;
- batch within fixed queue/deadline limits;
- map outputs to advisory/tighten-only evidence.

Gate: queue+inference p99 fits async budget; quality threshold met; failure/timeout/saturation cannot allow or loosen trust.

### Week 22 — Partitioned correlation and response intents

Deliverables:

- partition time windows by tenant/agent owner;
- implement bounded frequency/sequence/state-machine operators over HCMT/live rings;
- produce idempotent signed response intents with autonomy policy;
- retain LLM narration only after evidence/decision closure.

Gate: deterministic replay yields identical incidents/intents; bounded memory per tenant; no inline decision dependency.

### Week 23 — eBPF observation

Deliverables:

- introduce shared kernel/user ABI and CO-RE build workspace;
- capture process lifecycle and cgroup network events through per-CPU maps/ring buffer;
- integrate sensor durable spool and loss counters;
- run verifier/kernel matrix and capability detection.

Gate: unsupported kernels report reduced assurance; no ABI drift; ring overflow is detected and surfaced.

### Week 24 — eBPF containment

Deliverables:

- add signed, generation-switched cgroup network and selected BPF LSM policy maps;
- implement expiry, rollback, break glass and last-known-policy behavior;
- test process/file/network containment in disposable VMs;
- bind every enforcement decision to tenant/node/cgroup and signed command receipt.

Gate: unauthorized/stale/replayed commands rejected; rollback works; lockout recovery exercised; `<100 ms p99` deterministic detection-to-intent target evaluated.

## Phase 4 — UI Layer (Weeks 25–30)

### Week 25 — Arrow query and browser stream

Deliverables:

- serve native Arrow Flight and Aegis Arrow Stream WebSocket envelopes;
- implement schema/dictionary generations, CRC, credit, cancel and resume cursor;
- enforce tenant query and output-field redaction before transmission;
- retain JSON query fallback.

Gate: reconnect/resume/restart tests; server never exceeds credit; malformed IPC/envelope rejected.

### Week 26 — Rust WASM Arrow worker

Deliverables:

- add `ui-wasm` crate, bounded arena and one-copy browser→WASM ingest;
- validate Arrow messages and create typed buffer views;
- implement SIMD/scalar filter, aggregate and level-of-detail parity;
- instrument copied bytes, allocations and worker time.

Gate: scalar/WASM SIMD equality; stale views invalidated on memory growth; no per-field copy.

### Week 27 — WebGL2 rendering kernel

Deliverables:

- implement structure-of-arrays GPU buffers, instancing, triple buffering and changed-range upload;
- implement off-screen ID picking and context-loss recovery;
- render time series, scatter, bars and heatmaps;
- add deterministic screenshot and GPU-capability fallbacks.

Gate: frame budget on declared GPU/viewport/cardinality; no DOM/SVG object per point.

### Week 28 — SOC panels on Arrow frames

Deliverables:

- migrate Explore, live feed, incidents, integrity timeline and agent risk panels;
- preserve action/receipt hash drill-down and verification state;
- keep React state bounded to summaries/selections;
- add server-side pixel aggregation.

Gate: JSON versus Arrow panel semantics match; approval/containment actions remain typed and CSRF/auth protected.

### Week 29 — Graph and live-stream scaling

Deliverables:

- migrate evidence graph nodes/edges to WASM layout and WebGL2 instancing;
- coalesce obsolete visual frames while preserving resume cursor;
- cancel stale queries on navigation/time changes;
- stress multi-stream backpressure and browser memory plateau.

Gate: bounded memory for 8-hour session; interaction remains within frame budget; no dropped durable cursor state.

### Week 30 — UI qualification and accessibility

Deliverables:

- publish p50/p95/p99 frame, worker, upload and draw timings;
- complete keyboard, focus, screen-reader summary, contrast and reduced-motion coverage;
- test context loss, reconnect, offline, schema change and slow-device degradation;
- retain legacy UI rollback flag.

Gate: 60 FPS p95 target passes declared stress profile; critical workflows accessible without canvas-only semantics.

## Phase 5 — Integration and Qualification (Weeks 31–36)

### Week 31 — SDK binary transport

Deliverables:

- add gRPC/protobuf authorization to Python, TypeScript and Go;
- add streaming FlatBuffer transport where applicable;
- preserve exact local v1 action hashing and fail-closed consume sequence;
- negotiate fallback without downgrade ambiguity.

Gate: cross-language transport/canonical corpus; network failure/hash mismatch/expiry/replay never executes a protected tool.

### Week 32 — Contract parity and adapter cleanup

Deliverables:

- reconcile all public REST routes with protobuf services or accepted deprecation ADRs;
- remove remaining gRPC/REST JSON bridging;
- generate route/RPC/schema compatibility reports;
- move handler business logic into service crates.

Gate: parity report complete; adapter-only dependency checks; protocol E2E tests use identical service outcomes.

### Week 33 — HA, NUMA and shard movement

Deliverables:

- qualify control-store HA mode and declare linearizability/RPO/RTO;
- implement routing generations, tenant writer movement and snapshot/manifest handoff;
- bind Kubernetes/systemd deployment to cpusets, topology and IRQ policy;
- test node loss and cross-NUMA avoidance.

Gate: no duplicate approval/receipt/control mutation across failover; declared RPO/RTO met; reactor migrations zero.

### Week 34 — Security and chaos qualification

Deliverables:

- run disk-full, corrupt WAL/segment, KMS outage, policy compiler failure, model failure, queue saturation, network partition and clock rollback campaigns;
- run cross-tenant fuzzing, unsafe-code review, Miri/Loom/sanitizers and eBPF verifier matrix;
- complete threat-model and operational runbook updates;
- exercise rollback from built release artifacts.

Gate: no unauthorized execution or acknowledged protected-evidence loss; every failure is bounded and observable.

### Week 35 — Comparative performance qualification

Deliverables:

- run Aegis targets on published qualified hardware for 30+ minutes with compaction and queries active;
- compare representative JVM SIEM/search pipeline using identical durability, replication, retention, event schema and loss policy;
- publish raw configs, manifests, histograms and integrity reports;
- document misses and saturation without benchmark-specific security weakening.

Gate: claims exactly match evidence. A missed target becomes a measured backlog item, not a rewritten result.

### Week 36 — Controlled cutover and release

Deliverables:

- complete two-release zero-mismatch shadow requirement for integrity fields;
- cut selected canary tenants to HCMT queries, Arrow UI, local semantic index and qualified sensor mode;
- retain transactional control store and rollback readers;
- update implementation status, release notes, operator docs and support matrix;
- schedule legacy telemetry/Qdrant/UI retirement only after retention and rollback gates.

Gate: canary SLOs, integrity proofs, recovery, rollback and operator sign-off pass. Target architecture becomes `qualified` only for the tested deployment profile.

## Cross-phase metrics

The weekly scorecard tracks:

- authorization compute and protected-commit p50/p95/p99/p99.9 separately;
- admitted/durable events/s and loss/duplicate count;
- cycles, allocations and copied bytes per event;
- scheduler migrations, context switches, L1/LLC/branch/NUMA misses;
- WAL sync p99, bytes/event, segment compression and write amplification;
- compaction debt/age, granules pruned and bytes decoded;
- Aho states/resident bytes/scan rate;
- HNSW recall@k/p99/bytes per vector and PQ error;
- ONNX queue/inference p99 and quality;
- detection-to-alert/intent p99;
- browser worker, upload, draw and total frame histograms;
- policy/control generation propagation and receipt-chain verification;
- shadow mismatch count, which must be exactly zero for integrity fields.

## Explicit non-goals for this 36-week program

- replacing the transactional control store with an unproven merge tree;
- claiming universal end-to-end zero-copy across kernel, TLS, browser, WASM and GPU;
- allowing a model score to bypass Cedar or increase trust;
- implementing a general-purpose Elasticsearch/OpenSearch-compatible query language;
- supporting arbitrary unbounded regex, script or plugin execution in query/guardrail reactors;
- deleting the legacy path before a tested release-artifact rollback exists;
- calling a target shipped because a microbenchmark passed.
