# ADR-0007: Sealed generation-tagged slab pages

**Status:** Proposed
**Date:** 2026-07-13
**Issue/PR:** pending

## Context

ADR-0006 establishes a current, unwired SPSC prototype whose ring carries a
32-byte `TelemetryDescriptor`; it deliberately leaves payload-page ownership
and reclamation undefined. Publishing descriptors without that contract would
permit a consumer to resolve mutable, recycled, partially initialized, or
out-of-bounds bytes. A page-lifetime mistake is both a memory-safety risk and a
cross-event integrity risk even when the ring's cursor ordering is correct.

The target HLD requires an ingress reactor to write a verified FlatBuffer once
into NUMA-local memory, publish descriptors, and retire pages through epochs.
Implementing concurrent published-prefix reads and page reuse in the same step
would combine three independent proof obligations: byte initialization,
publication ordering, and reclamation. This ADR permits a smaller
non-authoritative prototype that makes mutable-to-immutable ownership and stale
generation rejection testable before an epoch manager or `CoreReactor` exists.

The prototype remains outside every current production path. It cannot carry
protected evidence, does not make the target event fabric current or qualified,
and does not establish the target admission-latency or throughput claims.

## Decision

Add a bounded `SlabPageBuilder` to `aegis-event`. The builder directly owns one
pre-reserved payload vector and one pre-reserved descriptor vector, appends
frames sequentially, and withholds all descriptors from callers until
`seal(self)` consumes the builder. Sealing moves the same vectors behind one
page-level `Arc` without copying payload bytes; page-level leases then keep the
page alive while the SPSC ring transfers only copied 32-byte descriptors.

The prototype contract is:

- a page is configured with `arena_id`, `arena_generation`, byte capacity,
  descriptor capacity, and first producer sequence;
- byte capacity is in `1..=64 MiB`; descriptor capacity is in
  `1..=65,536`; an individual frame remains bounded to `1 MiB`;
- payload and descriptor reservations are fallible and return typed errors;
- one builder owns all mutation; it is never shared with a reader;
- append validates slab-local non-empty/maximum length and both remaining
  budgets before changing state; FlatBuffer verification is an upstream caller
  precondition, not a guarantee encoded by this API;
- payloads are tightly packed in append order; `offset` is the prior used-byte
  count and `len` is the exact input length, both represented as `u32` only
  after checked conversion;
- append copies the input payload once into the pre-reserved page, computes
  CRC32C over the complete payload, and pushes one fixed descriptor without
  requesting vector growth; allocator instrumentation remains a qualification
  gate rather than a claim from pointer stability alone;
- descriptor sequence advances modulo `2^64`, matching ADR-0006; generation
  reuse is not implemented by this prototype;
- sealing is the only mutable-to-immutable transition. No public API exposes a
  descriptor before its complete page is immutable;
- a reader resolves a descriptor only after exact arena-ID and generation
  equality, non-empty length validation, and exact equality with the descriptor
  stored at its bounded modular sequence distance in the sealed page table;
  only that canonical entry may select bytes, after which checked offset/length
  arithmetic against `used_bytes` and CRC32C equality are required;
- CRC32C detects accidental corruption; it is not authentication and cannot
  replace tenant binding, FlatBuffer verification, receipt hashes, or
  cryptographic signatures;
- integration MUST create reader leases once per bounded page handoff or
  downstream consumer, not once per event; the standalone prototype cannot
  enforce call frequency until an arena registry owns lease issuance;
- there is no reset/reuse method, mutable published prefix, registry, epoch
  pin, NUMA allocator, priority lane, WAL, or production integration in this
  slice.

## Invariants and state transition

```text
allocated builder
    -- checked append* --> mutable private prefix
    -- consume/seal ----> immutable sealed page + publishable descriptors
    -- page-level lease -> immutable reader view
    -- last lease drop --> backing allocation reclaimed
```

Only the builder can mutate the payload vector. `seal(self)` consumes that
capability before any descriptor can escape. `SealedSlabPage` and
`SlabPageReader` expose shared byte slices only; the backing vector is private
and never resized or mutated after sealing. Consequently, safe Rust supplies
the aliasing proof and this slice adds no unsafe code or atomic publication
protocol.

Page identity is the tuple `(arena_id, arena_generation)`. A descriptor for any
other tuple fails before offset resolution. Exact table membership prevents a
forged descriptor from relabeling another valid byte range's schema or flags;
CRC still covers payload bytes only. The builder never reuses a page; therefore
generation allocation, wrap prevention, page registry publication, and ABA
freedom remain obligations of the future epoch/arena ADR. The sealed page
exposes its next sequence so a caller can carry sequence continuity into the
next page; the future arena manager must own and enforce that handoff.

## Logical memory layout

```text
payload allocation (logical capacity <= 64 MiB)
+----------------+----------------+---------------------+
| frame 0 bytes  | frame 1 bytes  | unused capacity ... |
+----------------+----------------+---------------------+
0                offset[1]        used_bytes            byte_capacity

descriptor allocation (capacity <= 65,536)
+----------------------+----------------------+----------+
| descriptor(frame 0)  | descriptor(frame 1)  | unused   |
+----------------------+----------------------+----------+
```

There is no page header, padding, endian contract, or persistent ABI. The
descriptor remains the in-memory prototype ABI defined by ADR-0006. A wire,
shared-process, or disk page format requires a separately versioned schema and
golden byte corpus.

## Copy and allocation ledger

| Boundary | Ownership before → after | Payload copies | Allocation/refcount behavior |
|---|---|---:|---|
| caller-provided slice → private builder page | caller → builder-owned bytes | one bounded copy | payload and descriptor capacities were reserved at construction; upstream verification is a precondition |
| builder → sealed page | builder-owned vectors → immutable page `Arc` | zero | one page-metadata `Arc` allocation; payload/vector allocations are moved, not copied |
| sealed page → SPSC ring | page remains lease-owned | zero | one 32-byte descriptor value is copied; no payload reference count |
| page reader → consumer parser | immutable page → borrowed slice | zero | no allocation or refcount per resolve |
| page lease create/drop | immutable page remains shared | zero | one `Arc` increment/decrement per page-level lease |

CRC calculation and verification read the full payload but do not materialize
it. NIC/TLS/gRPC-to-caller ownership is outside this boundary and remains an
explicit copy decision in the wire/reactor ADR.

## Failure and overload behavior

- invalid zero or oversized budgets fail before allocation;
- payload/descriptor reservation failure is a typed constructor error;
- empty or over-`MAX_FRAME_BYTES` input is rejected without changing builder
  state;
- insufficient byte or descriptor capacity returns a typed saturation error
  without partial append, growth, eviction, or overwrite;
- stale arena ID or generation, zero length, integer overflow, range beyond
  `used_bytes`, CRC mismatch, unknown sequence, or descriptor-table mismatch
  fails closed and returns no byte slice;
- sealing an empty page is legal but yields no descriptors; callers cannot use
  it to publish an event;
- ordinary process OOM policy still applies to the small `Arc` allocation at
  seal; the append path does not attempt recovery allocation;
- no error changes Cedar authority, approval state, receipt durability, or a
  protected action into best effort.

## Consequences

The slice creates a safe reference implementation for page layout, bounds,
generation checks, CRC verification, and page-level lifetime. It proves that a
descriptor can traverse the existing ring while its payload stays in one page
allocation, and it gives later concurrent implementations a differential
oracle.

Sealing performs one page-level `Arc` metadata allocation but leaves the payload
and descriptor vector allocations in place. Withholding descriptors until a
whole page is sealed adds page-fill/rotation latency and prevents
producer/consumer overlap within a page. Without a bounded
time/size flush policy, a low-rate page could wait indefinitely; that behavior
is intentional for this prototype and is not the final target fast path. `Arc`
reclamation can also execute the payload deallocation on whichever thread drops
the final lease, so it is not an acceptable substitute for NUMA-owner epoch
retirement in a qualified reactor. The primitive bounds each page but does not
bound the number of outstanding pages or leases; the future arena manager must
enforce those budgets.

CRC32C costs `O(n)` per payload at append and again at resolve. The cost is
independent of page size but proportional to frame bytes; hardware acceleration
is selected by the reviewed `crc32c` dependency when supported. No throughput
or latency result is claimed without the repository benchmark contract.

The dependency is workspace-pinned to `crc32c = "=0.6.8"`, is dual
MIT/Apache-2.0 licensed, and adds no transitive normal runtime dependency. Its
manifest declares no MSRV and contains architecture-specific unsafe hardware
paths behind capability selection, so stable-toolchain compilation, a scalar
Castagnoli differential oracle, Miri, advisory scanning, and the exact CI
dependency allowlist remain required. This review does not transfer authority
to CRC32C or make it a cryptographic primitive.

## Alternatives considered

- **Concurrent append plus immutable published-prefix reads now** — closer to
  the target latency, but requires unsafe disjoint-byte aliasing, an atomic
  committed-prefix protocol, Loom modeling, Miri/sanitizer coverage, and page
  reclamation rules. It is deferred until the safe oracle is present.
- **Epoch retirement in this slice** — rejected because there is no page
  registry or pinned reactor reader yet. Adding `crossbeam-epoch` without a
  real pointer-publication lifetime would provide ceremony rather than proof.
- **One `Arc<[u8]>` or `Bytes` per event** — safe but adds per-event allocation
  or reference-count traffic and defeats page-level ownership.
- **Store variable payloads in ring slots** — makes the queue own allocation,
  drop, and NUMA lifetime and violates ADR-0006's fixed-descriptor boundary.
- **Return descriptors directly from `try_append`** — rejected because callers
  could publish a descriptor while later appends still mutate the same page.
- **Unchecked `Vec` growth** — rejected because capacity exhaustion would
  allocate or panic instead of returning the declared bounded overload result.

## Revisit when

Revisit before production telemetry wiring or `CoreReactor` integration. The
next decision must specify concurrent byte publication, arena registry lookup,
generation allocation/wrap behavior, crossbeam-epoch pin/retire rules, NUMA
allocation and owner-thread destruction, page rotation thresholds, priority
budgets, and sanitizer/Loom evidence. It must retain this safe implementation
as a differential oracle or explain its replacement.

## Security consequences

The page is an internal integrity boundary after authentication, bounded wire
verification, and tenant routing; it does not derive tenant identity. Exact
identity/generation and sealed-table membership checks prevent an ordinary
stale or metadata-mutated descriptor from being resolved as a valid event.
Used-byte bounds prevent access to reserved but unwritten capacity. CRC
mismatch returns no view, but CRC collision resistance is not a security
property. Production pages must remain within one authenticated routing scope;
a tenant-agnostic global page registry is prohibited.

The prototype stores arbitrary caller bytes in memory, so upstream redaction
and the ban on raw credentials remain mandatory. Errors and debug output expose
only sizes and numeric identity metadata, never payload content. Residual risk
includes caller-managed generation reuse, non-cryptographic descriptor
metadata, allocator/NUMA placement, and final-drop placement; production wiring
is blocked until those are resolved and security-reviewed.

## Verification

```bash
cargo test -p aegis-event
cargo test -p aegis-event --features loom loom_
cargo +nightly miri test -p aegis-event
cargo clippy -p aegis-event --all-targets --all-features -- -D warnings
cargo tree -p aegis-event --edges normal
```

Tests must cover constructor limits, exact descriptor fields and known CRC32C
vectors, byte/descriptor saturation with state and sequence preservation,
modular sequence wrap and cross-page continuity, identity/generation/range/CRC
and forged-metadata rejection, page lifetime after sealed-owner drop, stable
pre-reserved vector pointers across append/seal, no per-resolve refcount, and
descriptor-only cross-thread SPSC transfer. Future concurrent publication
requires new Loom states; this safe sealed-page implementation has no new
atomics to model beyond `Arc`'s standard-library ownership.

## Migration and rollback

The page is current only as isolated, unwired prototype code while this ADR is
Proposed. Rollback removes the slab module and its single reviewed dependency;
no state, wire format, traffic flag, or release migration is involved. Future
shadow integration must retain the current SQL/Tokio telemetry path and use the
per-tenant `telemetry_wire`/`event_write` generations until equality, loss,
recovery, and release-artifact rollback gates pass.

## References

- [ADR-0006: Cache-padded SPSC event fabric](0006-cache-padded-spsc-event-fabric.md)
- [Mandatory architecture law](../architecture.md)
- [Target HLD: Shared-memory SPSC event bus](../../ARCHITECTURE.md#5-shared-memory-spsc-event-bus)
- [Target HLD: Protocol and copy contract](../../ARCHITECTURE.md#10-protocol-and-copy-contract)
- [Target LLD: Descriptor ABI and memory reclamation](../LLD.md#52-descriptor-abi)
- [Migration matrix](../../MIGRATION_MATRIX.md#10-gap-analysis-against-target)
- [Contribution standard: Zero-copy and allocation claims](../../CONTRIBUTING.md#zero-copy-and-allocation-claims)
