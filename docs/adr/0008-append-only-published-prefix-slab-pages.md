# ADR-0008: Append-only published-prefix slab pages

**Status:** Proposed
**Date:** 2026-07-13
**Issue/PR:** pending

## Context

ADR-0007 adds a current, unwired seal-before-publish slab page. That safe
implementation proves bounded layout, generation checks, exact descriptor
membership, CRC32C validation, and page-level lifetime, but it withholds every
descriptor until the complete page is sealed. The target event fabric must let
the ingress owner publish each descriptor immediately after its payload becomes
immutable so the consumer can overlap page production and consumption.

Publishing a mutable prefix creates a new unsafe and concurrency boundary. A
reader must never observe partially copied bytes, an uninitialized descriptor,
or a descriptor whose bytes can later be overwritten. Reclamation and reuse are
separate obligations: solving publication does not establish ABA freedom,
tenant-safe registry lookup, NUMA-owner destruction, or bounded epoch pins.
Combining those mechanisms in one change would make failures difficult to
localize and would remove ADR-0007 as an independent correctness oracle.

This decision therefore covers only an append-only, preallocated page whose
writer and reader endpoints are created together before the first append. The
prototype remains outside every production path. It cannot carry protected
evidence, does not make the target event fabric qualified, and provides no
authorization-latency or ingestion-throughput measurement.

## Decision

Add `PublishedSlabPage` to `aegis-event`. Construction preallocates one bounded
byte-cell array and one bounded descriptor-cell array, then `split` consumes the
setup handle and returns exactly one non-cloneable writer and one non-cloneable
reader. The writer appends to never-before-written cells and publishes one
packed, monotonic state word containing descriptor count, byte watermark, and
closure with a `Release` store. The reader performs one `Acquire` load of that
state before reading a committed descriptor slot or borrowing its immutable
byte range.

The prototype contract is:

- it reuses `SlabPageConfig` limits: byte capacity is `1..=64 MiB`, descriptor
  capacity is `1..=65,536`, and one payload is `1..=1 MiB`;
- payload-cell and descriptor-cell reservations are fallible and return the
  existing typed `SlabConfigError`; the small `Arc` metadata allocation remains
  subject to the process OOM policy;
- each reservation is filled to its configured length before the page enters
  the `Arc`; the private `Vec<ByteCell>` and `Vec<DescriptorCell>` metadata,
  lengths, capacities, and backing addresses never change after construction;
- `split` creates one writer and one reader; neither endpoint is cloneable and
  both are `!Sync`; each may move to its owner thread;
- the writer's staged descriptor cursor, used-byte cursor, and next sequence are
  private, non-atomic state accessed through `&mut self`; the packed atomic word
  is the authoritative cross-thread committed prefix;
- append checks payload length, descriptor budget, checked offset arithmetic,
  byte budget, and `u32` representability before touching page cells;
- FlatBuffer verification and redaction are upstream preconditions; this API
  validates slab-local framing and integrity only;
- append computes CRC32C, copies the payload once into a never-before-written
  byte range, writes the complete canonical descriptor into a
  never-before-written descriptor slot, and then
  `Release`-stores one state word containing `published_count = slot_index + 1`
  and `published_bytes = end_offset`; only after publication does it commit the
  staged writer-private cursors;
- no fallible, allocating, callback, formatting, indexing, or other
  panic-capable operation occurs after the first cell write and before the
  `Release` publication. The writer marks that interval poisoned; if unwinding
  is nevertheless forced and caught, future append attempts fail permanently
  rather than overwriting a partially initialized suffix;
- the `Release` store is the append linearization point. No descriptor is
  returned before that store completes;
- published count starts at zero, increases by exactly one, never exceeds the
  configured descriptor capacity, and cannot wrap within one page; published
  bytes starts at zero, increases by the non-empty payload length, and never
  exceeds byte capacity;
- descriptor sequence advances modulo `2^64`. Because a page holds at most
  `2^16` descriptors, modular distance from `first_sequence` is unambiguous;
- the reader validates exact arena ID and generation, loads the packed state
  with `Acquire`, validates reserved bits/count/byte watermark against page
  capacities, bounds the modular sequence distance by the published count,
  reads the canonical descriptor slot, and requires exact descriptor equality
  before accessing caller-selected payload bytes;
- only the canonical descriptor selects the payload range. Checked
  offset/length arithmetic against the coherently published byte watermark and
  CRC32C equality are then required before returning a view;
- the native reader returns a wrapper around a borrowed slice into the page;
  resolution performs no payload copy, allocation, or reference-count change;
- the Loom feature uses modeled atomics and checked cells. Its returned payload
  wrapper owns a small model-only copy because a reference cannot escape a Loom
  `UnsafeCell` access guard; Miri and sanitizers cover the native borrowed-view
  implementation;
- dropping the writer `Release`-publishes closure. The reader may drain every
  committed descriptor and retain page ownership after writer drop;
- cells are never reset, overwritten, or reused. There is no registry, epoch,
  generation allocator, NUMA pool, rotation policy, priority lane, WAL, or
  production integration in this decision.

## Ownership, publication, and memory-order proof

```text
setup handle
    -- consume/split --> one writer + one reader, both owning the page Arc

writer append i:
    validate all bounds
    write byte cells [offset_i, end_i) exactly once
    write descriptor cell i exactly once
    Release store pack(count = i + 1, bytes = end_i)  <-- linearization
    commit staged writer-private cursors
    return descriptor i

reader resolve descriptor i:
    validate page identity
    state = Acquire load publication_state
    validate state and require i < state.published_count
    read canonical descriptor cell i
    require exact descriptor equality
    validate canonical byte range and CRC32C
    borrow immutable byte cells [offset_i, end_i)
```

There is one writer, so descriptor slots and payload ranges are assigned in
strict append order without write/write races. A reader accesses slot `i` only
after an `Acquire` load observes a published count greater than `i`; that load
synchronizes with the `Release` store sequenced after both the byte copy and the
descriptor write. The byte watermark in the same state snapshot independently
bounds canonical ranges to initialized published bytes. Later appends touch
only disjoint cells, so an outstanding borrow into an earlier committed range
cannot alias a write. No committed cell is ever mutated.

`Relaxed` is insufficient for state publication because it would not
make preceding cell initialization visible. `SeqCst` adds a global order that
the single-writer prefix protocol does not require. Per-cell ready flags are
unnecessary because the committed prefix has no gaps. The packed `AtomicU64` is
cache-line aligned with `#[repr(align(64))]`; bits `0..=31` encode published
bytes, bits `32..=48` encode the 17-bit published count, bits `49..=62` are
reserved and must be zero, and bit `63` encodes writer closure. The capacity
limits fit those fields exactly. Closure shares the publication line because it
is written once at shutdown and does not create an independent hot cursor.

The progress property of a successful append is wait-free with respect to
other threads after bounded `O(n)` CRC and copy work for payload length `n`.
Resolution is wait-free after bounded `O(n)` CRC work. Neither operation loops,
blocks, grows a collection, calls an allocator, waits on another core, or
silently overwrites data. Capacity exhaustion is an immediate typed error.

## Unsafe invariants

The native implementation uses `#[repr(transparent)]` wrappers around
`UnsafeCell<MaybeUninit<u8>>` and
`UnsafeCell<MaybeUninit<TelemetryDescriptor>>` because safe slices cannot
express one writer mutating an unpublished suffix while another owner borrows
an immutable published prefix. Every unsafe block must preserve all of the
following:

1. `UnsafeCell<T>` and `MaybeUninit<T>` have `T`'s representation; the
   transparent wrappers therefore preserve the native `u8` and
   `TelemetryDescriptor` size/alignment, and their arrays remain at stable
   allocation-derived addresses from construction through final page drop;
2. the writer is the only mutator and writes each addressed cell exactly once;
3. all pointer arithmetic is derived from the owning allocation and preceded by
   checked range validation against the allocated cell count; no `&u8`,
   `&mut u8`, `&TelemetryDescriptor`, or `&mut TelemetryDescriptor` spans the
   whole allocation or an uncommitted suffix;
4. no reader accesses a descriptor or byte cell until an `Acquire` state
   snapshot proves the corresponding count and byte prefix was committed;
5. a descriptor is fully initialized before its state-word publication;
6. a returned native slice contains initialized `u8` cells only, is bounded by
   one canonical descriptor, and cannot overlap any later write;
7. the slice lifetime is bounded by the reader's page-owning `Arc`; dropping the
   writer cannot invalidate it;
8. `TelemetryDescriptor` and `u8` have no drop obligation in uncommitted cells;
9. final `Arc` drop occurs only after both endpoints and all reader borrows are
   gone; uncommitted `MaybeUninit` cells require no destruction;
10. there is no external endian, persistent, or shared-process ABI in this
    prototype.

The writer stages every slice/slot lookup, integer conversion, CRC, descriptor,
next cursor value, and packed state before setting its poison bit and performing
the first raw write. Native payload copying is then one `copy_nonoverlapping`
between proven disjoint ranges; the source may be an earlier committed payload
because its range cannot overlap the append-only destination. Descriptor
initialization, one atomic store, writer-local assignments, and poison clearing
are the only subsequent operations. If an injected or platform fault unwinds
before the store, the atomic prefix is unchanged, the partial tail is
unreachable, and the poisoned writer cannot resume. Writer drop sets only the
closed bit with an atomic read-modify-write against the authoritative published
state; it never derives closure from staged cursors and therefore cannot expose
the partial tail. If an interruption is forced after the Release store but
before cursor commit/return, the complete prefix remains published and closure
preserves it, while the poisoned endpoint cannot append again; production
integration must recover the resulting committed-but-undelivered descriptor
through its future composite admission/WAL protocol. Process abort needs no
in-process recovery.

The page cell arrays contain fixed-size elements and never resize. Native tests
assert the transparent-cell sizes and alignments, stable view pointers, and
borrow validity while later disjoint appends occur. The safe sealed page remains
the differential oracle for descriptor values and resolved payload bytes.

## Logical memory layout

```text
publication cache line (64-byte aligned)
+-------------------------+---------------+---------------------------+
| bytes:u32 | count:u17   | reserved:14   | closed:1                  |
+-------------------------+---------------+---------------------------+

payload cells (preallocated, append-only)
+=================+=================+-------------------------------+
| committed frame | committed frame | unpublished/uninitialized     |
| 0 bytes         | 1 bytes         | suffix                        |
+=================+=================+-------------------------------+
0                 offset[1]         writer.used_bytes      capacity

descriptor cells (preallocated, append-only)
+======================+======================+-----------------------+
| committed desc 0     | committed desc 1     | uninitialized suffix  |
+======================+======================+-----------------------+
0                                             published_count
```

This is a process-local layout, not a stable wire or disk format. The 32-byte
descriptor remains the prototype ABI from ADR-0006. Any mmap, cross-process, or
persistent representation requires a version, endian contract, checksums, and a
golden corpus in a separate ADR.

## Copy and allocation ledger

| Boundary | Ownership before → after | Payload copies | Allocation/refcount behavior |
|---|---|---:|---|
| page construction | allocator → setup handle | zero | one bounded byte reservation, one bounded descriptor reservation, and one small page `Arc` allocation |
| caller slice → unpublished suffix | caller → writer-owned cells | one bounded copy | no append-time allocation or growth |
| writer → reader publication | same page allocation remains endpoint-owned | zero | one 32-byte descriptor value returned; one `Release` atomic store |
| descriptor ring transfer | page remains reader-owned | zero | ring copies the 32-byte descriptor; no payload refcount |
| native resolve → parser | reader-owned page → borrowed view | zero | no allocation, copy, or `Arc` operation per resolve |
| Loom resolve | modeled cells → model assertion wrapper | one model-only copy | test-feature artifact; excluded from shipping copy claims |
| endpoint drop | last endpoint → allocator | zero | final `Arc` decrement may deallocate on either endpoint owner |

Kernel/user, TLS, gRPC, FlatBuffer verification, decompression, Arrow, browser,
WASM, and GPU transfers are outside this page-local boundary and remain visible
in their owning copy ledgers.

## Failure and overload behavior

- invalid capacity fails before cell initialization;
- payload or descriptor reservation failure returns a typed allocation error;
- empty or oversized payload fails without changing writer state or cells;
- a poisoned writer fails closed without touching cells or publication state;
- descriptor or byte exhaustion fails without advancing sequence, committing a
  slot, growing storage, spilling, evicting, or overwriting;
- checked-add or descriptor-address conversion failure is non-mutating;
- identity/generation mismatch, unpublished sequence, invalid packed state,
  exact-descriptor mismatch, invalid canonical range, or CRC mismatch returns
  no payload view;
- CRC errors expose sequence only, not payload bytes or expected/computed CRC;
- reader polling is not built into the page. An unpublished descriptor returns
  immediately; bounded retry/admission belongs to the owning reactor;
- writer drop freezes the published prefix permanently. It does not seal,
  recycle, transfer tenant scope, or make uncommitted suffix cells readable;
- process OOM for the small `Arc` metadata allocation remains the workspace
  process policy; no append-path recovery allocation exists;
- no failure can loosen Cedar, consume an approval, weaken receipt durability,
  or convert protected evidence to best effort.

## Security consequences

The page is an internal post-authentication boundary. It does not derive tenant
identity; construction and endpoint routing must remain inside one authenticated
tenant/shard scope. A tenant-agnostic global lookup table is prohibited. Exact
identity, generation, committed-prefix, and canonical descriptor checks prevent
ordinary stale, forged, relabeled, or redirected descriptors from selecting
bytes. Canonical membership is checked before CRC scanning so attacker-supplied
offset/length/CRC fields cannot turn the resolver into an arbitrary-range CRC
oracle.

CRC32C detects accidental corruption and is not authentication. It cannot
replace FlatBuffer verification, receipt chaining, action hashes, Ed25519, or
tenant binding. Payload bytes may contain sensitive telemetry, so upstream
redaction and the raw-credential prohibition remain mandatory. Public errors
and `Debug` implementations must never include payload contents.

Residual risk includes unsafe aliasing defects, process-local arena metadata,
caller-managed generation identity, final deallocation on the consumer core,
and absence of bounded page accounting. Production wiring remains blocked on
maintainer unsafe/security review, sanitizers, authenticated registry design,
generation/reuse proof, epoch/NUMA retirement, rotation/admission policy, and
shadow loss/equality evidence.

## Performance hypothesis and benchmark method

For payload length `n`, append performs `O(n)` CRC plus one `O(n)` copy and
`O(1)` descriptor initialization/publication. Resolve performs `O(1)` identity,
sequence, and table checks plus `O(n)` CRC and returns an `O(1)` borrowed view.
These costs are independent of total page population. The design removes the
whole-page seal latency and permits producer/consumer overlap, but it does not
prove a throughput or latency target.

Qualification must compare sealed and published-prefix pages on the declared
hardware with identical payload distributions and include p50/p95/p99/p99.9,
events/s, bytes/s, allocation/event, copied bytes/event, cycles/byte, branch and
cache misses, cache-line transfers, producer stalls, errors, and saturation.
Tests must verify no lost, duplicated, reordered, or mismatched descriptors.
The measurement must separate CRC/copy cost from ring transfer and protected
durability. Raw histograms and hardware/kernel/NUMA configuration are required.

## Alternatives considered

- **Keep seal-before-publish only** — preserves safe Rust but adds page-fill or
  timeout latency and prevents overlap within a page; retained as the oracle,
  not the target publication mechanism.
- **Add page reuse and epochs now** — rejected because registry publication,
  generation allocation, pin duration, retirement owner, and ABA freedom are
  independent proof obligations with different failure modes.
- **Atomic flag per descriptor or byte** — rejected because it increases memory
  and cache traffic while a single writer already guarantees a gap-free prefix.
- **Atomic committed count without a byte watermark** — sound when the
  canonical descriptor is the sole initialization proof, but rejected because
  one packed word can also fail closed if malformed internal metadata selects
  reserved or unpublished tail bytes.
- **Atomic committed byte count only** — rejected because it does not prove a
  canonical descriptor slot is initialized and makes variable-length record
  lookup ambiguous.
- **Return `Arc<[u8]>`/`Bytes` per event** — rejected because it creates
  per-event allocation or reference-count traffic and weakens page ownership.
- **Copy on native resolve** — rejected because it hides lifetime mistakes and
  violates the page-local zero-copy objective; Loom alone uses a disclosed
  model-only copy.
- **`Relaxed` publication** — rejected because descriptor and byte
  initialization would have no happens-before edge to the reader.
- **`SeqCst` publication** — rejected because no cross-page total order is
  needed; Acquire/Release is the minimal sufficient protocol.
- **Crossbeam epoch in an unwired page pair** — rejected because there is no
  pointer registry or reuse path to reclaim, and adding an unused epoch guard
  would not prove production lifetime.

## Verification

```bash
cargo test -p aegis-event
cargo test -p aegis-event --features loom loom_published
cargo +nightly miri test -p aegis-event
cargo clippy -p aegis-event --all-targets --all-features -- -D warnings
cargo tree -p aegis-event --edges normal
RUSTFLAGS='-Zsanitizer=address' cargo +nightly test -Zbuild-std --target x86_64-unknown-linux-gnu -p aegis-event --test published_slab
RUSTFLAGS='-Zsanitizer=thread' cargo +nightly test -Zbuild-std --target x86_64-unknown-linux-gnu -p aegis-event --test published_slab
```

Required coverage includes constructor bounds and allocation classification;
immediate same-page publication; identity/generation/metadata forgery rejection;
future-sequence rejection; byte and descriptor saturation with state and
sequence preservation; sequence wrap at `u64::MAX`; writer closure and page
lifetime; stable native borrowed pointers while later disjoint appends occur;
no per-resolve `Arc` change; deterministic corruption rejection; long
cross-thread descriptor-ring stress; byte-for-byte and descriptor-for-descriptor
differential tests against ADR-0007; Loom exploration of read-before/read-after
publication and shutdown; Miri native alias/lifetime checks; ASan/UBSan and TSan
where supported.

Loom must execute the same packed-state and cell-access algorithm. Its
model-only payload copy is not accepted as native lifetime evidence. Miri and
sanitizers must execute the native borrowed-view path.

The 2026-07-13 Rust nightly exposes `address` and `thread` sanitizers but rejects
`-Zsanitizer=undefined`; Miri is the current Rust undefined-behavior/provenance
gate. This limitation is recorded rather than relabeling another check as
UBSan. It remains an unmet `CONTRIBUTING.md` acceptance gate for this ADR; Miri
does not satisfy that requirement. Any future C/C++/FFI boundary must also add
its toolchain's real UBSan lane before acceptance.

## Migration and rollback

The implementation is current only as isolated, unwired prototype code while
this ADR is Proposed. It receives no production traffic, protected evidence,
schema authority, or durable state. Rollback deletes the published-prefix
module and ADR references while retaining ADR-0007's safe sealed page and
ADR-0006's descriptor ring; no data migration or runtime flag is involved.

Future shadow integration must retain the current SQL/Tokio telemetry path and
use the documented per-tenant `telemetry_wire` and `event_write` generations.
Cutover additionally requires authenticated page routing, bounded outstanding
pages, epoch/NUMA reuse, crash/loss tests, shadow equality, reproducible tail
latency evidence, and release-artifact rollback.

## Revisit when

Revisit before any arena registry, reset/reuse, crossbeam-epoch reclamation,
NUMA pool, production reactor, or protected-evidence integration. The next ADR
must define identity allocation and wrap, authenticated registry scope, pin and
retire ownership, page rotation/flush deadlines, outstanding-page admission,
priority policy, and sanitizer/benchmark qualification. It must retain the
sealed oracle and this append-only implementation as differential references or
justify their replacement.

## References

- [ADR-0006: Cache-padded SPSC event fabric](0006-cache-padded-spsc-event-fabric.md)
- [ADR-0007: Sealed generation-tagged slab pages](0007-sealed-generation-tagged-slab-pages.md)
- [Mandatory architecture law](../architecture.md)
- [Target HLD: Shared-memory SPSC event bus](../../ARCHITECTURE.md#5-shared-memory-spsc-event-bus)
- [Target HLD: Protocol and copy contract](../../ARCHITECTURE.md#10-protocol-and-copy-contract)
- [Target LLD: Event fabric](../LLD.md#5-event-fabric-and-lmax-style-sequencing)
- [Target LLD: Descriptor ABI](../LLD.md#52-descriptor-abi)
- [Migration matrix](../../MIGRATION_MATRIX.md#10-gap-analysis-against-target)
- [Contribution standard: lock-free structures](../../CONTRIBUTING.md#lock-free-structures)
- [Contribution standard: unsafe Rust](../../CONTRIBUTING.md#unsafe-rust)
- [Contribution standard: zero-copy claims](../../CONTRIBUTING.md#zero-copy-and-allocation-claims)
