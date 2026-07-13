# ADR-0006: Cache-padded SPSC event fabric

**Status:** Proposed
**Date:** 2026-07-13
**Issue/PR:** pending

## Context

The current telemetry path uses Tokio tasks and bounded MPSC channels before
materializing events into SQL-oriented storage. The target data plane assigns
mutable hot state to one pinned thread and transfers telemetry from each ingress
reactor to one NUMA-local writer. That topology is single-producer,
single-consumer by construction; a generic MPSC queue adds producer
coordination, scheduler wakeups, and cache-line traffic that the edge does not
need.

The ring also becomes an unsafe ownership boundary. Publishing a cursor before
the payload is initialized, reusing a slot before the consumer finishes, or
dropping an initialized slot twice would be memory-unsafe. A fast prototype is
therefore acceptable only with an explicit ownership and memory-ordering
contract plus model, interpreter, stress, and layout tests.

This ADR permits a non-authoritative `aegis-event` prototype while its status is
Proposed. Production telemetry wiring, protected evidence, slab-page lifetime,
and performance claims remain blocked until this ADR is accepted and their
separate gates pass.

## Decision

Create a bounded, power-of-two SPSC ring with the following contract:

- construction consumes the only splittable ring handle and returns exactly one
  non-cloneable `Producer` and one non-cloneable `Consumer`;
- each endpoint requires `&mut self` for mutation and is `Send` but not `Sync`;
- producer and consumer cursors occupy distinct 64-byte-aligned cache lines;
- the producer exclusively initializes a free slot, then publishes the next
  monotonic sequence with a `Release` store;
- the consumer observes publication with an `Acquire` load, moves the value out
  exactly once, then releases the consumed sequence;
- the producer acquires the consumed sequence before reusing a slot;
- cached remote cursors may cause a conservative full/empty result but cannot
  permit overwrite or uninitialized read;
- sequence arithmetic is modulo `2^64`; capacity is less than `2^63`, so the
  producer-consumer distance is unambiguous while the bounded-ring invariant
  holds;
- `try_push` and `try_pop` perform bounded work and never sleep, spin, allocate,
  invoke a callback, or enter an async runtime;
- saturation returns ownership of the rejected value to the producer;
- endpoint closure is explicit. A consumer drains already-published values
  before reporting producer disconnection. Concurrent closure may race with at
  most one successful publication, which remains initialized and is either
  consumed or dropped by final ring destruction;
- final ring destruction drops every published but unread value exactly once;
- the ring transfers fixed descriptors. Payload bytes remain in a separately
  owned slab and are not copied by the ring.

The initial descriptor ABI is `#[repr(C, align(32))]` and exactly 32 bytes. It
contains sequence, arena identity/generation, flags, checked offset/length,
CRC32C, and schema ID fields. This ADR freezes the in-memory prototype layout,
not a stable cross-process or disk ABI; those require the wire/segment ADR.

The unsafe implementation is confined to `lib/event/src/ring.rs`. Each unsafe
operation states the slot ownership, initialization, aliasing, and ordering
preconditions at the operation. The crate forbids unsafe operations inside an
unsafe function unless they are in an explicit unsafe block.

## Invariants and linearization points

`Producer::try_push` linearizes at the `Release` store to `published_head`.
Before that store, only the producer may access the selected slot. After an
`Acquire` load observes the sequence, only the consumer may move the value from
that slot.

`Consumer::try_pop` makes the slot reusable at the `Release` store to
`consumed_tail`. A producer may overwrite the slot only after an `Acquire` load
observes that sequence. The producer never advances more than `N` sequences
ahead of the consumer; the consumer never advances beyond the published head.

The progress property of each try-operation is wait-free for its owning thread:
the operation executes a fixed number of local operations and atomic loads or
stores. End-to-end delivery is not wait-free because progress also requires the
other endpoint and downstream capacity.

## Failure and overload behavior

- zero, non-power-of-two, or sequence-ambiguous capacity is rejected before
  allocation;
- a full ring returns `TryPushError::Full(value)` without modifying any slot;
- an empty connected ring returns `TryPopError::Empty`;
- a closed peer returns `Disconnected`; normal telemetry callers must reject or
  use their bounded durable spool;
- the ring never silently overwrites, expands, allocates an overflow node, or
  changes protected work to best effort;
- panic during a user value destructor follows Rust's ordinary unwinding rules;
  it cannot cause another initialized slot to be read twice, although remaining
  values may leak during process unwind as with other panicking destructors.

## Consequences

The normal data transfer costs one slot write, one publication store, one slot
read, and one consumption store. Remote cursors are cached, reducing coherence
loads until the ring approaches empty or full. Setup allocates the slot array
and two endpoint reference counts; steady-state push/pop allocates nothing.

The design deliberately does not include blocking waits, multi-producer access,
dynamic resizing, slab allocation, epoch reclamation, priority scheduling, or
WAL durability. Those responsibilities remain separate so their overload and
failure policies cannot be hidden inside a queue primitive.

Maintaining custom unsafe concurrency code has a substantial review and tooling
cost. The implementation must remain smaller than a generic queue and may be
replaced if a maintained primitive proves the same cursor visibility, layout,
drop, and slab-lifetime contract with equal or better measurements.

## Alternatives considered

- **Tokio bounded MPSC** — already useful in the compatibility plane, but it
  permits multiple producers and couples progress to the async scheduler. It
  does not establish the target one-core ownership or descriptor/slab contract.
- **Crossbeam `ArrayQueue`** — bounded and well reviewed, but implements MPMC
  coordination and per-slot sequencing that this topology does not require.
- **An external SPSC crate** — preferable if it exposes the required monotonic
  publication/consumption sequences, shutdown/drop proof, 64-byte cursor
  isolation, and Loom/Miri evidence. No dependency is selected by this ADR;
  replacement remains explicitly allowed after an audited comparison.
- **A ring of payload objects** — rejected because variable payload ownership
  would make the queue responsible for allocation, copies, and NUMA lifetime.
  The ring carries only descriptors into an independently bounded slab.
- **Per-slot atomics** — unnecessary for one producer and one consumer. Global
  producer/consumer sequences prove ownership and avoid another atomic per slot.

## Revisit when

Revisit before production wiring, when slab-page epoch retirement is designed,
when a maintained SPSC crate satisfies the full contract, when qualification
shows cursor/state layout is a bottleneck, or when a target lacks lock-free
64-bit atomics.

## Security consequences

The ring handles authenticated, tenant-routed telemetry only after bounded wire
verification; it does not authenticate tenant claims or authorize actions.
Descriptor offset and length arithmetic is checked before a slab view is
created. Payload bytes and raw credentials are never logged by this primitive.

Normal telemetry may be rejected only under its declared replay/spool policy.
Critical evidence must use a separately reserved ring and protected WAL lane;
until that lane exists, this prototype must not carry evidence whose successful
publication would authorize execution. Ring corruption, disconnect, or
saturation never converts a Cedar deny, approval failure, or receipt durability
failure into allow.

Residual risk is concentrated in unsafe slot initialization/drop and the atomic
ordering proof. Production wiring requires designated unsafe/concurrency review,
Miri, Loom, supported sanitizers, long native stress, and raw cache/allocation
measurements.

## Verification

```bash
cargo test -p aegis-event
cargo test -p aegis-event --features loom loom_
cargo +nightly miri test -p aegis-event
cargo bench -p aegis-event --bench spsc_ring
cargo clippy -p aegis-event --all-targets -- -D warnings
cargo tree -p aegis-event
```

Required tests cover FIFO ordering, full/empty transitions, endpoint closure,
unread-value destruction, modular sequence wrap, cache-line and descriptor
layout, randomized native stress, and Loom publication/reuse schedules. A
benchmark result is evidence only when accompanied by the repository's hardware
manifest and raw artifacts; this ADR makes no throughput claim.

## Migration and rollback

The prototype is not wired into any current path, so rollback is removal of the
workspace member. Later integration must be controlled by the per-tenant
`event_write` generation and retain the current Tokio/SQL pipeline until shadow
equality, loss/duplicate, crash, and release-artifact rollback gates pass.

## References

- [Mandatory architecture law](../architecture.md)
- [Target HLD: shared-memory SPSC event bus](../../ARCHITECTURE.md#5-shared-memory-spsc-event-bus)
- [Target LLD: Disruptor-style SPSC ring](../LLD.md#5-disruptor-style-spsc-ring)
- [Migration matrix](../../MIGRATION_MATRIX.md#8-target-component-map)
- [Contribution and unsafe-code standard](../../CONTRIBUTING.md#lock-free-structures)
