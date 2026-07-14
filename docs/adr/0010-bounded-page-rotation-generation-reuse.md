# ADR-0010: Bounded page rotation with generation-tagged reuse

**Status:** Proposed
**Date:** 2026-07-14
**Issue/PR:** pending

> **Design-first ADR.** The design above landed before any code (ADR-0009
> §"Revisit when" required that stop); an **unwired prototype**
> (`lib/event/src/rotating.rs`) accompanies it in the same review with the
> deviations disclosed in §Prototype notes. Proposed status still permits
> only unwired prototypes.

## Context

ADR-0009's `VolatileAdmissionChannel<N>` binds one preallocated
published-prefix page (ADR-0008) to one SPSC descriptor ring (ADR-0006). When
the page's byte or descriptor capacity is exhausted the lane is finished: the
typed `page full` error is terminal for the channel's useful life, and the
producer's only recovery is to tear down and rebuild the composite, losing the
ring, sequence continuity, and the consumer binding.

A production event fabric cannot run on one page per lane lifetime. It needs
the producer to continue admitting into a fresh page while the consumer
finishes draining the previous one — with the number of simultaneously live
pages **bounded by construction**, page memory **reused** rather than
reallocated, and reuse **provably safe** against stale descriptors addressing
a recycled page (the ABA problem).

Scope boundaries inherited from ADR-0009 remain: one producer, one consumer,
volatile, process-local, unwired, non-authoritative. This ADR adds only
rotation, bounded outstanding pages, and generation-tagged reuse. It does
**not** add WAL durability/replay, authenticated registry lookup, NUMA pool
placement policy, priority lanes, crossbeam-epoch, multi-producer or
multi-consumer topology, or any protected-evidence semantics.

## Decision

Add a `RotatingAdmissionChannel<N, P>` in `aegis-event`: one SPSC descriptor
ring bound to a **fixed pool of `P >= 2` identically-configured page slots**,
all preallocated at construction. No allocation, deallocation, or `Arc`
reference-count traffic occurs after `split`.

### Page epochs and slot addressing

Pages are identified by a monotonically increasing **page epoch** `e`
(`u64`, starting at 0). Epoch `e` occupies pool slot `e mod P` and stamps its
descriptors with `arena_generation = e as u32` (wrapping). The consumer
recovers the slot index from a descriptor as
`descriptor.arena_generation as u64 mod P` and then requires **exact
generation equality** with the slot's currently-bound page before any
descriptor-cell or payload access — the same identity check ADR-0007/0008
already enforce, now doing double duty as the reuse guard.

Sequence space is continuous across pages: page epoch `e+1` is constructed
with `first_sequence` equal to the sealed page `e`'s `next_sequence`, so ring
sequence and page sequence remain a single unbroken wrapping sequence exactly
as in ADR-0009.

### Producer rotation algorithm

Rotation is attempted only inside admission, only on the typed
`page full` / `descriptor full` validation results, and **before** ring
reservation — a rotated-then-admitted event keeps ADR-0009's phase discipline
unchanged:

```text
validate payload length against the ACTIVE page
on page/descriptor full:
    Acquire-load consumer released_epoch                      [A]
    require active_epoch + 1 <= released_epoch + P            (slot free?)
    on failure: return typed PageQuotaExhausted — nothing mutated
    Release-close the active page writer (seal, ADR-0008)     [S]
    rebind slot (active_epoch + 1) mod P:
        new generation = (active_epoch + 1) as u32
        first_sequence = sealed page next_sequence
    active_epoch += 1
    re-validate payload against the fresh page
then the unchanged ADR-0009 admission sequence:
    reserve ring slot, InFlight, append + page Release [P],
    ring slot write, ring Release [R], Open
```

Properties:

- **Bounded work, no waiting.** Rotation is a seal, one Acquire load, one
  slot re-initialization over preallocated memory, and bookkeeping. If the
  successor slot is still outstanding, the producer returns
  `PageQuotaExhausted` with **zero page and zero ring mutation** — the caller
  applies its declared event-class policy (bounded retry, spool, or
  best-effort drop). No spin, sleep, allocation, or overflow queue.
- **A payload larger than one empty page** is still the ADR-0008 typed
  invalid-input error; rotation never loops.
- **Failure atomicity is preserved.** The quota check happens before the seal
  `[S]`, so a refused rotation leaves the active page open and usable for
  smaller payloads. An unwind during rotation follows ADR-0009's caught-unwind
  contract: ordered faulted closure of the page (sealed or fresh), terminal
  word, and ring.

### Consumer release protocol

The ring is FIFO and consumption is strictly in-order (ADR-0009's exact
expected-sequence rule), so descriptors arrive grouped by epoch in epoch
order. The consumer tracks `current_epoch` and, upon validating the first
descriptor of epoch `e+1`:

1. requires its per-epoch committed count to equal the sealed page `e`'s
   published count — a shortfall is the terminal orphaned-prefix/count
   mismatch of ADR-0009, now detected at the page boundary instead of only at
   end of stream;
2. Release-stores `released_epoch = e`                         `[E]`;
3. proceeds with ADR-0009 validation of the new epoch's descriptor against
   the freshly Acquire-loaded slot binding.

Clean or faulted end-of-stream releases the final epoch after the ADR-0009
terminal checks, which now aggregate: total committed count must equal the
sum of sealed published counts plus the final page's published count.

### Reclamation proof (why no epochs are needed)

The single reclamation edge is consumer → producer over `released_epoch`:

```text
last frame commit for epoch e, ring-tail Release [C]
    -> released_epoch Release-store [E]
    -> producer released_epoch Acquire [A]
    -> slot (e mod P) rebind and first cell write of epoch e+P
```

- A payload lease (`AdmittedEvent`) mutably borrows the consumer, so no lease
  can be alive when the consumer later executes `[E]` inside `try_next` — the
  borrow checker, not a runtime count, proves no reader holds bytes of a page
  being released. This is the property crossbeam-epoch would otherwise buy,
  and it holds only because the topology is exactly one consumer; any
  multi-reader future (query snapshots, secondary indexes) must not reuse
  this argument and gets its own ADR.
- The producer never rebinds a slot without Acquire-observing `[E]` for its
  previous occupant, so every cell write of epoch `e+P` happens-after every
  committed read of epoch `e`.
- **ABA/wrap safety:** at most `P` epochs are ever live, and the ring is
  FIFO, so a descriptor observable by the consumer references an epoch in
  `[released_epoch, active_epoch]`, a window of width `<= P`. The `u32`
  generation tag is unambiguous while `P < 2^32`, which the type-level
  `P: usize` bound enforces absurdly early; the epoch counter itself is `u64`
  and non-wrapping for any realistic process lifetime (`2^64` rotations).
  A descriptor whose generation fails slot equality is the ADR-0009 terminal
  identity mismatch — never a skip, never a fallback read.

### Prototype notes (disclosed deviations)

The `current` prototype (`RotatingAdmissionChannel<N, P>`) deviates from the
target in three bounded, disclosed ways:

1. **Rebind allocates.** Rebinding constructs a fresh page (one bounded
   allocation per rotation, zero per event) instead of reusing the slot
   allocation in place. In-place reuse — which requires a mutable-generation
   page state with its own ordering proof — is required before any `shadow`
   wiring and stays inside this ADR's design envelope.
2. **Reader handoff ring.** The successor epoch's reader travels
   producer→consumer over a second bounded SPSC ring of capacity `P`. Its
   publication Release-store precedes the data ring's `[R]` for the epoch's
   first descriptor, so a consumer observing that descriptor observes the
   handoff; an absent handoff at a seam is terminal, never transient. The
   quota check `[A]` still governs reclamation — the handoff ring observing
   `Full` despite quota is a terminal invariant violation.
3. **`P` is a power of two** (the handoff ring shares the SPSC capacity
   rule) and the construction rejects `P < 2` and a nonzero
   `arena_generation` (epochs own the tag, starting at zero).

### Terminal-state extension

The composite terminal word and its `OPEN/CLEAN/FAULTED` values are unchanged.
`finish` seals the **active** page before storing `CLEAN` and closing the
ring. Clean end-of-stream now additionally requires every sealed epoch to have
been fully committed at its boundary (checked incrementally by the release
protocol) — so the aggregate clean condition remains "total committed equals
total published", with page-boundary early detection as a strengthening, not
a replacement, of ADR-0009's end-of-stream checks.

## Public result semantics

`AdmittedSequence` gains nothing: it already carries page identity, generation,
and wrapping sequence. Success semantics are ADR-0009's verbatim — volatile
publication only; never consumption, durability, a receipt, or authorization.

New/changed typed errors:

| Error | Page mutation | Ring mutation | Retry meaning |
|---|---:|---:|---|
| `PageQuotaExhausted` (all `P` slots outstanding) | none | none | consumer lagging; bounded retry/spool per event class |
| `page full` / `descriptor full` | no longer surfaced when rotation succeeds; surfaced unchanged when the payload exceeds one empty page | none | correct input |

All other ADR-0009 error rows are unchanged.

## Memory and ownership layout

```text
RotatingAdmissionChannel<N, P>
    pool: [page slot 0][page slot 1]...[page slot P-1]   (preallocated)
    ring, terminal word                                   (as ADR-0009)
    released_epoch: cache-line-aligned AtomicU64          (consumer writes,
                                                           producer reads)

producer: [active writer][active_epoch][pool handles][ring producer][terminal]
consumer: [ring consumer][current_epoch][per-epoch committed][pool handles]
```

`released_epoch` lives on its own cache line: it is written once per page
lifetime, not per event, so rotation metadata adds no steady-state false
sharing to the `[P]`/`[R]`/`[C]` hot lines. Slot rebinding reuses the page
allocation in place; the pool never grows, shrinks, or reallocates.

## Failure, overload, and security behavior

- `PageQuotaExhausted` is backpressure, not data loss: nothing is admitted,
  nothing is dropped, and the caller's event-class policy decides. The
  critical/WAL lane semantics remain future work — this channel still cannot
  carry protected evidence.
- A slow or stalled consumer bounds producer memory at exactly `P` pages plus
  the ring; there is no unbounded queue anywhere in the composite
  (architecture law §2.7).
- Generation mismatch, epoch-boundary count shortfall, sequence discontinuity,
  CRC failure, and corrupt terminal state all remain terminal, fail-closed
  lane errors — rotation adds detection points, never recovery-by-skipping.
- Descriptors remain non-capabilities; slot addressing via
  `generation mod P` selects memory already owned by this channel's bound
  pool and never a registry, tenant, or foreign allocation. Authenticated
  registry lookup remains explicitly out of scope and future work.

## Progress and performance hypothesis

Steady-state admission and consumption are byte-for-byte the ADR-0009 paths;
rotation adds one Acquire load on the page-full branch only. The hypothesis is
that amortized cost per event is unchanged and rotation cost is `O(1)`
bounded, paid once per page. No measurement accompanies this ADR; the fabric
remains `target` with no performance claim, and qualification requirements are
unchanged from ADR-0009.

## Alternatives considered

- **Allocate a fresh page per rotation, drop the old one** — rejected:
  per-page allocation/free in the hot path, unbounded live pages under a slow
  consumer, and no reuse story; violates the bounded-everything law.
- **crossbeam-epoch reclamation now** — rejected: the SPSC borrow-checker
  argument above makes epochs redundant for this topology; epochs enter with
  multi-reader query snapshots (LLD §epoch retirement) under their own ADR.
- **Per-slot busy/free atomic flags** — rejected: a single released-epoch
  counter is sufficient under FIFO in-order consumption and keeps one
  reclamation edge to prove instead of `P`.
- **Producer blocks/spins when the pool is exhausted** — rejected: hot crates
  admit no unbounded waits; typed backpressure lets the declared event class
  decide.
- **Encode slot index in `arena_id`** — rejected: `arena_id` identifies the
  lane/arena binding and participates in identity checks across the channel;
  overloading it conflates lane identity with position. The epoch already
  determines the slot.
- **Skip the page-boundary count check and rely on end-of-stream totals** —
  rejected: boundary checking converts a silent mid-stream orphan into an
  immediate terminal error while the evidence is fresh.

## Verification (required before the prototype can merge)

The implementing PR must provide, mirroring ADR-0009's evidence classes:

- rotation at byte exhaustion and at descriptor exhaustion; sequence
  continuity across the seam; admission token generations advancing;
- `PageQuotaExhausted` with zero page/ring mutation, then successful admission
  after the consumer crosses the boundary;
- generation-tagged reuse: slot rebinding after release, stale-descriptor
  injection failing identity terminally, wrap of the `u32` tag under a small
  `P` fixture;
- epoch-boundary committed-count shortfall detected terminally at the seam;
- caught-unwind fault injection at: before quota check, after seal `[S]`
  before rebind, after rebind before re-validation, plus all ADR-0009 points;
- differential oracle (safe sealed pages + `VecDeque`) across many rotations
  with variable-length payloads;
- Loom models for the release/rebind race (`[C]→[E]→[A]→rebind`), quota
  refusal versus in-flight release, and faulted closure mid-rotation;
- full Miri; ASan/TSan lanes extended to the rotation suites; zero
  steady-state allocations including across a rotation.

## Migration and rollback

While Proposed, the implementation is `current` only as isolated, unwired
prototype code (`lib/event/src/rotating.rs`) beside the single-page
composite, which remains the reviewed baseline and differential reference.
It receives no production or `shadow` traffic, cannot carry protected
evidence, and has no performance claim. Rollback deletes the rotating module
and this ADR's index row;
ADR-0006..0009 artifacts are untouched. Production wiring still additionally
requires WAL durability/replay, authenticated registry lookup, NUMA-owner
reclamation policy, priority lanes, shadow equality, qualification, and
release-artifact rollback — rotation removes exactly one blocker from that
list, not several.

## Revisit when

Revisit before adding WAL/durability classes, an authenticated page registry,
NUMA placement or cross-node pools, priority lanes, crossbeam-epoch or any
second reader, or any multi-producer/multi-consumer topology — each invalidates
at least one proof above (most immediately the borrow-checker reclamation
argument, which is single-consumer-only).

## References

- [Mandatory architecture law](../architecture.md)
- [ADR-0007: sealed generation-tagged slab pages](0007-sealed-generation-tagged-slab-pages.md)
- [ADR-0008: append-only published-prefix slab pages](0008-append-only-published-prefix-slab-pages.md)
- [ADR-0009: failure-atomic single-page slab/ring admission](0009-failure-atomic-slab-ring-admission.md)
- [Target LLD: epoch retirement and reclamation](../LLD.md)
- [Migration matrix](../../MIGRATION_MATRIX.md#10-gap-analysis-against-target)
- [Contribution and unsafe-code standard](../../CONTRIBUTING.md#lock-free-structures)
