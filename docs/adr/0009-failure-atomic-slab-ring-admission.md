# ADR-0009: Failure-atomic single-page slab/ring admission

**Status:** Proposed
**Date:** 2026-07-13
**Issue/PR:** pending

## Context

ADR-0006 provides a bounded SPSC descriptor ring and ADR-0008 provides an
append-only page whose immutable prefix is published after each complete
payload. Calling `PublishedSlabWriter::try_append` and then
`Producer::try_push` does not form one admission operation. A full ring or an
already-disconnected consumer is discovered only after the page has consumed
bytes, descriptor capacity, and sequence space. An interruption between the
page Release store and the ring Release store leaves a complete but
undelivered page descriptor.

The reverse order is also incomplete. A producer cannot publish a placeholder
ring entry before the payload exists because the consumer could observe an
uninitialized or non-canonical descriptor. A general two-object transaction,
CAS loop, per-slot state machine, or pending overflow queue would add shared
coordination that the single-producer topology does not require.

Consumption has a symmetric boundary. The current `try_pop` moves the
descriptor and Release-advances the ring tail immediately. If page identity,
canonical membership, bounds, or CRC verification then fails, the producer may
reuse the slot even though the consumer never accepted a valid event. That is
memory-safe for an immutable page but is the wrong acknowledgement contract for
a security-event lane.

This decision covers one preallocated page paired with one preallocated ring.
It remains volatile, process-local, unwired, and non-authoritative. It does not
provide WAL durability, page rotation, registry authentication, page reuse,
epoch reclamation, or a protected-evidence acknowledgement.

## Decision

Add a `VolatileAdmissionChannel<N>` in `aegis-event`. Construction validates
one `SlabPageConfig`, initializes the ring at the same `first_sequence`, and
owns both setup handles plus a cache-line-aligned terminal-state word. Consuming
`split` returns exactly one non-cloneable `AdmissionProducer<N>` and one
non-cloneable `AdmissionConsumer<N>`. Raw page and ring endpoints do not escape
this composite.

The ring gains two producer/consumer-local capabilities:

1. `Producer::try_reserve` returns a unique vacant-slot permit after checking
   consumer closure and capacity. It does not write a slot or advance the
   published head. Dropping the permit is a no-op.
2. `Consumer::try_claim` returns a read claim for a `Copy` value after Acquire
   observing the published head. It does not move the slot value or advance the
   consumed tail. Dropping the claim is a no-op. `commit` moves the value once
   and Release-advances the tail.

Both capabilities exclusively borrow their endpoint, are non-cloneable,
`!Send`, and `!Sync`. They contain no allocation, wait, retry, callback, lock,
or async operation. Their commit operations are infallible after issuance and
use a slot reference staged before any composite page mutation or validation
lease is returned.

The producer admission algorithm is:

```text
validate payload length and current page capacity without CRC or mutation
require page next_sequence == ring next_sequence
reserve one vacant ring slot without publishing it
mark producer InFlight
compute CRC32C and append the page payload/canonical descriptor
Release-store the page prefix                                  [P]
write the descriptor into the reserved ring slot
Release-store the ring published head                         [R]
mark producer Open
return a volatile admission token
```

`[R]` is the composite admission linearization point. The page publication
`[P]` is necessarily earlier because a consumer must never receive a
descriptor before its complete immutable payload is page-visible. The two
stores update distinct ownership domains and cannot honestly be described as
one crash-atomic instruction.

The consumer algorithm is:

```text
Acquire-observe and claim the next ring descriptor without advancing tail
require the exact expected wrapping descriptor sequence
Acquire-load and validate the page prefix
require canonical descriptor equality, checked bounds, and CRC32C
return a must-use borrowed frame lease

frame lease commit:
    move the ring descriptor exactly once
    Release-store the consumed tail                           [C]
    advance consumer-local expected sequence and count
```

`[C]` is the capacity-reclamation and consumer-acknowledgement linearization
point. Dropping an uncommitted frame lease leaves the ring slot claimed but
unconsumed; a later call may validate the same event again. The lease is
non-cloneable, `!Send`, and `!Sync` and MUST NOT cross I/O, `.await`, a callback,
or an uncontrolled duration.

## Public result semantics

Successful producer admission returns an `AdmittedSequence` containing only
the page identity/generation and wrapping sequence. It is not named or treated
as a receipt. Success means:

- the complete payload and canonical descriptor are immutable in the bound
  page;
- the descriptor is published in the volatile SPSC ring;
- a correctly operating bound consumer can Acquire-observe it.

Success does not mean consumed, WAL-appended, durable, replicated, indexed, or
authorized. An upstream source retains its bounded replay/spool record until a
separate downstream durability acknowledgement unless the declared event class
is explicitly best effort.

Normal typed errors are transactional:

| Error | Page mutation | Ring logical mutation | Retry meaning |
|---|---:|---:|---|
| invalid, empty, oversized, page full, descriptor full | none | none | correct input or rotate in a future layer |
| ring full | none; CRC and payload copy do not run | none | bounded retry/spool according to class |
| consumer disconnected before reservation | none | none | lane unavailable |
| producer poisoned or page/ring sequence divergence | none after detection | none after detection | terminal; rebuild lane |

A consumer closing after reservation cannot revoke the permit. The producer
still publishes at most that already-reserved descriptor and may return
volatile success. This is the unavoidable SPSC shutdown race already allowed
by ADR-0006; it is another reason admission is not a durability
acknowledgement.

## Explicit closure and terminal state

The composite terminal word is 64-byte aligned and has three valid values:

```text
OPEN = 0
CLEAN = 1
FAULTED = 2
```

Only the producer writes it. `AdmissionProducer::finish(self)` performs, in
order:

1. Release-close the page writer;
2. Release-store `CLEAN` to the terminal word;
3. Release-close the ring producer.

Ordinary producer drop, a caught unwind, a poisoned state, or a failed finish
performs the same ordered closure with `FAULTED`. Page closure therefore
happens-before any consumer that Acquire-observes ring disconnection. Repeated
close operations from field destruction are idempotent.

After the ring is drained and disconnected, the consumer Acquire-loads one
validated page status and the terminal word. Clean end-of-stream requires all
of the following:

- page writer is closed;
- terminal state is `CLEAN`;
- validated page published count equals committed frame count;
- every committed descriptor followed the exact wrapping sequence.

`FAULTED` with a larger page count reports an orphaned published prefix.
`FAULTED` with equal counts reports a faulted producer. An open/unknown terminal
state, a page that is not closed, a count mismatch in either direction, a
sequence gap/duplicate/reorder, canonical mismatch, range error, or CRC failure
is terminal data loss. The consumer closes its ring endpoint and never skips to
the next descriptor.

## Ordering proof

For one admitted descriptor, the relevant happens-before chain is:

```text
payload bytes and canonical page descriptor initialized
    -> page publication Release [P]
    -> reserved ring slot initialized
    -> ring-head Release [R]
    -> consumer ring-head Acquire
    -> descriptor copy from claimed initialized slot
    -> page-state Acquire
    -> canonical/range/CRC validation
    -> ring-tail Release [C]
    -> producer ring-tail Acquire before slot reuse
```

Program order plus the Release/Acquire synchronization means a consumer that
observes `[R]` cannot observe a page state older than the descriptor's complete
publication when it subsequently Acquire-loads that page. A later page prefix
may be visible, but committed cells never change. Withholding `[C]` prevents the
producer from reusing the claimed ring slot while validation or a frame lease
is outstanding.

The ring permit needs no shared reserved bit. There is exactly one producer,
the permit holds its exclusive mutable borrow, and the consumer can only
increase available capacity. Cached remote cursors may cause a conservative
full result but can never over-admit. The ring/page capacity is below `2^63`, so
wrapping cursor distance remains unambiguous. One page contains at most `2^16`
descriptors, making page-sequence distance unambiguous across `u64::MAX -> 0`.

## Panic, cancellation, and partial initialization

The composite producer uses local `Open`, `InFlight`, `Poisoned`, and
`Finished` states. The public admission boundary catches an unwind only long
enough to close the page, Release-store `FAULTED`, close the ring, and resume
the same panic; it never converts a panic into a normal result. A caller that
catches the resumed unwind therefore retains a terminal producer rather than
an atomically open poisoned lane. The producer enters `InFlight` only after all
typed validation and ring reservation succeed. No allocation, lookup,
indexing, formatting, callback, branch returning an error, or peer-state
recheck occurs after `[P]` and before `[R]` in production code. Test-only fault
hooks at the phase boundaries are compiled out of non-test builds.

- Before the first page cell write, an unwind cancels the unused permit.
- During page mutation before `[P]`, ADR-0008 poisoning leaves an unreachable
  suffix and forbids writer reuse; the ring permit remains unpublished.
- After `[P]` and before `[R]`, rollback is impossible. The page prefix remains
  immutable, the producer remains poisoned, ordered faulted closure exposes the
  count mismatch, and the consumer reports an orphan rather than guessing or
  continuing.
- After `[R]`, the descriptor remains drainable exactly once. Faulted closure
  still prevents the lane from being reported as a clean stream.

Process abort loses this volatile channel and requires no in-process rollback.
Process-crash recovery and durable replay belong to the future WAL/page-rotation
protocol. Protected evidence remains prohibited from this channel.

## Memory and ownership layout

```text
setup: VolatileAdmissionChannel<N>
    page Arc ------------------------------+
    ring Arc -------------------------+    |
    terminal Arc ----------------+    |    |
                                |    |    |
split                           v    v    v
producer: [slab writer][ring producer][terminal][local state]
consumer: [ring consumer][slab reader][terminal][expected/count/state]

producer hot path:
    page publication cache line [P]
    ring published-head cache line [R]

consumer hot path:
    ring consumed-tail cache line [C]

terminal cache line:
    written only during clean/faulted shutdown
```

The producer closes the page before the terminal word and ring. The consumer
closes the ring endpoint before releasing the page reader. The terminal word is
not colocated with either hot cursor, so shutdown metadata does not introduce
steady-state false sharing. All allocations and `Arc` clones happen during
construction/split; no per-event reference count operation is permitted.

The composite module is safe Rust. The permit and claim extend the existing
reviewed unsafe ring boundary. Their staged slot references derive from the
fixed ring allocation after checked masking/index validation. A permit writes
only the producer-owned free slot. A claim copies only an initialized,
Acquire-published `Copy` value and commits by moving that slot once. An
uncommitted claim leaves the initialized slot untouched. Existing final-drop
logic still destroys every published, unconsumed value exactly once.

## Copy and allocation ledger

| Boundary | Payload copies | Descriptor movement | Allocation/refcount |
|---|---:|---:|---|
| channel construction/split | zero | zero | bounded page/ring storage and setup-only `Arc` clones |
| validation + ring reservation | zero | none | zero |
| caller slice -> page suffix | exactly one bounded copy | canonical descriptor initialized once | zero |
| page -> ring | zero | one 32-byte slot write | zero |
| ring claim + page validation | zero | one 32-byte validation copy; slot remains owned by ring | zero |
| frame commit | zero | original slot value moved once | zero |
| native payload lease | zero within page-to-consumer boundary | none | zero |
| Loom payload validation | one disclosed model-only copy | modeled claim/commit | test-only allocation |

CRC32C is `O(n)` corruption detection over payload length `n`; it is not
authentication. `arena_id` and generation detect stale/mismatched page routing
but are not tenant credentials or capabilities.

## Failure, overload, and security behavior

- Validation precedes reservation and prevents malformed input from being
  hidden behind saturation.
- Ring full executes bounded work, does not compute CRC32C, does not copy the
  payload, and does not consume page sequence or capacity.
- Page full and descriptor exhaustion occur before ring reservation; there is
  no pending descriptor queue.
- No automatic spin, sleep, allocation, page rotation, overflow node, or
  best-effort conversion exists.
- Raw descriptors are accepted only from the channel's bound ring. They are not
  capabilities and never select a tenant or registry entry.
- The page belongs to one already-authenticated producer/consumer edge. Future
  registry lookup must bind trusted tenant, shard, arena ID, and generation
  before descriptor-cell access.
- CRC mismatch, identity mismatch, invalid metadata, sequence discontinuity,
  corrupt terminal state, or count mismatch terminates the lane without
  exposing bytes or acknowledging the ring slot.
- Admission cannot allow an action, consume an approval, satisfy receipt
  durability, or carry raw credentials. Cedar and protected control semantics
  are unchanged.

## Progress and performance hypothesis

Validation and ring reservation are wait-free bounded operations. Successful
admission performs bounded `O(n)` CRC/copy work followed by fixed slot and
atomic operations. Claim, frame validation, and commit perform bounded `O(n)`
CRC work and fixed atomics. Neither side waits for the peer; an empty/full result
is immediate.

The hypothesis is that one local capacity check before the payload copy removes
the current wasted page work at saturation while retaining one payload copy and
descriptor-only transfer. This ADR provides no latency, cycles, cache-miss,
allocation, or throughput measurement and does not make the event fabric
`shadow` or `qualified`.

Qualification must report p50/p95/p99/p99.9, events/s, bytes/s, CRC/copy cost,
full-rejection cost, allocations/event, copied bytes/event, cache-line
transfers, cache/branch misses, producer stalls, errors, saturation, and exact
loss/duplicate/reorder checks on a declared hardware/NUMA profile.

## Alternatives considered

- **Append then call `try_push`** — rejected because full/disconnected errors
  occur after page mutation and invite duplicate retries.
- **Publish a ring placeholder first** — rejected because the consumer could
  observe a descriptor before canonical bytes exist.
- **Keep one pending descriptor in the producer** — rejected because it adds a
  second queue, consumes page capacity on ring full, blocks later admissions,
  and complicates drop/retry semantics.
- **Per-slot reserved atomics or a two-word CAS** — rejected because the sole
  producer already provides exclusive reservation and the page/ring words are
  on distinct allocations.
- **Advance ring tail before page validation** — rejected because it
  acknowledges capacity before the consumer accepts a valid event.
- **Copy the payload out before tail advance** — rejected because it adds a
  second payload copy and evades the page-lifetime proof.
- **Treat ordinary producer drop as clean** — rejected because an unwind or
  forgotten shutdown would be indistinguishable from a complete stream.
- **Add WAL or epochs in this ADR** — rejected because crash durability, page
  rotation, authenticated lookup, reuse, and reclamation have independent
  state machines and recovery proofs.

## Verification

Required evidence includes:

- ring permit reserve/cancel/commit, saturation, disconnect, reuse, wrap,
  closure race, and exactly-once unread destruction;
- ring claim/drop/reclaim, validation-before-tail, slot reuse only after commit,
  wrap, and closure drain;
- invalid/page-full/descriptor-full/ring-full/disconnected admission with no
  page/ring logical mutation;
- exact success, sequence parity, clean finish/drain/end, faulted drop, orphan
  prefix detection, gap/mismatch/corruption termination, and retry of a dropped
  frame lease;
- deterministic short-trace differential tests against a safe
  `SlabPageBuilder + VecDeque` oracle;
- fault injection before page mutation, during the ADR-0008 poisoned suffix,
  after `[P]`, after ring-slot initialization, and after `[R]`;
- Loom models using the shipping permit/claim algorithms for visibility,
  cancellation, saturation/retry, close races, clean/faulted order, and wrap;
- full native Miri including held page borrows and claim/permit drop order;
- local and CI ASan/TSan, plus real UBSan when the Rust/toolchain boundary
  supports it; Miri is not relabeled as UBSan;
- long tiny-ring native stress proving no loss, duplicate, reorder, payload
  mismatch, or clean-end count mismatch;
- zero steady-state allocations for admission, validation lease, and commit;
  full rejection must execute no payload copy.

```bash
cargo test -p aegis-event
cargo test -p aegis-event --all-features
cargo test -p aegis-event --features loom loom_admission
cargo +nightly miri test -p aegis-event
cargo clippy -p aegis-event --all-targets --all-features -- -D warnings
cargo bench -p aegis-event --bench admission --no-run
```

The `current` prototype includes retained-producer caught-unwind tests at the
pre-`[P]`, post-`[P]`, post-ring-slot-write, and post-`[R]` boundaries;
gap/duplicate/reorder, identity, range, CRC, terminal-state, count-mismatch,
and post-`[C]` fail-closed fixtures; and a Loom validation-failure versus
reserved-publication race. These local sources do not replace formal ADR
acceptance, hosted sanitizer artifacts, or the remaining UBSan gate.

The current Rust nightly does not expose `-Zsanitizer=undefined`. This remains
an unmet `CONTRIBUTING.md` acceptance gate; Miri is complementary provenance
and undefined-behavior evidence, not UBSan equivalence.

## Migration and rollback

While this ADR is Proposed, the implementation is `current` only as isolated,
unwired prototype code. It receives no production or `shadow` traffic, cannot
carry protected evidence, and has no durable state. Rollback removes the
composite module, permit/claim APIs, and ADR references while retaining the
independently tested ADR-0006 ring, ADR-0007 safe page, and ADR-0008 published
page.

Future integration remains behind the per-tenant `event_write` generation and
the current SQL/Tokio path. Production wiring additionally requires green
unsafe/sanitizer review artifacts, authenticated page registry lookup, bounded
page rotation/outstanding pages, WAL replay and durability classes, generation
reuse with epochs, NUMA-owner reclamation, priority lanes, shadow equality,
qualification, and release-artifact rollback.

## Revisit when

Revisit before adding page rotation, a page registry, generation reuse,
crossbeam-epoch, a NUMA pool, a critical/WAL lane, production reactor wiring,
or protected evidence. Any change that permits multiple producers or consumers
requires a new algorithm and ADR; this SPSC permit/claim proof does not extend
to MPSC or MPMC.

## References

- [Mandatory architecture law](../architecture.md)
- [Target HLD: shared-memory SPSC event bus](../../ARCHITECTURE.md#5-shared-memory-spsc-event-bus)
- [Target LLD: Disruptor-style SPSC ring](../LLD.md#5-disruptor-style-spsc-ring)
- [ADR-0006: cache-padded SPSC event fabric](0006-cache-padded-spsc-event-fabric.md)
- [ADR-0008: append-only published-prefix slab pages](0008-append-only-published-prefix-slab-pages.md)
- [Migration matrix](../../MIGRATION_MATRIX.md#10-gap-analysis-against-target)
- [Contribution and unsafe-code standard](../../CONTRIBUTING.md#lock-free-structures)
