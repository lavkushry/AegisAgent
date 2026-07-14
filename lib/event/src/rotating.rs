//! Bounded page rotation over the failure-atomic admission composite.
//!
//! Current, unwired, volatile prototype under Proposed ADR-0010. One SPSC
//! descriptor ring spans a monotonically increasing sequence across a bounded
//! series of published-prefix pages; at most `P` page epochs are ever live.
//! It carries neither production telemetry nor protected evidence and
//! provides no durability, registry, NUMA, priority-lane, or qualification
//! claim.
//!
//! Construction preallocates a fixed pool of `P` pages. Rotation rebinds a
//! freed slot in place (exclusive `PublishedSlabPage::rebind`) — zero
//! allocation after `new`, zero per event. Shadow wiring still requires
//! formal ADR acceptance and the other ADR-0010 blockers.
//!
//! The new epoch's reader travels producer→consumer over a second bounded
//! SPSC ring. Its publication Release-store happens before the data ring's
//! `[R]` Release for the epoch's first descriptor, so a consumer that
//! Acquire-observes that descriptor also observes the handoff slot as
//! occupied — an absent reader at an epoch boundary is therefore a terminal
//! invariant violation, never a transient state.

use std::{cell::Cell, error::Error, fmt, marker::PhantomData};

#[cfg(feature = "loom")]
use loom::sync::{
    atomic::{AtomicU64, AtomicU8, Ordering},
    Arc,
};
#[cfg(not(feature = "loom"))]
use std::sync::{
    atomic::{AtomicU64, AtomicU8, Ordering},
    Arc,
};

use crate::{
    ring::{validate_capacity, OccupiedSlot, RingInvariantError, TryClaimError, TryReserveError},
    slab::validate_config,
    Consumer, Producer, PublishedPayload, PublishedSlabPage, PublishedSlabReadError,
    PublishedSlabReader, PublishedSlabWriter, RingConfigError, SlabAppendError, SlabConfigError,
    SlabPageConfig, SlabRebindError, SpscRing, TelemetryDescriptor, TryPopError,
};

const TERMINAL_OPEN: u8 = 0;
const TERMINAL_CLEAN: u8 = 1;
const TERMINAL_FAULTED: u8 = 2;

#[repr(align(64))]
struct PaddedTerminal(AtomicU8);

/// Count of fully-committed-and-released page epochs. Consumer-written once
/// per page lifetime, producer-read on the page-full branch only — never on
/// the per-event hot path, and never colocated with a hot cursor line.
#[repr(align(64))]
struct PaddedReleasedEpochs(AtomicU64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProducerState {
    Open,
    InFlight,
    Finished,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConsumerState {
    Open,
    Faulted,
    CleanEnd,
}

/// Setup handle binding one descriptor ring to a bounded series of page
/// epochs (`P` maximum live pages).
pub struct RotatingAdmissionChannel<const N: usize, const P: usize> {
    /// Fixed pool of page slots; slot `e mod P` serves epoch `e` after rebind.
    pool: [PublishedSlabPage; P],
    template: SlabPageConfig,
    ring: SpscRing<TelemetryDescriptor, N>,
    handoff: SpscRing<PublishedSlabReader, P>,
    released: Arc<PaddedReleasedEpochs>,
    terminal: Arc<PaddedTerminal>,
}

impl<const N: usize, const P: usize> RotatingAdmissionChannel<N, P> {
    /// `config.arena_generation` must be zero: page epochs own the
    /// generation tag (`generation = epoch as u32`) and epoch numbering
    /// starts at zero. `P` must be a power of two (the handoff ring
    /// shares the SPSC ring's capacity rule) and at least 2.
    pub fn new(config: SlabPageConfig) -> Result<Self, RotatingConfigError> {
        validate_capacity::<N>().map_err(RotatingConfigError::Ring)?;
        validate_capacity::<P>().map_err(RotatingConfigError::Handoff)?;
        if P < 2 {
            return Err(RotatingConfigError::PoolTooSmall { pool: P });
        }
        if config.arena_generation != 0 {
            return Err(RotatingConfigError::GenerationNotZero {
                arena_generation: config.arena_generation,
            });
        }
        validate_config(config).map_err(RotatingConfigError::Slab)?;

        let pool = build_page_pool::<P>(config)?;
        let ring = SpscRing::new_with_sequence(config.first_sequence)
            .map_err(RotatingConfigError::Ring)?;
        let handoff = SpscRing::new().map_err(RotatingConfigError::Handoff)?;

        Ok(Self {
            pool,
            template: config,
            ring,
            handoff,
            released: Arc::new(PaddedReleasedEpochs(AtomicU64::new(0))),
            terminal: Arc::new(PaddedTerminal(AtomicU8::new(TERMINAL_OPEN))),
        })
    }

    pub const fn ring_capacity(&self) -> usize {
        N
    }

    pub const fn pool_capacity(&self) -> usize {
        P
    }

    pub fn split(self) -> (RotatingProducer<N, P>, RotatingConsumer<N, P>) {
        let Self {
            pool,
            template: _,
            ring,
            handoff,
            released,
            terminal,
        } = self;
        // Epoch 0 opens pool slot 0 without rebind (constructed with gen 0).
        let (slab, reader) = pool[0].open();
        let (ring_producer, ring_consumer) = ring.split();
        let (handoff_producer, handoff_consumer) = handoff.split();
        let expected_sequence = slab.next_sequence();

        (
            RotatingProducer {
                slab,
                pool,
                ring: ring_producer,
                handoff: handoff_producer,
                released: Arc::clone(&released),
                terminal: Arc::clone(&terminal),
                epoch: 0,
                state: ProducerState::Open,
                #[cfg(all(test, not(feature = "loom")))]
                fault_after_seal: false,
                _not_sync: PhantomData,
            },
            RotatingConsumer {
                ring: ring_consumer,
                handoff: handoff_consumer,
                slab: reader,
                released,
                terminal,
                epoch: 0,
                expected_sequence,
                epoch_committed: 0,
                total_committed: 0,
                state: ConsumerState::Open,
                _not_sync: PhantomData,
            },
        )
    }
}

fn build_page_pool<const P: usize>(
    template: SlabPageConfig,
) -> Result<[PublishedSlabPage; P], RotatingConfigError> {
    // Preallocate every slot at construction; rotation only rebinds.
    let mut pages = Vec::with_capacity(P);
    for slot in 0..P {
        let mut cfg = template;
        // Placeholder generation until rebind (epoch 0 keeps gen 0).
        cfg.arena_generation = slot as u32;
        pages.push(PublishedSlabPage::new(cfg).map_err(RotatingConfigError::Slab)?);
    }
    pages
        .try_into()
        .map_err(|_| RotatingConfigError::PoolBuildLength)
}

impl<const N: usize, const P: usize> fmt::Debug for RotatingAdmissionChannel<N, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RotatingAdmissionChannel")
            .field("ring_capacity", &N)
            .field("pool_capacity", &P)
            .field("arena_id", &self.template.arena_id)
            .field("byte_capacity", &self.template.byte_capacity)
            .field("descriptor_capacity", &self.template.descriptor_capacity)
            .finish()
    }
}

/// Sole admission owner for the rotating page series.
///
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<aegis_event::RotatingProducer<1, 2>>();
/// ```
pub struct RotatingProducer<const N: usize, const P: usize> {
    // Declaration order preserves active-page-before-rings closure during
    // automatic field destruction, matching `close_faulted`.
    slab: PublishedSlabWriter,
    /// Fixed ADR-0010 page pool; slots rebind in place after release.
    pool: [PublishedSlabPage; P],
    ring: Producer<TelemetryDescriptor, N>,
    handoff: Producer<PublishedSlabReader, P>,
    released: Arc<PaddedReleasedEpochs>,
    terminal: Arc<PaddedTerminal>,
    epoch: u64,
    state: ProducerState,
    #[cfg(all(test, not(feature = "loom")))]
    fault_after_seal: bool,
    _not_sync: PhantomData<Cell<()>>,
}

impl<const N: usize, const P: usize> RotatingProducer<N, P> {
    /// Publishes one frame, rotating to a fresh page epoch when the active
    /// page's byte or descriptor capacity is exhausted.
    ///
    /// Success is only a volatile publication token — never consumption, WAL
    /// durability, a receipt, an authorization result, or permission to
    /// discard protected evidence or an upstream replay/spool record.
    pub fn try_admit(
        &mut self,
        payload: &[u8],
        schema_id: u32,
        flags: u16,
    ) -> Result<crate::AdmittedSequence, TryRotatingAdmitError> {
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.try_admit_inner(payload, schema_id, flags)
        }));
        match attempt {
            Ok(result) => result,
            Err(panic) => {
                // Same retained-producer contract as ADR-0009: close every
                // shared endpoint before an unwind can escape to a caller
                // that catches it.
                self.close_faulted();
                std::panic::resume_unwind(panic)
            }
        }
    }

    fn try_admit_inner(
        &mut self,
        payload: &[u8],
        schema_id: u32,
        flags: u16,
    ) -> Result<crate::AdmittedSequence, TryRotatingAdmitError> {
        if self.state != ProducerState::Open {
            self.close_faulted();
            return Err(TryRotatingAdmitError::ProducerPoisoned);
        }

        match self.slab.preflight_append(payload.len()) {
            Ok(()) => {}
            Err(
                SlabAppendError::PageFull { .. }
                | SlabAppendError::DescriptorCapacityExhausted { .. },
            ) => {
                self.rotate()?;
                // A payload that still does not fit an empty page is the
                // caller's typed input error, never a rotation loop.
                self.slab
                    .preflight_append(payload.len())
                    .map_err(TryRotatingAdmitError::Slab)?;
            }
            Err(error) => return Err(TryRotatingAdmitError::Slab(error)),
        }

        self.admit_on_active(payload, schema_id, flags)
    }

    /// ADR-0010 rotation: quota check, then seal `[S]`, then rebind. The
    /// quota check precedes the seal so a refused rotation leaves the active
    /// page open and usable for smaller payloads.
    fn rotate(&mut self) -> Result<(), TryRotatingAdmitError> {
        let next_epoch = self.epoch + 1;

        // Quota `[A]`: epoch e' may open only when its slot's previous
        // occupant (e' - P) was fully committed and released. Epochs below P
        // occupy never-used slots.
        if next_epoch >= P as u64 {
            let released = self.released.0.load(Ordering::Acquire);
            if released < next_epoch - P as u64 + 1 {
                return Err(TryRotatingAdmitError::PageQuotaExhausted {
                    live_epochs: (next_epoch - released) as usize,
                    pool: P,
                });
            }
        }

        let permit = match self.handoff.try_reserve() {
            Ok(permit) => permit,
            Err(TryReserveError::Disconnected) => {
                return Err(TryRotatingAdmitError::ConsumerDisconnected);
            }
            // The quota admitted at most P live epochs, so the P-capacity
            // handoff ring can never be full here; observing Full (or a
            // cursor invariant) breaks the reclamation proof and must fault
            // the lane rather than be retried.
            Err(TryReserveError::Full) => {
                self.close_faulted();
                return Err(TryRotatingAdmitError::HandoffInvariant);
            }
            Err(TryReserveError::Invariant(error)) => {
                self.close_faulted();
                return Err(TryRotatingAdmitError::RingInvariant(error));
            }
        };

        // Seal `[S]`. From here on any failure must fault the lane: the
        // active page is closed and cannot accept the caller's retry.
        self.slab.close();
        #[cfg(all(test, not(feature = "loom")))]
        if self.fault_after_seal {
            panic!("injected rotation fault after seal");
        }

        let first_sequence = self.slab.next_sequence();
        let slot = (next_epoch as usize) % P;
        // In-place reuse: exclusive rebind of the freed pool slot (ADR-0010).
        // Quota `[A]` proved the prior occupant of this slot was released, so
        // no writer/reader should hold the page Arc — outstanding endpoints
        // are a terminal invariant fault, not a retryable error.
        if let Err(error) = self.pool[slot].rebind(next_epoch as u32, first_sequence) {
            self.close_faulted();
            return Err(TryRotatingAdmitError::Rebind(error));
        }
        let (writer, reader) = self.pool[slot].open();
        // Reader publication Release happens-before the data ring's `[R]`
        // for this epoch's first descriptor (program order + both Release),
        // so a consumer observing that descriptor observes this handoff.
        permit.publish(reader);
        self.slab = writer;
        self.epoch = next_epoch;
        Ok(())
    }

    /// The unchanged ADR-0009 single-page admission sequence against the
    /// active page.
    fn admit_on_active(
        &mut self,
        payload: &[u8],
        schema_id: u32,
        flags: u16,
    ) -> Result<crate::AdmittedSequence, TryRotatingAdmitError> {
        let slab_sequence = self.slab.next_sequence();
        let ring_sequence = self.ring.next_sequence();
        if slab_sequence != ring_sequence {
            self.close_faulted();
            return Err(TryRotatingAdmitError::SequenceDiverged {
                slab: slab_sequence,
                ring: ring_sequence,
            });
        }

        let permit = match self.ring.try_reserve() {
            Ok(permit) => permit,
            Err(TryReserveError::Full) => return Err(TryRotatingAdmitError::RingFull),
            Err(TryReserveError::Disconnected) => {
                return Err(TryRotatingAdmitError::ConsumerDisconnected);
            }
            Err(TryReserveError::Invariant(error)) => {
                self.close_faulted();
                return Err(TryRotatingAdmitError::RingInvariant(error));
            }
        };
        if permit.sequence() != slab_sequence {
            let ring = permit.sequence();
            permit.cancel();
            self.close_faulted();
            return Err(TryRotatingAdmitError::SequenceDiverged {
                slab: slab_sequence,
                ring,
            });
        }

        self.state = ProducerState::InFlight;
        let descriptor = match self.slab.try_append(payload, schema_id, flags) {
            Ok(descriptor) => descriptor,
            Err(error) => {
                self.state = ProducerState::Open;
                return Err(TryRotatingAdmitError::Slab(error));
            }
        };
        permit.publish(descriptor);
        self.state = ProducerState::Open;
        Ok(crate::AdmittedSequence::from_descriptor(descriptor))
    }

    pub fn finish(mut self) -> Result<(), RotatingFinishError> {
        if self.state != ProducerState::Open {
            self.close_faulted();
            return Err(RotatingFinishError::ProducerPoisoned);
        }
        self.slab.close();
        self.terminal.0.store(TERMINAL_CLEAN, Ordering::Release);
        self.ring.close();
        self.handoff.close();
        self.state = ProducerState::Finished;
        Ok(())
    }

    fn close_faulted(&mut self) {
        if self.state == ProducerState::Finished {
            return;
        }
        self.slab.close();
        self.terminal.0.store(TERMINAL_FAULTED, Ordering::Release);
        self.ring.close();
        self.handoff.close();
        self.state = ProducerState::Finished;
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn arena_generation(&self) -> u32 {
        self.slab.arena_generation()
    }

    pub fn next_sequence(&self) -> u64 {
        self.slab.next_sequence()
    }

    pub fn published_count_active(&self) -> usize {
        self.slab.published_count()
    }

    #[cfg(all(test, not(feature = "loom")))]
    pub(crate) fn inject_fault_after_next_seal(&mut self) {
        self.fault_after_seal = true;
    }

    /// Test-only: publish a descriptor whose generation skips an epoch,
    /// exercising the consumer's terminal identity check for stale/foreign
    /// generations that are neither current nor current + 1.
    #[cfg(all(test, not(feature = "loom")))]
    pub(crate) fn inject_generation_skip(
        &mut self,
        payload: &[u8],
    ) -> Result<(), TryRotatingAdmitError> {
        self.slab
            .preflight_append(payload.len())
            .map_err(TryRotatingAdmitError::Slab)?;
        let permit = match self.ring.try_reserve() {
            Ok(permit) => permit,
            Err(error) => return Err(TryRotatingAdmitError::from(error)),
        };
        let mut descriptor = self
            .slab
            .try_append(payload, 1, 0)
            .map_err(TryRotatingAdmitError::Slab)?;
        descriptor.arena_generation = descriptor.arena_generation.wrapping_add(2);
        permit.publish(descriptor);
        Ok(())
    }

    /// Test-only: orphan one page entry, rotate, then admit a frame whose
    /// ring descriptor sequence is forged to stay contiguous — the only way
    /// a consumer can reach the epoch seam with the sealed page showing more
    /// published entries than the ring ever delivered. A correct producer
    /// cannot produce this state (the divergence guard poisons it first);
    /// the fixture models a corrupted peer.
    #[cfg(all(test, not(feature = "loom")))]
    pub(crate) fn inject_seam_shortfall(
        &mut self,
        orphaned: &[u8],
        next_epoch_payload: &[u8],
    ) -> Result<(), TryRotatingAdmitError> {
        self.inject_orphan(orphaned)?;
        let forged_sequence = self.ring.next_sequence();
        self.rotate()?;
        self.slab
            .preflight_append(next_epoch_payload.len())
            .map_err(TryRotatingAdmitError::Slab)?;
        let permit = match self.ring.try_reserve() {
            Ok(permit) => permit,
            Err(error) => return Err(TryRotatingAdmitError::from(error)),
        };
        let mut descriptor = self
            .slab
            .try_append(next_epoch_payload, 1, 0)
            .map_err(TryRotatingAdmitError::Slab)?;
        descriptor.sequence = forged_sequence;
        permit.publish(descriptor);
        Ok(())
    }

    /// Test-only: append to the page without publishing the ring descriptor,
    /// creating an orphaned published prefix on the active page.
    #[cfg(all(test, not(feature = "loom")))]
    pub(crate) fn inject_orphan(&mut self, payload: &[u8]) -> Result<(), TryRotatingAdmitError> {
        self.slab
            .preflight_append(payload.len())
            .map_err(TryRotatingAdmitError::Slab)?;
        let permit = match self.ring.try_reserve() {
            Ok(permit) => permit,
            Err(error) => return Err(TryRotatingAdmitError::from(error)),
        };
        let _descriptor = self
            .slab
            .try_append(payload, 1, 0)
            .map_err(TryRotatingAdmitError::Slab)?;
        permit.cancel();
        Ok(())
    }
}

impl<const N: usize, const P: usize> Drop for RotatingProducer<N, P> {
    fn drop(&mut self) {
        self.close_faulted();
    }
}

impl<const N: usize, const P: usize> fmt::Debug for RotatingProducer<N, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RotatingProducer")
            .field("ring_capacity", &N)
            .field("pool_capacity", &P)
            .field("epoch", &self.epoch)
            .field("next_sequence", &self.next_sequence())
            .field("state", &self.state)
            .finish()
    }
}

/// Sole validation/acknowledgement owner for the rotating page series.
///
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<aegis_event::RotatingConsumer<1, 2>>();
/// ```
pub struct RotatingConsumer<const N: usize, const P: usize> {
    ring: Consumer<TelemetryDescriptor, N>,
    handoff: Consumer<PublishedSlabReader, P>,
    slab: PublishedSlabReader,
    released: Arc<PaddedReleasedEpochs>,
    terminal: Arc<PaddedTerminal>,
    epoch: u64,
    expected_sequence: u64,
    epoch_committed: usize,
    total_committed: usize,
    state: ConsumerState,
    _not_sync: PhantomData<Cell<()>>,
}

impl<const N: usize, const P: usize> RotatingConsumer<N, P> {
    pub fn try_next(&mut self) -> Result<RotatingAdmittedEvent<'_, N>, TryRotatingConsumeError> {
        let Self {
            ring,
            handoff,
            slab,
            released,
            terminal,
            epoch,
            expected_sequence,
            epoch_committed,
            total_committed,
            state,
            _not_sync: _,
        } = self;

        match *state {
            ConsumerState::CleanEnd => return Err(TryRotatingConsumeError::CleanEnd),
            ConsumerState::Faulted => return Err(TryRotatingConsumeError::ConsumerPoisoned),
            ConsumerState::Open => {}
        }

        let claim = match ring.try_claim() {
            Ok(claim) => claim,
            Err(TryClaimError::Empty) => return Err(TryRotatingConsumeError::Empty),
            Err(TryClaimError::Disconnected) => {
                return Err(Self::classify_end(
                    slab,
                    terminal,
                    released,
                    *epoch,
                    *epoch_committed,
                    state,
                ));
            }
            Err(TryClaimError::Invariant(error)) => {
                *state = ConsumerState::Faulted;
                return Err(TryRotatingConsumeError::RingInvariant(error));
            }
        };

        let descriptor = claim.value();
        if descriptor.sequence != *expected_sequence {
            claim.close_consumer();
            let expected = *expected_sequence;
            *state = ConsumerState::Faulted;
            return Err(TryRotatingConsumeError::SequenceMismatch {
                expected,
                actual: descriptor.sequence,
            });
        }

        let current_generation = *epoch as u32;
        if descriptor.arena_generation == current_generation.wrapping_add(1) {
            // Epoch boundary `[E]`: prove the sealed page complete, release
            // it, and bind the successor before validating its first frame.
            if let Err(error) =
                Self::cross_epoch_boundary(slab, handoff, released, epoch, epoch_committed)
            {
                claim.close_consumer();
                *state = ConsumerState::Faulted;
                return Err(error);
            }
        } else if descriptor.arena_generation != current_generation {
            claim.close_consumer();
            *state = ConsumerState::Faulted;
            return Err(TryRotatingConsumeError::EpochIdentityMismatch {
                current: current_generation,
                actual: descriptor.arena_generation,
            });
        }

        let payload = match slab.resolve(&descriptor) {
            Ok(payload) => payload,
            Err(error) => {
                claim.close_consumer();
                *state = ConsumerState::Faulted;
                return Err(TryRotatingConsumeError::Page(error));
            }
        };

        Ok(RotatingAdmittedEvent {
            descriptor,
            payload,
            claim,
            expected_sequence,
            epoch_committed,
            total_committed,
        })
    }

    fn cross_epoch_boundary(
        slab: &mut PublishedSlabReader,
        handoff: &mut Consumer<PublishedSlabReader, P>,
        released: &Arc<PaddedReleasedEpochs>,
        epoch: &mut u64,
        epoch_committed: &mut usize,
    ) -> Result<(), TryRotatingConsumeError> {
        let status = slab.status().map_err(TryRotatingConsumeError::Page)?;
        if !status.writer_closed {
            return Err(TryRotatingConsumeError::ClosureOrderViolation);
        }
        if status.published_count != *epoch_committed {
            return Err(TryRotatingConsumeError::EpochBoundaryShortfall {
                epoch: *epoch,
                published: status.published_count,
                committed: *epoch_committed,
            });
        }

        let reader = match handoff.try_pop() {
            Ok(reader) => reader,
            // The handoff publication happens-before the first descriptor of
            // the new epoch (see module docs), so an empty/absent handoff
            // here is a broken invariant, not a transient race.
            Err(TryPopError::Empty | TryPopError::Disconnected) => {
                return Err(TryRotatingConsumeError::HandoffMissing);
            }
        };
        let next_generation = (*epoch as u32).wrapping_add(1);
        if reader.arena_generation() != next_generation {
            return Err(TryRotatingConsumeError::HandoffIdentityMismatch {
                expected: next_generation,
                actual: reader.arena_generation(),
            });
        }

        *slab = reader;
        *epoch += 1;
        *epoch_committed = 0;
        // Release edge `[E]`: the sealed page's slot may now be rebound; the
        // frame lease's mutable borrow of the consumer proves no payload
        // borrow of the released page can be alive here.
        released.0.store(*epoch, Ordering::Release);
        Ok(())
    }

    fn classify_end(
        slab: &PublishedSlabReader,
        terminal: &Arc<PaddedTerminal>,
        released: &Arc<PaddedReleasedEpochs>,
        epoch: u64,
        epoch_committed: usize,
        state: &mut ConsumerState,
    ) -> TryRotatingConsumeError {
        let status = match slab.status() {
            Ok(status) => status,
            Err(error) => {
                *state = ConsumerState::Faulted;
                return TryRotatingConsumeError::Page(error);
            }
        };
        let terminal = terminal.0.load(Ordering::Acquire);

        if !status.writer_closed {
            *state = ConsumerState::Faulted;
            return TryRotatingConsumeError::ClosureOrderViolation;
        }

        // Earlier epochs were proven complete at their boundaries, so the
        // aggregate clean condition reduces to the final page's counts.
        if status.published_count != epoch_committed {
            let error = if terminal == TERMINAL_FAULTED && status.published_count > epoch_committed
            {
                TryRotatingConsumeError::OrphanedPublishedPrefix {
                    epoch,
                    published: status.published_count,
                    committed: epoch_committed,
                }
            } else {
                TryRotatingConsumeError::CountMismatch {
                    epoch,
                    published: status.published_count,
                    committed: epoch_committed,
                }
            };
            *state = ConsumerState::Faulted;
            return error;
        }

        match terminal {
            TERMINAL_CLEAN => {
                *state = ConsumerState::CleanEnd;
                released.0.store(epoch + 1, Ordering::Release);
                TryRotatingConsumeError::CleanEnd
            }
            TERMINAL_FAULTED => {
                *state = ConsumerState::Faulted;
                TryRotatingConsumeError::ProducerFaulted {
                    published: status.published_count,
                    committed: epoch_committed,
                }
            }
            TERMINAL_OPEN => {
                *state = ConsumerState::Faulted;
                TryRotatingConsumeError::ClosureOrderViolation
            }
            raw => {
                *state = ConsumerState::Faulted;
                TryRotatingConsumeError::TerminalStateInvalid { raw }
            }
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn arena_generation(&self) -> u32 {
        self.slab.arena_generation()
    }

    pub fn total_committed(&self) -> usize {
        self.total_committed
    }

    pub fn expected_sequence(&self) -> u64 {
        self.expected_sequence
    }
}

impl<const N: usize, const P: usize> fmt::Debug for RotatingConsumer<N, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RotatingConsumer")
            .field("ring_capacity", &N)
            .field("pool_capacity", &P)
            .field("epoch", &self.epoch)
            .field("expected_sequence", &self.expected_sequence)
            .field("total_committed", &self.total_committed)
            .field("state", &self.state)
            .finish()
    }
}

/// Must-use validated frame; ring capacity stays claimed until commit.
///
/// ```compile_fail
/// fn require_send<T: Send>() {}
/// require_send::<aegis_event::RotatingAdmittedEvent<'static, 1>>();
/// ```
#[must_use = "commit the frame only after synchronous processing succeeds"]
pub struct RotatingAdmittedEvent<'consumer, const N: usize> {
    descriptor: TelemetryDescriptor,
    payload: PublishedPayload<'consumer>,
    claim: OccupiedSlot<'consumer, TelemetryDescriptor, N>,
    expected_sequence: &'consumer mut u64,
    epoch_committed: &'consumer mut usize,
    total_committed: &'consumer mut usize,
}

impl<const N: usize> RotatingAdmittedEvent<'_, N> {
    pub const fn descriptor(&self) -> &TelemetryDescriptor {
        &self.descriptor
    }

    pub fn payload(&self) -> &[u8] {
        self.payload.as_ref()
    }

    /// Reclaims this volatile ring slot after synchronous processing. Not a
    /// receipt, durability acknowledgement, or authorization result.
    pub fn commit(self) -> crate::AdmittedSequence {
        let Self {
            descriptor: _,
            payload: _,
            claim,
            expected_sequence,
            epoch_committed,
            total_committed,
        } = self;
        let descriptor = claim.commit();
        *expected_sequence = descriptor.sequence.wrapping_add(1);
        *epoch_committed += 1;
        *total_committed += 1;
        crate::AdmittedSequence::from_descriptor(descriptor)
    }
}

impl<const N: usize> fmt::Debug for RotatingAdmittedEvent<'_, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RotatingAdmittedEvent")
            .field("descriptor", &self.descriptor)
            .field("payload_len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotatingConfigError {
    Ring(RingConfigError),
    Handoff(RingConfigError),
    Slab(SlabConfigError),
    PoolTooSmall {
        pool: usize,
    },
    GenerationNotZero {
        arena_generation: u32,
    },
    /// Internal: fixed pool length did not match `P` after construction.
    PoolBuildLength,
}

impl fmt::Display for RotatingConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ring(error) => write!(f, "invalid rotating ring configuration: {error}"),
            Self::Handoff(error) => write!(f, "invalid handoff ring configuration: {error}"),
            Self::Slab(error) => write!(f, "invalid rotating page configuration: {error}"),
            Self::PoolTooSmall { pool } => {
                write!(f, "rotating pool must hold at least 2 pages, got {pool}")
            }
            Self::GenerationNotZero { arena_generation } => write!(
                f,
                "rotating channels own the generation tag; expected 0, got {arena_generation}"
            ),
            Self::PoolBuildLength => {
                write!(f, "rotating page pool construction length mismatch")
            }
        }
    }
}

impl Error for RotatingConfigError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TryRotatingAdmitError {
    RingFull,
    ConsumerDisconnected,
    Slab(SlabAppendError),
    SequenceDiverged {
        slab: u64,
        ring: u64,
    },
    RingInvariant(RingInvariantError),
    ProducerPoisoned,
    /// All `P` pool slots hold live epochs — typed backpressure, nothing
    /// mutated. Bounded retry/spool per the caller's declared event class.
    PageQuotaExhausted {
        live_epochs: usize,
        pool: usize,
    },
    /// Exclusive pool-slot rebind failed (outstanding endpoints).
    Rebind(SlabRebindError),
    HandoffInvariant,
}

impl From<TryReserveError> for TryRotatingAdmitError {
    fn from(error: TryReserveError) -> Self {
        match error {
            TryReserveError::Full => Self::RingFull,
            TryReserveError::Disconnected => Self::ConsumerDisconnected,
            TryReserveError::Invariant(error) => Self::RingInvariant(error),
        }
    }
}

impl fmt::Display for TryRotatingAdmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RingFull => write!(f, "volatile admission ring is full"),
            Self::ConsumerDisconnected => write!(f, "volatile admission consumer is disconnected"),
            Self::Slab(error) => write!(f, "volatile admission page rejected the frame: {error}"),
            Self::SequenceDiverged { slab, ring } => write!(
                f,
                "page/ring sequence diverged (page {slab}, ring {ring}); lane is terminal"
            ),
            Self::RingInvariant(error) => write!(f, "ring invariant violated: {error}"),
            Self::ProducerPoisoned => write!(f, "rotating producer is poisoned"),
            Self::PageQuotaExhausted { live_epochs, pool } => write!(
                f,
                "all {pool} page slots hold live epochs ({live_epochs}); consumer is lagging"
            ),
            Self::Rebind(error) => {
                write!(f, "rotation could not rebind freed pool slot: {error}")
            }
            Self::HandoffInvariant => {
                write!(
                    f,
                    "handoff ring full despite quota; reclamation invariant broken"
                )
            }
        }
    }
}

impl Error for TryRotatingAdmitError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotatingFinishError {
    ProducerPoisoned,
}

impl fmt::Display for RotatingFinishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProducerPoisoned => write!(f, "rotating producer is poisoned"),
        }
    }
}

impl Error for RotatingFinishError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TryRotatingConsumeError {
    Empty,
    CleanEnd,
    ConsumerPoisoned,
    RingInvariant(RingInvariantError),
    SequenceMismatch {
        expected: u64,
        actual: u64,
    },
    Page(PublishedSlabReadError),
    ClosureOrderViolation,
    EpochIdentityMismatch {
        current: u32,
        actual: u32,
    },
    EpochBoundaryShortfall {
        epoch: u64,
        published: usize,
        committed: usize,
    },
    HandoffMissing,
    HandoffIdentityMismatch {
        expected: u32,
        actual: u32,
    },
    OrphanedPublishedPrefix {
        epoch: u64,
        published: usize,
        committed: usize,
    },
    CountMismatch {
        epoch: u64,
        published: usize,
        committed: usize,
    },
    ProducerFaulted {
        published: usize,
        committed: usize,
    },
    TerminalStateInvalid {
        raw: u8,
    },
}

impl fmt::Display for TryRotatingConsumeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "no descriptor is currently published"),
            Self::CleanEnd => write!(f, "stream ended cleanly"),
            Self::ConsumerPoisoned => write!(f, "rotating consumer is poisoned"),
            Self::RingInvariant(error) => write!(f, "ring invariant violated: {error}"),
            Self::SequenceMismatch { expected, actual } => {
                write!(f, "descriptor sequence {actual} != expected {expected}")
            }
            Self::Page(error) => write!(f, "page validation failed: {error}"),
            Self::ClosureOrderViolation => {
                write!(f, "ring disconnected before the page writer closed")
            }
            Self::EpochIdentityMismatch { current, actual } => write!(
                f,
                "descriptor generation {actual} is neither current epoch {current} nor its successor"
            ),
            Self::EpochBoundaryShortfall {
                epoch,
                published,
                committed,
            } => write!(
                f,
                "epoch {epoch} sealed with {published} published but only {committed} committed"
            ),
            Self::HandoffMissing => {
                write!(f, "successor epoch descriptor arrived without a page handoff")
            }
            Self::HandoffIdentityMismatch { expected, actual } => write!(
                f,
                "handoff page generation {actual} != expected successor {expected}"
            ),
            Self::OrphanedPublishedPrefix {
                epoch,
                published,
                committed,
            } => write!(
                f,
                "epoch {epoch}: faulted producer left {published} published, {committed} committed"
            ),
            Self::CountMismatch {
                epoch,
                published,
                committed,
            } => write!(
                f,
                "epoch {epoch}: published {published} != committed {committed} at end of stream"
            ),
            Self::ProducerFaulted {
                published,
                committed,
            } => write!(
                f,
                "producer closed faulted after {published} published, {committed} committed"
            ),
            Self::TerminalStateInvalid { raw } => {
                write!(f, "terminal state word holds invalid value {raw}")
            }
        }
    }
}

impl Error for TryRotatingConsumeError {}

#[cfg(all(test, not(feature = "loom")))]
mod native_tests {
    use super::*;

    fn config() -> SlabPageConfig {
        SlabPageConfig {
            arena_id: 7,
            arena_generation: 0,
            byte_capacity: 1024,
            descriptor_capacity: 2,
            first_sequence: 3,
        }
    }

    fn drain_one<const N: usize, const P: usize>(
        consumer: &mut RotatingConsumer<N, P>,
        expected_payload: &[u8],
    ) -> crate::AdmittedSequence {
        let frame = consumer.try_next().expect("frame validates");
        assert_eq!(frame.payload(), expected_payload);
        frame.commit()
    }

    #[test]
    fn rejects_pool_smaller_than_two_and_nonzero_generation() {
        assert!(matches!(
            RotatingAdmissionChannel::<4, 1>::new(config()),
            Err(RotatingConfigError::PoolTooSmall { pool: 1 })
        ));
        let mut bad = config();
        bad.arena_generation = 9;
        assert!(matches!(
            RotatingAdmissionChannel::<4, 2>::new(bad),
            Err(RotatingConfigError::GenerationNotZero {
                arena_generation: 9
            })
        ));
    }

    #[test]
    fn rotation_at_descriptor_exhaustion_preserves_sequence_and_generation() {
        let channel = RotatingAdmissionChannel::<8, 4>::new(config()).expect("channel");
        let (mut producer, mut consumer) = channel.split();

        // descriptor_capacity = 2: the third admit must rotate to epoch 1.
        for (i, payload) in [b"a1", b"a2", b"b1", b"b2", b"c1"].iter().enumerate() {
            let token = producer
                .try_admit(*payload, 1, 0)
                .expect("admit across rotations");
            assert_eq!(token.sequence(), 3 + i as u64, "continuous sequence");
        }
        assert_eq!(producer.epoch(), 2);
        assert_eq!(producer.arena_generation(), 2);

        for (i, payload) in [b"a1", b"a2", b"b1", b"b2", b"c1"].iter().enumerate() {
            let token = drain_one(&mut consumer, *payload);
            assert_eq!(token.sequence(), 3 + i as u64);
        }
        assert_eq!(consumer.epoch(), 2);
        assert_eq!(consumer.total_committed(), 5);
    }

    #[test]
    fn rotation_at_byte_exhaustion_rotates_instead_of_failing() {
        let mut cfg = config();
        cfg.byte_capacity = 8;
        cfg.descriptor_capacity = 16;
        let channel = RotatingAdmissionChannel::<8, 2>::new(cfg).expect("channel");
        let (mut producer, mut consumer) = channel.split();

        producer.try_admit(&[1u8; 6], 1, 0).expect("fits epoch 0");
        producer
            .try_admit(&[2u8; 6], 1, 0)
            .expect("rotates to epoch 1");
        assert_eq!(producer.epoch(), 1);

        drain_one(&mut consumer, &[1u8; 6]);
        drain_one(&mut consumer, &[2u8; 6]);
        assert_eq!(consumer.epoch(), 1);
    }

    /// ADR-0010 in-place reuse: more rotations than pool capacity rebind
    /// released slots without constructing new pages.
    #[test]
    fn rotation_reuses_pool_slots_beyond_capacity() {
        let mut cfg = config();
        cfg.descriptor_capacity = 1;
        cfg.byte_capacity = 64;
        let channel = RotatingAdmissionChannel::<16, 2>::new(cfg).expect("channel");
        let (mut producer, mut consumer) = channel.split();

        // P=2, capacity 1: every admit after the first rotates. Produce 6
        // epochs so slots 0 and 1 are rebound multiple times (epochs 0..5).
        let mut seen = Vec::new();
        for i in 0u8..6 {
            let payload = [i];
            loop {
                match producer.try_admit(&payload, 1, 0) {
                    Ok(_) => break,
                    Err(TryRotatingAdmitError::PageQuotaExhausted { .. }) => {
                        let frame = consumer.try_next().expect("drain lagging consumer");
                        seen.push(frame.payload()[0]);
                        frame.commit();
                    }
                    Err(error) => panic!("unexpected admit error at {i}: {error}"),
                }
            }
        }
        producer.finish().expect("clean finish");
        loop {
            match consumer.try_next() {
                Ok(frame) => {
                    seen.push(frame.payload()[0]);
                    frame.commit();
                }
                Err(TryRotatingConsumeError::CleanEnd) => break,
                Err(TryRotatingConsumeError::Empty) => continue,
                Err(error) => panic!("unexpected end drain: {error}"),
            }
        }
        assert_eq!(seen, vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(consumer.total_committed(), 6);
    }

    #[test]
    fn page_rebind_rejects_outstanding_endpoints() {
        let page = PublishedSlabPage::new(config()).expect("page");
        let (_w, _r) = page.open();
        let mut page = page;
        let err = page.rebind(1, 99).expect_err("open endpoints block rebind");
        assert_eq!(err, crate::SlabRebindError::OutstandingEndpoints);
    }

    #[test]
    fn page_rebind_succeeds_after_endpoints_drop() {
        let mut page = PublishedSlabPage::new(config()).expect("page");
        {
            let (_w, _r) = page.open();
        }
        page.rebind(3, 42).expect("exclusive rebind");
        assert_eq!(page.arena_generation(), 3);
        let (w, _r) = page.open();
        assert_eq!(w.next_sequence(), 42);
        assert_eq!(w.arena_generation(), 3);
    }

    #[test]
    fn payload_larger_than_an_empty_page_is_a_typed_error_not_a_loop() {
        let mut cfg = config();
        cfg.byte_capacity = 8;
        let channel = RotatingAdmissionChannel::<8, 4>::new(cfg).expect("channel");
        let (mut producer, _consumer) = channel.split();

        producer.try_admit(&[1u8; 4], 1, 0).expect("fits");
        // 9 bytes can never fit an 8-byte page: one rotation happens (the
        // active page had bytes used), then the empty successor rejects it.
        let err = producer.try_admit(&[9u8; 9], 1, 0).expect_err("too large");
        assert!(matches!(err, TryRotatingAdmitError::Slab(_)));
        assert_eq!(producer.epoch(), 1);
    }

    #[test]
    fn quota_exhaustion_is_typed_backpressure_and_recovers_after_release() {
        // P = 2: epochs 0 and 1 may be live; opening epoch 2 requires the
        // consumer to have fully released epoch 0.
        let channel = RotatingAdmissionChannel::<8, 2>::new(config()).expect("channel");
        let (mut producer, mut consumer) = channel.split();

        for payload in [b"a1", b"a2", b"b1", b"b2"] {
            producer.try_admit(payload, 1, 0).expect("epochs 0 and 1");
        }
        let before_epoch = producer.epoch();
        let before_seq = producer.next_sequence();
        let err = producer.try_admit(b"c1", 1, 0).expect_err("pool exhausted");
        assert!(matches!(
            err,
            TryRotatingAdmitError::PageQuotaExhausted {
                live_epochs: 2,
                pool: 2
            }
        ));
        // Refused rotation mutated nothing.
        assert_eq!(producer.epoch(), before_epoch);
        assert_eq!(producer.next_sequence(), before_seq);

        // Consumer finishes epoch 0 (crossing the boundary releases it).
        drain_one(&mut consumer, b"a1");
        drain_one(&mut consumer, b"a2");
        drain_one(&mut consumer, b"b1");

        producer
            .try_admit(b"c1", 1, 0)
            .expect("rotation succeeds after release");
        assert_eq!(producer.epoch(), 2);

        drain_one(&mut consumer, b"b2");
        drain_one(&mut consumer, b"c1");
        assert_eq!(consumer.epoch(), 2);
    }

    #[test]
    fn clean_end_across_rotations_aggregates_per_epoch_counts() {
        let channel = RotatingAdmissionChannel::<8, 4>::new(config()).expect("channel");
        let (mut producer, mut consumer) = channel.split();
        for payload in [b"a1", b"a2", b"b1"] {
            producer.try_admit(payload, 1, 0).expect("admit");
        }
        producer.finish().expect("clean finish");

        drain_one(&mut consumer, b"a1");
        drain_one(&mut consumer, b"a2");
        drain_one(&mut consumer, b"b1");
        assert!(matches!(
            consumer.try_next(),
            Err(TryRotatingConsumeError::CleanEnd)
        ));
        assert_eq!(consumer.total_committed(), 3);
    }

    #[test]
    fn faulted_drop_reports_orphan_on_the_final_page() {
        let channel = RotatingAdmissionChannel::<8, 4>::new(config()).expect("channel");
        let (mut producer, mut consumer) = channel.split();
        producer.try_admit(b"a1", 1, 0).expect("admit");
        producer.try_admit(b"a2", 1, 0).expect("admit");
        producer.try_admit(b"b1", 1, 0).expect("rotates");
        producer.inject_orphan(b"b2").expect("orphan on epoch 1");
        drop(producer);

        drain_one(&mut consumer, b"a1");
        drain_one(&mut consumer, b"a2");
        drain_one(&mut consumer, b"b1");
        assert!(matches!(
            consumer.try_next(),
            Err(TryRotatingConsumeError::OrphanedPublishedPrefix {
                epoch: 1,
                published: 2,
                committed: 1,
            })
        ));
    }

    #[test]
    fn epoch_boundary_shortfall_is_terminal_at_the_seam() {
        let channel = RotatingAdmissionChannel::<8, 4>::new(config()).expect("channel");
        let (mut producer, mut consumer) = channel.split();
        producer.try_admit(b"a1", 1, 0).expect("admit");
        // Orphan fills epoch 0's second descriptor without a ring entry, so
        // the rotation seam shows published=2 vs committed=1; the forged
        // follow-up keeps the ring contiguous so the seam check is reached.
        producer
            .inject_seam_shortfall(b"a2", b"b1")
            .expect("seam fixture");

        drain_one(&mut consumer, b"a1");
        assert!(matches!(
            consumer.try_next(),
            Err(TryRotatingConsumeError::EpochBoundaryShortfall {
                epoch: 0,
                published: 2,
                committed: 1,
            })
        ));
        assert!(matches!(
            consumer.try_next(),
            Err(TryRotatingConsumeError::ConsumerPoisoned)
        ));
    }

    #[test]
    fn generation_skip_is_a_terminal_identity_error() {
        let channel = RotatingAdmissionChannel::<8, 4>::new(config()).expect("channel");
        let (mut producer, mut consumer) = channel.split();
        producer
            .inject_generation_skip(b"a1")
            .expect("skip fixture");

        assert!(matches!(
            consumer.try_next(),
            Err(TryRotatingConsumeError::EpochIdentityMismatch {
                current: 0,
                actual: 2,
            })
        ));
        assert_eq!(
            producer.try_admit(b"a2", 1, 0),
            Err(TryRotatingAdmitError::ConsumerDisconnected)
        );
    }

    #[test]
    fn caught_unwind_after_seal_leaves_a_retained_producer_terminal() {
        let channel = RotatingAdmissionChannel::<8, 4>::new(config()).expect("channel");
        let (mut producer, mut consumer) = channel.split();
        producer.try_admit(b"a1", 1, 0).expect("admit");
        producer.try_admit(b"a2", 1, 0).expect("admit");
        producer.inject_fault_after_next_seal();

        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = producer.try_admit(b"b1", 1, 0);
        }));
        assert!(unwind.is_err());
        assert_eq!(
            producer.try_admit(b"b2", 1, 0),
            Err(TryRotatingAdmitError::ProducerPoisoned)
        );

        drain_one(&mut consumer, b"a1");
        drain_one(&mut consumer, b"a2");
        assert!(matches!(
            consumer.try_next(),
            Err(TryRotatingConsumeError::ProducerFaulted {
                published: 2,
                committed: 2,
            })
        ));
    }

    #[test]
    fn released_epochs_counter_is_cache_line_aligned() {
        assert_eq!(std::mem::align_of::<PaddedReleasedEpochs>(), 64);
        assert_eq!(std::mem::align_of::<PaddedTerminal>(), 64);
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
    use loom::thread;

    /// The rotation seam under every interleaving: seal `[S]`, handoff
    /// publication, data-ring `[R]`, boundary crossing `[E]`, and the
    /// released-epoch edge, with descriptor_capacity = 1 forcing a rotation
    /// between two admissions. The concurrent phase makes a bounded number
    /// of attempts (an unbounded poll loop explodes Loom's state space);
    /// the post-join drain is deterministic and completes the stream.
    #[test]
    fn loom_rotating_boundary_is_lossless_and_in_order() {
        loom::model(|| {
            let config = SlabPageConfig {
                arena_id: 7,
                arena_generation: 0,
                byte_capacity: 64,
                descriptor_capacity: 1,
                first_sequence: 0,
            };
            let channel = RotatingAdmissionChannel::<4, 2>::new(config).expect("model channel");
            let (mut producer, mut consumer) = channel.split();

            let producer_thread = thread::spawn(move || {
                producer.try_admit(b"x", 1, 0).expect("epoch 0 admit");
                producer.try_admit(b"y", 1, 0).expect("epoch 1 admit");
                producer.finish().expect("clean finish");
            });
            let consumer_thread = thread::spawn(move || {
                let mut seen: Vec<Vec<u8>> = Vec::new();
                for _ in 0..2 {
                    match consumer.try_next() {
                        Ok(frame) => {
                            seen.push(frame.payload().to_vec());
                            frame.commit();
                        }
                        Err(TryRotatingConsumeError::Empty) => {}
                        Err(error) => panic!("unexpected concurrent error: {error}"),
                    }
                }
                (consumer, seen)
            });

            producer_thread.join().expect("producer joins");
            let (mut consumer, mut seen) = consumer_thread.join().expect("consumer joins");
            // Deterministic drain: the producer is done, so every remaining
            // publication and the clean end are already visible.
            loop {
                match consumer.try_next() {
                    Ok(frame) => {
                        seen.push(frame.payload().to_vec());
                        frame.commit();
                    }
                    Err(TryRotatingConsumeError::CleanEnd) => break,
                    Err(error) => panic!("unexpected drain error: {error}"),
                }
            }
            assert_eq!(seen, vec![b"x".to_vec(), b"y".to_vec()]);
            assert_eq!(consumer.epoch(), 1);
            assert_eq!(consumer.total_committed(), 2);
        });
    }
}
