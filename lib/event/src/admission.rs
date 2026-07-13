//! Failure-atomic composition of one published slab page and one SPSC ring.
//!
//! This is a current, unwired, volatile prototype under Proposed ADR-0009. It
//! carries neither production telemetry nor protected evidence and provides no
//! durability, registry, page rotation, reuse, epoch, NUMA, or qualification
//! claim.

use std::{cell::Cell, error::Error, fmt, marker::PhantomData};

#[cfg(feature = "loom")]
use loom::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};
#[cfg(not(feature = "loom"))]
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};

use crate::{
    ring::{validate_capacity, OccupiedSlot, RingInvariantError, TryClaimError, TryReserveError},
    slab::validate_config,
    Consumer, Producer, PublishedPayload, PublishedSlabPage, PublishedSlabReadError,
    PublishedSlabReader, PublishedSlabWriter, RingConfigError, SlabAppendError, SlabConfigError,
    SlabPageConfig, SpscRing, TelemetryDescriptor,
};

const TERMINAL_OPEN: u8 = 0;
const TERMINAL_CLEAN: u8 = 1;
const TERMINAL_FAULTED: u8 = 2;

#[repr(align(64))]
struct PaddedTerminalState(AtomicU8);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProducerState {
    Open,
    InFlight,
    Poisoned,
    Finished,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConsumerState {
    Open,
    Faulted,
    CleanEnd,
}

#[cfg(all(test, not(feature = "loom")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdmissionFaultPoint {
    BeforePagePublication,
    AfterPagePublication,
    AfterRingSlotWrite,
    AfterRingPublication,
}

#[cfg(all(test, not(feature = "loom")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DescriptorFault {
    SequenceGap,
    SequenceDuplicate,
    SequenceReorder,
    ArenaIdentity,
    PayloadRange,
    PayloadCrc,
}

/// Setup handle binding one fixed page to one fixed descriptor ring.
pub struct VolatileAdmissionChannel<const N: usize> {
    page: PublishedSlabPage,
    ring: SpscRing<TelemetryDescriptor, N>,
    terminal: Arc<PaddedTerminalState>,
}

impl<const N: usize> VolatileAdmissionChannel<N> {
    pub fn new(config: SlabPageConfig) -> Result<Self, AdmissionConfigError> {
        validate_capacity::<N>().map_err(AdmissionConfigError::Ring)?;
        validate_config(config).map_err(AdmissionConfigError::Slab)?;

        let page = PublishedSlabPage::new(config).map_err(AdmissionConfigError::Slab)?;
        let ring = SpscRing::new_with_sequence(config.first_sequence)
            .map_err(AdmissionConfigError::Ring)?;

        Ok(Self {
            page,
            ring,
            terminal: Arc::new(PaddedTerminalState(AtomicU8::new(TERMINAL_OPEN))),
        })
    }

    pub const fn ring_capacity(&self) -> usize {
        N
    }

    pub fn terminal_state_alignment(&self) -> usize {
        std::mem::align_of::<PaddedTerminalState>()
    }

    pub fn split(self) -> (AdmissionProducer<N>, AdmissionConsumer<N>) {
        let Self {
            page,
            ring,
            terminal,
        } = self;
        let (slab, reader) = page.split();
        let (ring, consumer) = ring.split();
        let consumer_terminal = Arc::clone(&terminal);
        let expected_sequence = slab.next_sequence();

        (
            AdmissionProducer {
                slab,
                ring,
                terminal,
                state: ProducerState::Open,
                #[cfg(all(test, not(feature = "loom")))]
                fault_on_next_admission: None,
                _not_sync: PhantomData,
            },
            AdmissionConsumer {
                ring: consumer,
                slab: reader,
                terminal: consumer_terminal,
                expected_sequence,
                committed_count: 0,
                state: ConsumerState::Open,
                _not_sync: PhantomData,
            },
        )
    }
}

impl<const N: usize> fmt::Debug for VolatileAdmissionChannel<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VolatileAdmissionChannel")
            .field("ring_capacity", &N)
            .field("arena_id", &self.page.arena_id())
            .field("arena_generation", &self.page.arena_generation())
            .field("byte_capacity", &self.page.byte_capacity())
            .field("descriptor_capacity", &self.page.descriptor_capacity())
            .finish()
    }
}

/// Sole admission owner for one fixed volatile page/ring pair.
///
/// The endpoint may move to its owning thread but is intentionally not `Sync`:
///
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<aegis_event::AdmissionProducer<1>>();
/// ```
pub struct AdmissionProducer<const N: usize> {
    // Ordered closure is explicit; declaration order preserves page-before-ring
    // closure again during automatic field destruction.
    slab: PublishedSlabWriter,
    ring: Producer<TelemetryDescriptor, N>,
    terminal: Arc<PaddedTerminalState>,
    state: ProducerState,
    #[cfg(all(test, not(feature = "loom")))]
    fault_on_next_admission: Option<AdmissionFaultPoint>,
    _not_sync: PhantomData<Cell<()>>,
}

impl<const N: usize> AdmissionProducer<N> {
    /// Publishes one frame to this process-local volatile page/ring pair.
    ///
    /// Success is only a volatile publication token. It is not consumption,
    /// WAL durability, a receipt, an authorization result, or permission to
    /// discard protected evidence or an upstream replay/spool record.
    pub fn try_admit(
        &mut self,
        payload: &[u8],
        schema_id: u32,
        flags: u16,
    ) -> Result<AdmittedSequence, TryAdmitError> {
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.try_admit_inner(payload, schema_id, flags)
        }));
        match attempt {
            Ok(result) => result,
            Err(panic) => {
                // A caller may catch the resumed unwind and retain this value.
                // Close every shared endpoint before control can escape so the
                // consumer never polls an atomically open, poisoned lane.
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
    ) -> Result<AdmittedSequence, TryAdmitError> {
        #[cfg(all(test, not(feature = "loom")))]
        let fault = self.fault_on_next_admission.take();

        if self.state != ProducerState::Open {
            self.close_faulted();
            return Err(TryAdmitError::ProducerPoisoned);
        }

        self.slab
            .preflight_append(payload.len())
            .map_err(TryAdmitError::Slab)?;

        let slab_sequence = self.slab.next_sequence();
        let ring_sequence = self.ring.next_sequence();
        if slab_sequence != ring_sequence {
            self.state = ProducerState::Poisoned;
            self.close_faulted();
            return Err(TryAdmitError::SequenceDiverged {
                slab: slab_sequence,
                ring: ring_sequence,
            });
        }

        let permit = match self.ring.try_reserve() {
            Ok(permit) => permit,
            Err(TryReserveError::Full) => return Err(TryAdmitError::RingFull),
            Err(TryReserveError::Disconnected) => return Err(TryAdmitError::ConsumerDisconnected),
            Err(TryReserveError::Invariant(error)) => {
                self.state = ProducerState::Poisoned;
                self.close_faulted();
                return Err(TryAdmitError::RingInvariant(error));
            }
        };

        if permit.sequence() != slab_sequence {
            let ring = permit.sequence();
            permit.cancel();
            self.state = ProducerState::Poisoned;
            self.close_faulted();
            return Err(TryAdmitError::SequenceDiverged {
                slab: slab_sequence,
                ring,
            });
        }

        self.state = ProducerState::InFlight;
        #[cfg(all(test, not(feature = "loom")))]
        Self::panic_at(fault, AdmissionFaultPoint::BeforePagePublication);
        let descriptor = match self.slab.try_append(payload, schema_id, flags) {
            Ok(descriptor) => descriptor,
            Err(error) => {
                self.state = ProducerState::Open;
                return Err(TryAdmitError::Slab(error));
            }
        };

        // ADR-0009's post-page-publication interval starts at the return from
        // `try_append`. `publish` is deliberately infallible and performs no
        // allocation, indexing, callback, formatting, or peer-state recheck.
        #[cfg(all(test, not(feature = "loom")))]
        Self::panic_at(fault, AdmissionFaultPoint::AfterPagePublication);
        #[cfg(all(test, not(feature = "loom")))]
        if fault == Some(AdmissionFaultPoint::AfterRingSlotWrite) {
            permit.publish_then_panic_before_head(descriptor);
        }
        permit.publish(descriptor);
        #[cfg(all(test, not(feature = "loom")))]
        Self::panic_at(fault, AdmissionFaultPoint::AfterRingPublication);
        self.state = ProducerState::Open;
        Ok(AdmittedSequence::from_descriptor(descriptor))
    }

    #[cfg(all(test, not(feature = "loom")))]
    fn panic_at(actual: Option<AdmissionFaultPoint>, expected: AdmissionFaultPoint) {
        if actual == Some(expected) {
            panic!("injected admission fault at {expected:?}");
        }
    }

    #[cfg(all(test, not(feature = "loom")))]
    fn inject_panic_on_next_admission(&mut self, point: AdmissionFaultPoint) {
        self.fault_on_next_admission = Some(point);
    }

    #[cfg(all(test, not(feature = "loom")))]
    fn inject_corrupt_descriptor(
        &mut self,
        payload: &[u8],
        fault: DescriptorFault,
    ) -> Result<(), TryAdmitError> {
        self.slab
            .preflight_append(payload.len())
            .map_err(TryAdmitError::Slab)?;
        let permit = self.ring.try_reserve().map_err(TryAdmitError::from)?;
        self.state = ProducerState::InFlight;
        let mut descriptor = self
            .slab
            .try_append(payload, 1, 0)
            .map_err(TryAdmitError::Slab)?;

        let overwrite_canonical = match fault {
            DescriptorFault::SequenceGap => {
                descriptor.sequence = descriptor.sequence.wrapping_add(2);
                false
            }
            DescriptorFault::SequenceDuplicate => {
                descriptor.sequence = descriptor.sequence.wrapping_sub(1);
                false
            }
            DescriptorFault::SequenceReorder => {
                descriptor.sequence = descriptor.sequence.wrapping_add(1);
                false
            }
            DescriptorFault::ArenaIdentity => {
                descriptor.arena_id ^= 1;
                false
            }
            DescriptorFault::PayloadRange => {
                descriptor.offset = u32::try_from(self.slab.byte_capacity())
                    .expect("bounded test page is u32-addressable");
                descriptor.len = 1;
                true
            }
            DescriptorFault::PayloadCrc => {
                descriptor.crc32c ^= u32::MAX;
                true
            }
        };
        if overwrite_canonical {
            // SAFETY: this single-threaded fixture rewrites the canonical cell
            // before publishing its ring descriptor; the consumer cannot yet
            // observe or access the page entry.
            unsafe {
                self.slab.overwrite_last_descriptor_for_test(descriptor);
            }
        }

        permit.publish(descriptor);
        self.state = ProducerState::Open;
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), FinishError> {
        if self.state != ProducerState::Open {
            self.close_faulted();
            return Err(FinishError::ProducerPoisoned);
        }

        self.slab.close();
        self.terminal.0.store(TERMINAL_CLEAN, Ordering::Release);
        self.ring.close();
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
        self.state = ProducerState::Finished;
    }

    pub fn arena_id(&self) -> u16 {
        self.slab.arena_id()
    }

    pub fn arena_generation(&self) -> u32 {
        self.slab.arena_generation()
    }

    pub fn used_bytes(&self) -> usize {
        self.slab.used_bytes()
    }

    pub fn published_count(&self) -> usize {
        self.slab.published_count()
    }

    pub fn remaining_bytes(&self) -> usize {
        self.slab.remaining_bytes()
    }

    pub fn remaining_descriptors(&self) -> usize {
        self.slab.remaining_descriptors()
    }

    pub fn next_sequence(&self) -> u64 {
        self.slab.next_sequence()
    }

    #[cfg(test)]
    fn inject_orphan_after_page_publication(
        &mut self,
        payload: &[u8],
    ) -> Result<(), TryAdmitError> {
        self.slab
            .preflight_append(payload.len())
            .map_err(TryAdmitError::Slab)?;
        let permit = self.ring.try_reserve().map_err(TryAdmitError::from)?;
        self.state = ProducerState::InFlight;
        let _descriptor = self
            .slab
            .try_append(payload, 1, 0)
            .map_err(TryAdmitError::Slab)?;
        permit.cancel();
        Ok(())
    }
}

impl<const N: usize> Drop for AdmissionProducer<N> {
    fn drop(&mut self) {
        self.close_faulted();
    }
}

impl<const N: usize> fmt::Debug for AdmissionProducer<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdmissionProducer")
            .field("ring_capacity", &N)
            .field("arena_id", &self.arena_id())
            .field("arena_generation", &self.arena_generation())
            .field("used_bytes", &self.used_bytes())
            .field("published_count", &self.published_count())
            .field("next_sequence", &self.next_sequence())
            .field("state", &self.state)
            .finish()
    }
}

/// Sole validation/acknowledgement owner for one fixed volatile page/ring pair.
///
/// The endpoint may move to its owning thread but is intentionally not `Sync`:
///
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<aegis_event::AdmissionConsumer<1>>();
/// ```
pub struct AdmissionConsumer<const N: usize> {
    // Closing the ring consumer before releasing the page reader prevents a new
    // producer permit after the bound reader lifetime ends.
    ring: Consumer<TelemetryDescriptor, N>,
    slab: PublishedSlabReader,
    terminal: Arc<PaddedTerminalState>,
    expected_sequence: u64,
    committed_count: usize,
    state: ConsumerState,
    _not_sync: PhantomData<Cell<()>>,
}

impl<const N: usize> AdmissionConsumer<N> {
    pub fn try_next(&mut self) -> Result<AdmittedEvent<'_, N>, TryConsumeError> {
        let Self {
            ring,
            slab,
            terminal,
            expected_sequence,
            committed_count,
            state,
            _not_sync: _,
        } = self;

        match *state {
            ConsumerState::CleanEnd => return Err(TryConsumeError::CleanEnd),
            ConsumerState::Faulted => return Err(TryConsumeError::ConsumerPoisoned),
            ConsumerState::Open => {}
        }

        let claim = match ring.try_claim() {
            Ok(claim) => claim,
            Err(TryClaimError::Empty) => return Err(TryConsumeError::Empty),
            Err(TryClaimError::Disconnected) => {
                return Err(Self::classify_end(slab, terminal, *committed_count, state));
            }
            Err(TryClaimError::Invariant(error)) => {
                // `try_claim` Release-closes the ring consumer before exposing
                // an invariant failure, so the producer cannot publish more.
                *state = ConsumerState::Faulted;
                return Err(TryConsumeError::RingInvariant(error));
            }
        };

        let descriptor = claim.value();
        if descriptor.sequence != *expected_sequence {
            claim.close_consumer();
            let expected = *expected_sequence;
            *state = ConsumerState::Faulted;
            return Err(TryConsumeError::SequenceMismatch {
                expected,
                actual: descriptor.sequence,
            });
        }

        let payload = match slab.resolve(&descriptor) {
            Ok(payload) => payload,
            Err(error) => {
                claim.close_consumer();
                *state = ConsumerState::Faulted;
                return Err(TryConsumeError::Page(error));
            }
        };

        Ok(AdmittedEvent {
            descriptor,
            payload,
            claim,
            expected_sequence,
            committed_count,
        })
    }

    fn classify_end(
        slab: &PublishedSlabReader,
        terminal: &Arc<PaddedTerminalState>,
        committed_count: usize,
        state: &mut ConsumerState,
    ) -> TryConsumeError {
        let status = match slab.status() {
            Ok(status) => status,
            Err(error) => {
                *state = ConsumerState::Faulted;
                return TryConsumeError::Page(error);
            }
        };
        let terminal = terminal.0.load(Ordering::Acquire);

        if !status.writer_closed {
            *state = ConsumerState::Faulted;
            return TryConsumeError::ClosureOrderViolation;
        }

        if status.published_count != committed_count {
            let error = if terminal == TERMINAL_FAULTED && status.published_count > committed_count
            {
                TryConsumeError::OrphanedPublishedPrefix {
                    published: status.published_count,
                    committed: committed_count,
                }
            } else {
                TryConsumeError::CountMismatch {
                    published: status.published_count,
                    committed: committed_count,
                }
            };
            *state = ConsumerState::Faulted;
            return error;
        }

        match terminal {
            TERMINAL_CLEAN => {
                *state = ConsumerState::CleanEnd;
                TryConsumeError::CleanEnd
            }
            TERMINAL_FAULTED => {
                *state = ConsumerState::Faulted;
                TryConsumeError::ProducerFaulted {
                    published: status.published_count,
                    committed: committed_count,
                }
            }
            TERMINAL_OPEN => {
                *state = ConsumerState::Faulted;
                TryConsumeError::ClosureOrderViolation
            }
            raw => {
                *state = ConsumerState::Faulted;
                TryConsumeError::TerminalStateInvalid { raw }
            }
        }
    }

    pub fn arena_id(&self) -> u16 {
        self.slab.arena_id()
    }

    pub fn arena_generation(&self) -> u32 {
        self.slab.arena_generation()
    }

    pub fn committed_count(&self) -> usize {
        self.committed_count
    }

    pub fn expected_sequence(&self) -> u64 {
        self.expected_sequence
    }
}

impl<const N: usize> fmt::Debug for AdmissionConsumer<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdmissionConsumer")
            .field("ring_capacity", &N)
            .field("arena_id", &self.arena_id())
            .field("arena_generation", &self.arena_generation())
            .field("expected_sequence", &self.expected_sequence)
            .field("committed_count", &self.committed_count)
            .field("state", &self.state)
            .finish()
    }
}

/// Must-use validated frame whose ring capacity remains claimed until commit.
///
/// A frame lease is intentionally neither `Send` nor `Sync` and cannot cross
/// an `.await`, callback, or ownership handoff:
///
/// ```compile_fail
/// fn require_send<T: Send>() {}
/// require_send::<aegis_event::AdmittedEvent<'static, 1>>();
/// ```
///
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<aegis_event::AdmittedEvent<'static, 1>>();
/// ```
#[must_use = "commit the frame only after synchronous processing succeeds"]
pub struct AdmittedEvent<'consumer, const N: usize> {
    descriptor: TelemetryDescriptor,
    payload: PublishedPayload<'consumer>,
    claim: OccupiedSlot<'consumer, TelemetryDescriptor, N>,
    expected_sequence: &'consumer mut u64,
    committed_count: &'consumer mut usize,
}

impl<const N: usize> AdmittedEvent<'_, N> {
    pub const fn descriptor(&self) -> &TelemetryDescriptor {
        &self.descriptor
    }

    pub fn payload(&self) -> &[u8] {
        self.payload.as_ref()
    }

    /// Reclaims this volatile ring slot after synchronous validation/handling.
    ///
    /// The returned value is not a receipt, durability acknowledgement, or
    /// authorization result and must never acknowledge protected evidence.
    pub fn commit(self) -> AdmittedSequence {
        let Self {
            descriptor: _,
            payload: _,
            claim,
            expected_sequence,
            committed_count,
        } = self;
        let descriptor = claim.commit();
        *expected_sequence = descriptor.sequence.wrapping_add(1);
        *committed_count += 1;
        AdmittedSequence::from_descriptor(descriptor)
    }

    #[cfg(all(test, not(feature = "loom")))]
    fn commit_then_panic_before_counters(self) -> ! {
        let Self {
            descriptor: _,
            payload: _,
            claim,
            expected_sequence: _,
            committed_count: _,
        } = self;
        let _ = claim.commit();
        panic!("injected frame fault after tail commit and before local counters");
    }
}

impl<const N: usize> fmt::Debug for AdmittedEvent<'_, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdmittedEvent")
            .field("descriptor", &self.descriptor)
            .field("payload_len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

/// Identity of one frame published to the volatile admission pair.
///
/// This token proves neither consumption nor durability and must not be used
/// as a receipt, protected-evidence acknowledgement, or authorization result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmittedSequence {
    arena_id: u16,
    arena_generation: u32,
    sequence: u64,
}

impl AdmittedSequence {
    const fn from_descriptor(descriptor: TelemetryDescriptor) -> Self {
        Self {
            arena_id: descriptor.arena_id,
            arena_generation: descriptor.arena_generation,
            sequence: descriptor.sequence,
        }
    }

    pub const fn arena_id(self) -> u16 {
        self.arena_id
    }

    pub const fn arena_generation(self) -> u32 {
        self.arena_generation
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionConfigError {
    Ring(RingConfigError),
    Slab(SlabConfigError),
}

impl fmt::Display for AdmissionConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ring(error) => write!(f, "invalid admission ring configuration: {error}"),
            Self::Slab(error) => write!(f, "invalid admission page configuration: {error}"),
        }
    }
}

impl Error for AdmissionConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Ring(error) => Some(error),
            Self::Slab(error) => Some(error),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TryAdmitError {
    RingFull,
    ConsumerDisconnected,
    Slab(SlabAppendError),
    SequenceDiverged { slab: u64, ring: u64 },
    RingInvariant(RingInvariantError),
    ProducerPoisoned,
}

impl From<TryReserveError> for TryAdmitError {
    fn from(error: TryReserveError) -> Self {
        match error {
            TryReserveError::Full => Self::RingFull,
            TryReserveError::Disconnected => Self::ConsumerDisconnected,
            TryReserveError::Invariant(error) => Self::RingInvariant(error),
        }
    }
}

impl fmt::Display for TryAdmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RingFull => write!(f, "volatile admission ring is full"),
            Self::ConsumerDisconnected => write!(f, "volatile admission consumer is disconnected"),
            Self::Slab(error) => write!(f, "volatile admission page rejected the frame: {error}"),
            Self::SequenceDiverged { slab, ring } => write!(
                f,
                "volatile admission page sequence {slab} diverged from ring sequence {ring}"
            ),
            Self::RingInvariant(error) => {
                write!(f, "volatile admission ring invariant failed: {error}")
            }
            Self::ProducerPoisoned => write!(f, "volatile admission producer is poisoned"),
        }
    }
}

impl Error for TryAdmitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Slab(error) => Some(error),
            Self::RingInvariant(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinishError {
    ProducerPoisoned,
}

impl fmt::Display for FinishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProducerPoisoned => {
                write!(f, "poisoned admission producer cannot finish cleanly")
            }
        }
    }
}

impl Error for FinishError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TryConsumeError {
    Empty,
    CleanEnd,
    ConsumerPoisoned,
    ProducerFaulted { published: usize, committed: usize },
    OrphanedPublishedPrefix { published: usize, committed: usize },
    CountMismatch { published: usize, committed: usize },
    SequenceMismatch { expected: u64, actual: u64 },
    ClosureOrderViolation,
    TerminalStateInvalid { raw: u8 },
    RingInvariant(RingInvariantError),
    Page(PublishedSlabReadError),
}

impl fmt::Display for TryConsumeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "volatile admission ring is empty"),
            Self::CleanEnd => write!(f, "volatile admission stream ended cleanly"),
            Self::ConsumerPoisoned => write!(f, "volatile admission consumer is poisoned"),
            Self::ProducerFaulted {
                published,
                committed,
            } => write!(
                f,
                "volatile admission producer faulted after publishing {published} and committing {committed} events"
            ),
            Self::OrphanedPublishedPrefix {
                published,
                committed,
            } => write!(
                f,
                "volatile admission page has orphaned prefix: published {published}, committed {committed}"
            ),
            Self::CountMismatch {
                published,
                committed,
            } => write!(
                f,
                "volatile admission count mismatch: published {published}, committed {committed}"
            ),
            Self::SequenceMismatch { expected, actual } => write!(
                f,
                "volatile admission sequence mismatch: expected {expected}, received {actual}"
            ),
            Self::ClosureOrderViolation => write!(
                f,
                "volatile admission ring closed before page and terminal state"
            ),
            Self::TerminalStateInvalid { raw } => {
                write!(f, "volatile admission terminal state {raw} is invalid")
            }
            Self::RingInvariant(error) => {
                write!(f, "volatile admission ring invariant failed: {error}")
            }
            Self::Page(error) => write!(f, "volatile admission page validation failed: {error}"),
        }
    }
}

impl Error for TryConsumeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RingInvariant(error) => Some(error),
            Self::Page(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(all(test, not(feature = "loom")))]
mod native_tests {
    use super::*;
    use crate::CACHE_LINE_BYTES;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn config() -> SlabPageConfig {
        SlabPageConfig {
            arena_id: 1,
            arena_generation: 2,
            byte_capacity: 8,
            descriptor_capacity: 2,
            first_sequence: 3,
        }
    }

    #[test]
    fn terminal_state_occupies_a_distinct_cache_aligned_unit() {
        fn require_send<T: Send>() {}

        require_send::<AdmissionProducer<2>>();
        require_send::<AdmissionConsumer<2>>();
        let channel = VolatileAdmissionChannel::<2>::new(config()).expect("bounded channel");
        assert_eq!(channel.terminal_state_alignment(), CACHE_LINE_BYTES);
        assert!(std::mem::size_of::<PaddedTerminalState>() >= CACHE_LINE_BYTES);
    }

    #[test]
    fn injected_post_page_pre_ring_interruption_reports_an_orphan() {
        let channel = VolatileAdmissionChannel::<1>::new(config()).expect("bounded channel");
        let (mut producer, mut consumer) = channel.split();
        producer
            .inject_orphan_after_page_publication(b"x")
            .expect("fault injection publishes only the page");
        drop(producer);

        assert!(matches!(
            consumer.try_next(),
            Err(TryConsumeError::OrphanedPublishedPrefix {
                published: 1,
                committed: 0,
            })
        ));
    }

    #[test]
    fn caught_unwind_closes_a_retained_producer_at_every_publication_phase() {
        for point in [
            AdmissionFaultPoint::BeforePagePublication,
            AdmissionFaultPoint::AfterPagePublication,
            AdmissionFaultPoint::AfterRingSlotWrite,
            AdmissionFaultPoint::AfterRingPublication,
        ] {
            let channel = VolatileAdmissionChannel::<1>::new(config()).expect("bounded channel");
            let (mut producer, mut consumer) = channel.split();
            producer.inject_panic_on_next_admission(point);

            let unwind = catch_unwind(AssertUnwindSafe(|| {
                let _ = producer.try_admit(b"x", 1, 0);
            }));
            assert!(unwind.is_err(), "fault point {point:?} must unwind");

            let expected_published =
                usize::from(point != AdmissionFaultPoint::BeforePagePublication);
            assert_eq!(producer.published_count(), expected_published);
            assert_eq!(
                producer.try_admit(b"retained", 1, 0),
                Err(TryAdmitError::ProducerPoisoned),
                "retained producer must remain terminal at {point:?}"
            );

            match point {
                AdmissionFaultPoint::BeforePagePublication => assert!(matches!(
                    consumer.try_next(),
                    Err(TryConsumeError::ProducerFaulted {
                        published: 0,
                        committed: 0,
                    })
                )),
                AdmissionFaultPoint::AfterPagePublication
                | AdmissionFaultPoint::AfterRingSlotWrite => assert!(matches!(
                    consumer.try_next(),
                    Err(TryConsumeError::OrphanedPublishedPrefix {
                        published: 1,
                        committed: 0,
                    })
                )),
                AdmissionFaultPoint::AfterRingPublication => {
                    let frame = consumer
                        .try_next()
                        .expect("published frame remains drainable");
                    assert_eq!(frame.payload(), b"x");
                    frame.commit();
                    assert!(matches!(
                        consumer.try_next(),
                        Err(TryConsumeError::ProducerFaulted {
                            published: 1,
                            committed: 1,
                        })
                    ));
                }
            }
        }
    }

    #[test]
    fn claim_invariant_closes_consumer_before_returning_the_error() {
        let channel = VolatileAdmissionChannel::<2>::new(config()).expect("bounded channel");
        let (mut producer, mut consumer) = channel.split();
        consumer
            .ring
            .inject_cached_head_for_test(consumer.expected_sequence.wrapping_add(3));

        assert!(matches!(
            consumer.try_next(),
            Err(TryConsumeError::RingInvariant(
                RingInvariantError::CursorDistanceExceedsCapacity { capacity: 2, .. }
            ))
        ));
        assert_eq!(
            producer.try_admit(b"blocked", 1, 0),
            Err(TryAdmitError::ConsumerDisconnected)
        );
        assert_eq!(producer.published_count(), 0);
        assert_eq!(producer.used_bytes(), 0);
        assert!(matches!(
            consumer.try_next(),
            Err(TryConsumeError::ConsumerPoisoned)
        ));
    }

    #[test]
    fn corrupt_descriptors_withhold_tail_and_disconnect_the_producer() {
        for fault in [
            DescriptorFault::SequenceGap,
            DescriptorFault::SequenceDuplicate,
            DescriptorFault::SequenceReorder,
            DescriptorFault::ArenaIdentity,
            DescriptorFault::PayloadRange,
            DescriptorFault::PayloadCrc,
        ] {
            let channel = VolatileAdmissionChannel::<2>::new(config()).expect("bounded channel");
            let (mut producer, mut consumer) = channel.split();
            producer
                .inject_corrupt_descriptor(b"x", fault)
                .expect("fault fixture publishes one corrupt descriptor");

            let error = consumer
                .try_next()
                .expect_err("corrupt descriptor must fail closed");
            match fault {
                DescriptorFault::SequenceGap => assert_eq!(
                    error,
                    TryConsumeError::SequenceMismatch {
                        expected: 3,
                        actual: 5,
                    }
                ),
                DescriptorFault::SequenceDuplicate => assert_eq!(
                    error,
                    TryConsumeError::SequenceMismatch {
                        expected: 3,
                        actual: 2,
                    }
                ),
                DescriptorFault::SequenceReorder => assert_eq!(
                    error,
                    TryConsumeError::SequenceMismatch {
                        expected: 3,
                        actual: 4,
                    }
                ),
                DescriptorFault::ArenaIdentity => assert_eq!(
                    error,
                    TryConsumeError::Page(PublishedSlabReadError::ArenaIdMismatch {
                        page: 1,
                        descriptor: 0,
                    })
                ),
                DescriptorFault::PayloadRange => assert_eq!(
                    error,
                    TryConsumeError::Page(PublishedSlabReadError::Descriptor(
                        crate::DescriptorError::OutOfBounds {
                            end: 9,
                            page_len: 1,
                        }
                    ))
                ),
                DescriptorFault::PayloadCrc => assert_eq!(
                    error,
                    TryConsumeError::Page(PublishedSlabReadError::CrcMismatch { sequence: 3 })
                ),
            }

            assert_eq!(consumer.committed_count(), 0);
            assert_eq!(producer.published_count(), 1);
            assert_eq!(producer.used_bytes(), 1);
            assert_eq!(
                producer.try_admit(b"y", 1, 0),
                Err(TryAdmitError::ConsumerDisconnected),
                "fault {fault:?} must close before the producer can grow the page"
            );
            assert_eq!(producer.published_count(), 1);
            assert_eq!(producer.used_bytes(), 1);
            assert!(matches!(
                consumer.try_next(),
                Err(TryConsumeError::ConsumerPoisoned)
            ));
        }
    }

    #[test]
    fn malformed_terminal_closure_states_never_report_clean_end() {
        {
            let channel = VolatileAdmissionChannel::<1>::new(config()).expect("bounded channel");
            let (mut producer, mut consumer) = channel.split();
            producer.terminal.0.store(TERMINAL_CLEAN, Ordering::Release);
            producer.ring.close();
            assert_eq!(
                consumer.try_next().expect_err("page is still open"),
                TryConsumeError::ClosureOrderViolation
            );
        }

        {
            let channel = VolatileAdmissionChannel::<1>::new(config()).expect("bounded channel");
            let (mut producer, mut consumer) = channel.split();
            producer.slab.close();
            producer.terminal.0.store(0xff, Ordering::Release);
            producer.ring.close();
            producer.state = ProducerState::Finished;
            assert_eq!(
                consumer
                    .try_next()
                    .expect_err("unknown terminal state is corrupt"),
                TryConsumeError::TerminalStateInvalid { raw: 0xff }
            );
        }

        {
            let channel = VolatileAdmissionChannel::<1>::new(config()).expect("bounded channel");
            let (mut producer, mut consumer) = channel.split();
            producer
                .inject_orphan_after_page_publication(b"x")
                .expect("page-only fixture");
            producer.slab.close();
            producer.terminal.0.store(TERMINAL_CLEAN, Ordering::Release);
            producer.ring.close();
            producer.state = ProducerState::Finished;
            assert_eq!(
                consumer
                    .try_next()
                    .expect_err("clean state cannot hide a page-ahead count"),
                TryConsumeError::CountMismatch {
                    published: 1,
                    committed: 0,
                }
            );
        }

        {
            let channel = VolatileAdmissionChannel::<1>::new(config()).expect("bounded channel");
            let (mut producer, mut consumer) = channel.split();
            consumer.committed_count = 1;
            producer.slab.close();
            producer.terminal.0.store(TERMINAL_CLEAN, Ordering::Release);
            producer.ring.close();
            producer.state = ProducerState::Finished;
            assert_eq!(
                consumer
                    .try_next()
                    .expect_err("consumer-ahead count is corrupt"),
                TryConsumeError::CountMismatch {
                    published: 0,
                    committed: 1,
                }
            );
        }
    }

    #[test]
    fn interruption_after_tail_commit_poison_closes_on_the_next_descriptor() {
        let channel = VolatileAdmissionChannel::<2>::new(config()).expect("bounded channel");
        let (mut producer, mut consumer) = channel.split();
        producer.try_admit(b"a", 1, 0).expect("first event");
        producer.try_admit(b"b", 1, 0).expect("second event");
        producer.finish().expect("clean producer close");

        let frame = consumer.try_next().expect("first frame validates");
        let unwind = catch_unwind(AssertUnwindSafe(|| {
            frame.commit_then_panic_before_counters();
        }));
        assert!(unwind.is_err());
        assert_eq!(consumer.committed_count(), 0);
        assert_eq!(consumer.expected_sequence(), 3);
        assert_eq!(
            consumer
                .try_next()
                .expect_err("stale local sequence must fail closed"),
            TryConsumeError::SequenceMismatch {
                expected: 3,
                actual: 4,
            }
        );
        assert!(matches!(
            consumer.try_next(),
            Err(TryConsumeError::ConsumerPoisoned)
        ));
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
    use loom::thread;

    fn config() -> SlabPageConfig {
        SlabPageConfig {
            arena_id: 1,
            arena_generation: 2,
            byte_capacity: 2,
            descriptor_capacity: 2,
            first_sequence: u64::MAX,
        }
    }

    #[test]
    fn loom_admission_page_publication_precedes_ring_visibility_and_clean_close() {
        loom::model(|| {
            let channel = VolatileAdmissionChannel::<1>::new(config()).expect("bounded model");
            let (mut producer, mut consumer) = channel.split();

            let producer_thread = thread::spawn(move || {
                producer.try_admit(b"x", 1, 0).expect("model admit");
                producer.finish().expect("clean model finish");
            });
            let consumer_thread = thread::spawn(move || {
                let consumed = match consumer.try_next() {
                    Ok(frame) => {
                        assert_eq!(frame.descriptor().sequence, u64::MAX);
                        assert_eq!(frame.payload(), b"x");
                        frame.commit();
                        true
                    }
                    Err(TryConsumeError::Empty) => false,
                    Err(error) => panic!("unexpected model error: {error}"),
                };
                (consumer, consumed)
            });

            producer_thread.join().expect("producer succeeds");
            let (mut consumer, consumed) = consumer_thread.join().expect("consumer succeeds");
            if !consumed {
                let frame = consumer.try_next().expect("final publication drains");
                assert_eq!(frame.payload(), b"x");
                frame.commit();
            }
            assert!(matches!(
                consumer.try_next(),
                Err(TryConsumeError::CleanEnd)
            ));
        });
    }

    #[test]
    fn loom_admission_full_retry_never_consumes_page_capacity() {
        loom::model(|| {
            let channel = VolatileAdmissionChannel::<1>::new(config()).expect("bounded model");
            let (mut producer, mut consumer) = channel.split();
            producer.try_admit(b"a", 1, 0).expect("first admit");

            let producer_thread = thread::spawn(move || {
                let outcome = match producer.try_admit(b"b", 1, 0) {
                    Ok(token) => {
                        assert_eq!(token.sequence(), 0);
                        2
                    }
                    Err(TryAdmitError::RingFull) => {
                        assert_eq!(producer.published_count(), 1);
                        assert_eq!(producer.used_bytes(), 1);
                        1
                    }
                    Err(TryAdmitError::ConsumerDisconnected) => {
                        assert_eq!(producer.published_count(), 1);
                        assert_eq!(producer.used_bytes(), 1);
                        1
                    }
                    Err(error) => panic!("unexpected producer error: {error}"),
                };
                assert_eq!(producer.published_count(), outcome);
                drop(producer);
            });
            let consumer_thread = thread::spawn(move || {
                let frame = consumer.try_next().expect("first event was prepublished");
                assert_eq!(frame.payload(), b"a");
                frame.commit();
            });

            producer_thread.join().expect("producer succeeds");
            consumer_thread.join().expect("consumer succeeds");
        });
    }

    #[test]
    fn loom_admission_validation_failure_races_reserved_publication() {
        loom::model(|| {
            let channel = VolatileAdmissionChannel::<2>::new(config()).expect("bounded model");
            let (mut producer, mut consumer) = channel.split();
            producer.try_admit(b"a", 1, 0).expect("first model admit");

            consumer.expected_sequence = consumer.expected_sequence.wrapping_add(1);
            let producer_thread = thread::spawn(move || {
                let outcome = match producer.try_admit(b"b", 1, 0) {
                    Ok(token) => {
                        assert_eq!(token.sequence(), 0);
                        assert_eq!(producer.published_count(), 2);
                        assert_eq!(producer.used_bytes(), 2);
                        2
                    }
                    Err(TryAdmitError::ConsumerDisconnected) => {
                        assert_eq!(producer.published_count(), 1);
                        assert_eq!(producer.used_bytes(), 1);
                        1
                    }
                    Err(error) => panic!("unexpected raced producer error: {error}"),
                };
                (producer, outcome)
            });
            let consumer_thread = thread::spawn(move || {
                assert!(matches!(
                    consumer.try_next(),
                    Err(TryConsumeError::SequenceMismatch {
                        expected: 0,
                        actual: u64::MAX,
                    })
                ));
                assert!(matches!(
                    consumer.try_next(),
                    Err(TryConsumeError::ConsumerPoisoned)
                ));
                consumer
            });

            let (producer, published) = producer_thread.join().expect("producer succeeds");
            let consumer = consumer_thread.join().expect("consumer succeeds");
            assert_eq!(producer.published_count(), published);
            drop(producer);
            drop(consumer);
        });
    }

    #[test]
    fn loom_admission_faulted_orphan_is_never_reported_as_clean_end() {
        loom::model(|| {
            let channel = VolatileAdmissionChannel::<1>::new(config()).expect("bounded model");
            let (mut producer, mut consumer) = channel.split();
            producer
                .inject_orphan_after_page_publication(b"x")
                .expect("page-only fault injection");
            drop(producer);

            assert!(matches!(
                consumer.try_next(),
                Err(TryConsumeError::OrphanedPublishedPrefix {
                    published: 1,
                    committed: 0,
                })
            ));
        });
    }
}
