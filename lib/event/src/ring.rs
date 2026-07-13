//! Cache-padded, bounded single-producer/single-consumer ring.
//!
//! # Safety invariants
//!
//! - `SpscRing::split` creates exactly one non-cloneable producer and consumer.
//! - Endpoint mutation requires `&mut self`; endpoint marker fields make them
//!   `!Sync`, while `T: Send` permits ownership transfer to another thread.
//! - The producer is the only writer to a free slot. Its `Release` publication
//!   follows initialization, and the consumer reads only after an `Acquire`.
//! - A `Copy` consumer may inspect a claimed slot without advancing the tail.
//!   The consumer moves each value once only when the claim commits. Its
//!   `Release` consumption follows the move, and the producer reuses a slot
//!   only after an `Acquire`.
//! - Vacant and occupied slot capabilities exclusively borrow their endpoint
//!   and are `!Send` and `!Sync`. Dropping either capability is a no-op.
//! - Published minus consumed distance never exceeds capacity. Capacity is a
//!   power of two below `2^63`, making modular sequence distance unambiguous.
//! - The final `Inner` drop runs only after both endpoints are gone and drops
//!   exactly the still-published range. An invalid distance panics in debug and
//!   leaks in release rather than dereferencing an unproven slot.

use std::{cell::Cell, error::Error, fmt, marker::PhantomData, mem::MaybeUninit, rc::Rc};

#[cfg(feature = "loom")]
use loom::{
    cell::UnsafeCell,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};
#[cfg(not(feature = "loom"))]
use std::{
    cell::UnsafeCell,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};

pub const CACHE_LINE_BYTES: usize = 64;

#[repr(align(64))]
struct PaddedSequence(AtomicU64);

#[repr(align(64))]
struct PaddedEndpointState {
    producer_closed: AtomicBool,
    consumer_closed: AtomicBool,
}

struct Slot<T>(UnsafeCell<MaybeUninit<T>>);

impl<T> Slot<T> {
    fn uninit() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }

    #[cfg(not(feature = "loom"))]
    fn write(&self, value: T) {
        // SAFETY: Only the producer accesses this slot before the publication
        // sequence advances, and the consumed sequence proved any old value was
        // moved out before this call.
        unsafe { (*self.0.get()).write(value) };
    }

    #[cfg(feature = "loom")]
    fn write(&self, value: T) {
        self.0.with_mut(|slot| {
            // SAFETY: The SPSC ownership and sequence proof is identical to the
            // native implementation; Loom tracks the exclusive cell access.
            unsafe { (*slot).write(value) };
        });
    }

    #[cfg(not(feature = "loom"))]
    fn read(&self) -> T {
        // SAFETY: The consumer observed the producer's Release publication with
        // Acquire and is the only reader. The slot is initialized and is moved
        // exactly once before the consumed sequence advances.
        unsafe { (*self.0.get()).assume_init_read() }
    }

    #[cfg(feature = "loom")]
    fn read(&self) -> T {
        self.0.with(|slot| {
            // SAFETY: The SPSC ownership and publication proof is identical to
            // the native implementation; Loom tracks the immutable cell access.
            unsafe { (*slot).assume_init_read() }
        })
    }

    #[cfg(not(feature = "loom"))]
    fn copy_value(&self) -> T
    where
        T: Copy,
    {
        // SAFETY: The consumer observed publication with Acquire and holds the
        // only consumer endpoint mutably. Copying through a shared reference
        // does not move or invalidate the initialized slot, so cancellation
        // can leave it available for a later claim.
        unsafe { *(*self.0.get()).assume_init_ref() }
    }

    #[cfg(feature = "loom")]
    fn copy_value(&self) -> T
    where
        T: Copy,
    {
        self.0.with(|slot| {
            // SAFETY: The claim has the same publication and exclusive
            // consumer proof as native code; Loom tracks this shared access.
            unsafe { *(*slot).assume_init_ref() }
        })
    }

    #[cfg(not(feature = "loom"))]
    fn drop_value(&self) {
        // SAFETY: `Inner::drop` calls this only for the bounded sequence range
        // published but not consumed. No endpoint still exists at final drop.
        unsafe { (*self.0.get()).assume_init_drop() };
    }

    #[cfg(feature = "loom")]
    fn drop_value(&self) {
        self.0.with_mut(|slot| {
            // SAFETY: The final-drop initialization proof is identical to the
            // native implementation; Loom tracks the exclusive cell access.
            unsafe { (*slot).assume_init_drop() };
        });
    }
}

#[repr(C)]
struct Inner<T> {
    published_head: PaddedSequence,
    consumed_tail: PaddedSequence,
    endpoint_state: PaddedEndpointState,
    slots: Box<[Slot<T>]>,
}

// SAFETY: `T: Send` values cross from the producer thread to the consumer
// thread. The sequence protocol provides exclusive slot access and publication.
unsafe impl<T: Send> Send for Inner<T> {}

// SAFETY: Shared `Inner` access is restricted to atomics plus slots whose
// exclusive owner is proven by the SPSC sequence protocol.
unsafe impl<T: Send> Sync for Inner<T> {}

impl<T> Drop for Inner<T> {
    fn drop(&mut self) {
        let head = self.published_head.0.load(Ordering::Acquire);
        let tail = self.consumed_tail.0.load(Ordering::Acquire);
        let remaining = head.wrapping_sub(tail);

        if remaining > self.slots.len() as u64 {
            debug_assert!(
                remaining <= self.slots.len() as u64,
                "SPSC sequence invariant violated during drop"
            );
            return;
        }

        for distance in 0..remaining {
            let sequence = tail.wrapping_add(distance);
            let index = (sequence as usize) & (self.slots.len() - 1);
            self.slots[index].drop_value();
        }
    }
}

pub struct SpscRing<T, const N: usize> {
    inner: Arc<Inner<T>>,
}

impl<T, const N: usize> SpscRing<T, N> {
    pub fn new() -> Result<Self, RingConfigError> {
        Self::new_with_sequence(0)
    }

    pub(crate) fn new_with_sequence(sequence: u64) -> Result<Self, RingConfigError> {
        validate_capacity::<N>()?;

        let mut slots = Vec::with_capacity(N);
        slots.resize_with(N, Slot::uninit);

        Ok(Self {
            inner: Arc::new(Inner {
                published_head: PaddedSequence(AtomicU64::new(sequence)),
                consumed_tail: PaddedSequence(AtomicU64::new(sequence)),
                endpoint_state: PaddedEndpointState {
                    producer_closed: AtomicBool::new(false),
                    consumer_closed: AtomicBool::new(false),
                },
                slots: slots.into_boxed_slice(),
            }),
        })
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    pub fn layout(&self) -> RingLayout {
        let inner = &*self.inner;
        let base = std::ptr::from_ref(inner) as usize;
        let producer = std::ptr::addr_of!(inner.published_head) as usize;
        let consumer = std::ptr::addr_of!(inner.consumed_tail) as usize;

        RingLayout {
            cursor_alignment: std::mem::align_of::<PaddedSequence>(),
            producer_sequence_offset: producer - base,
            consumer_sequence_offset: consumer - base,
        }
    }

    pub fn split(self) -> (Producer<T, N>, Consumer<T, N>) {
        let Self { inner } = self;
        let sequence = inner.published_head.0.load(Ordering::Relaxed);
        let consumer_inner = Arc::clone(&inner);

        (
            Producer {
                inner,
                next: sequence,
                cached_tail: sequence,
                _not_sync: PhantomData,
            },
            Consumer {
                inner: consumer_inner,
                next: sequence,
                cached_head: sequence,
                _not_sync: PhantomData,
            },
        )
    }
}

pub(crate) fn validate_capacity<const N: usize>() -> Result<(), RingConfigError> {
    if N == 0 {
        return Err(RingConfigError::ZeroCapacity);
    }
    if !N.is_power_of_two() {
        return Err(RingConfigError::NotPowerOfTwo { capacity: N });
    }
    if (N as u128) >= (1_u128 << 63) {
        return Err(RingConfigError::SequenceAmbiguous { capacity: N });
    }
    Ok(())
}

pub struct Producer<T, const N: usize> {
    inner: Arc<Inner<T>>,
    next: u64,
    cached_tail: u64,
    _not_sync: PhantomData<Cell<()>>,
}

impl<T, const N: usize> Producer<T, N> {
    pub const fn capacity(&self) -> usize {
        N
    }

    pub const fn next_sequence(&self) -> u64 {
        self.next
    }

    /// Claims the producer's next vacant slot without publishing it.
    ///
    /// The returned capability holds the producer's exclusive mutable borrow,
    /// so no shared reservation flag is required. Cancellation and drop leave
    /// every cursor and slot unchanged.
    pub fn try_reserve(&mut self) -> Result<VacantSlot<'_, T, N>, TryReserveError> {
        if self
            .inner
            .endpoint_state
            .consumer_closed
            .load(Ordering::Acquire)
        {
            return Err(TryReserveError::Disconnected);
        }

        let mut distance = self.next.wrapping_sub(self.cached_tail);
        if distance > N as u64 {
            return Err(TryReserveError::Invariant(
                RingInvariantError::CursorDistanceExceedsCapacity {
                    published_head: self.next,
                    consumed_tail: self.cached_tail,
                    capacity: N,
                },
            ));
        }

        if distance == N as u64 {
            self.cached_tail = self.inner.consumed_tail.0.load(Ordering::Acquire);
            distance = self.next.wrapping_sub(self.cached_tail);
            if distance > N as u64 {
                return Err(TryReserveError::Invariant(
                    RingInvariantError::CursorDistanceExceedsCapacity {
                        published_head: self.next,
                        consumed_tail: self.cached_tail,
                        capacity: N,
                    },
                ));
            }
            if distance == N as u64 {
                return Err(TryReserveError::Full);
            }
        }

        let sequence = self.next;
        let index = (sequence as usize) & (N - 1);
        let slot = self
            .inner
            .slots
            .get(index)
            .ok_or(TryReserveError::Invariant(
                RingInvariantError::SlotIndexOutOfBounds {
                    sequence,
                    index,
                    slot_count: self.inner.slots.len(),
                },
            ))?;
        Ok(VacantSlot {
            slot,
            published_head: &self.inner.published_head.0,
            next: &mut self.next,
            sequence,
            _not_send_sync: PhantomData,
        })
    }

    pub fn try_push(&mut self, value: T) -> Result<(), TryPushError<T>> {
        if self
            .inner
            .endpoint_state
            .consumer_closed
            .load(Ordering::Acquire)
        {
            return Err(TryPushError::Disconnected(value));
        }

        if self.next.wrapping_sub(self.cached_tail) >= N as u64 {
            self.cached_tail = self.inner.consumed_tail.0.load(Ordering::Acquire);
            if self.next.wrapping_sub(self.cached_tail) >= N as u64 {
                return Err(TryPushError::Full(value));
            }
        }

        let index = (self.next as usize) & (N - 1);
        self.inner.slots[index].write(value);
        self.next = self.next.wrapping_add(1);
        self.inner
            .published_head
            .0
            .store(self.next, Ordering::Release);
        Ok(())
    }

    pub fn is_consumer_closed(&self) -> bool {
        self.inner
            .endpoint_state
            .consumer_closed
            .load(Ordering::Acquire)
    }

    pub(crate) fn close(&mut self) {
        self.inner
            .endpoint_state
            .producer_closed
            .store(true, Ordering::Release);
    }
}

impl<T, const N: usize> Drop for Producer<T, N> {
    fn drop(&mut self) {
        self.close();
    }
}

/// Exclusive producer-local capability for one vacant ring slot.
///
/// Dropping or cancelling the capability is a no-op. `publish` is infallible
/// after issuance and is the ring publication linearization point.
///
/// The capability is intentionally neither `Send` nor `Sync`:
///
/// ```compile_fail
/// fn require_send<T: Send>() {}
/// require_send::<aegis_event::VacantSlot<'static, u64, 1>>();
/// ```
///
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<aegis_event::VacantSlot<'static, u64, 1>>();
/// ```
#[must_use = "dropping a vacant slot cancels the reservation"]
pub struct VacantSlot<'producer, T, const N: usize> {
    slot: &'producer Slot<T>,
    published_head: &'producer AtomicU64,
    next: &'producer mut u64,
    sequence: u64,
    _not_send_sync: PhantomData<(Rc<()>, [(); N])>,
}

impl<T, const N: usize> VacantSlot<'_, T, N> {
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn cancel(self) {}

    pub fn publish(self, value: T) {
        let Self {
            slot,
            published_head,
            next: producer_next,
            sequence,
            _not_send_sync: _,
        } = self;
        let next = sequence.wrapping_add(1);

        slot.write(value);
        *producer_next = next;
        published_head.store(next, Ordering::Release);
    }

    /// Test-only interruption point after slot initialization and before the
    /// published-head Release store. `T: Copy` guarantees that the deliberately
    /// unreachable test value has no destructor to leak during fault closure.
    #[cfg(all(test, not(feature = "loom")))]
    pub(crate) fn publish_then_panic_before_head(self, value: T) -> !
    where
        T: Copy,
    {
        let Self {
            slot,
            published_head: _,
            next: _,
            sequence: _,
            _not_send_sync: _,
        } = self;
        slot.write(value);
        panic!("injected ring fault after slot write and before head publication");
    }
}

pub struct Consumer<T, const N: usize> {
    inner: Arc<Inner<T>>,
    next: u64,
    cached_head: u64,
    _not_sync: PhantomData<Cell<()>>,
}

impl<T, const N: usize> Consumer<T, N> {
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Claims the next published slot without reclaiming its capacity.
    ///
    /// The validation copy is available through `OccupiedSlot::value`. Only
    /// `OccupiedSlot::commit` moves the original value and advances the tail.
    pub fn try_claim(&mut self) -> Result<OccupiedSlot<'_, T, N>, TryClaimError>
    where
        T: Copy,
    {
        let (sequence, index) = match self.next_occupied_slot() {
            Ok(position) => position,
            Err(error @ TryClaimError::Invariant(_)) => {
                self.close();
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let slot = match self.inner.slots.get(index) {
            Some(slot) => slot,
            None => {
                self.close();
                return Err(TryClaimError::Invariant(
                    RingInvariantError::SlotIndexOutOfBounds {
                        sequence,
                        index,
                        slot_count: self.inner.slots.len(),
                    },
                ));
            }
        };
        let value = slot.copy_value();

        Ok(OccupiedSlot {
            slot,
            consumed_tail: &self.inner.consumed_tail.0,
            consumer_closed: &self.inner.endpoint_state.consumer_closed,
            next: &mut self.next,
            sequence,
            value,
            _not_send_sync: PhantomData,
        })
    }

    fn next_occupied_slot(&mut self) -> Result<(u64, usize), TryClaimError> {
        let mut available = self.cached_head.wrapping_sub(self.next);
        if available > N as u64 {
            return Err(TryClaimError::Invariant(
                RingInvariantError::CursorDistanceExceedsCapacity {
                    published_head: self.cached_head,
                    consumed_tail: self.next,
                    capacity: N,
                },
            ));
        }

        if available == 0 {
            self.cached_head = self.inner.published_head.0.load(Ordering::Acquire);
            available = self.cached_head.wrapping_sub(self.next);
            if available > N as u64 {
                return Err(TryClaimError::Invariant(
                    RingInvariantError::CursorDistanceExceedsCapacity {
                        published_head: self.cached_head,
                        consumed_tail: self.next,
                        capacity: N,
                    },
                ));
            }

            if available == 0 {
                if self
                    .inner
                    .endpoint_state
                    .producer_closed
                    .load(Ordering::Acquire)
                {
                    // The producer publishes every claimed permit before its
                    // ordered close. Reloading after closure prevents the final
                    // publication from being hidden behind an earlier head.
                    self.cached_head = self.inner.published_head.0.load(Ordering::Acquire);
                    available = self.cached_head.wrapping_sub(self.next);
                    if available > N as u64 {
                        return Err(TryClaimError::Invariant(
                            RingInvariantError::CursorDistanceExceedsCapacity {
                                published_head: self.cached_head,
                                consumed_tail: self.next,
                                capacity: N,
                            },
                        ));
                    }
                    if available == 0 {
                        return Err(TryClaimError::Disconnected);
                    }
                } else {
                    return Err(TryClaimError::Empty);
                }
            }
        }

        let sequence = self.next;
        let index = (sequence as usize) & (N - 1);
        Ok((sequence, index))
    }

    pub fn try_pop(&mut self) -> Result<T, TryPopError> {
        if self.next == self.cached_head {
            self.cached_head = self.inner.published_head.0.load(Ordering::Acquire);
            if self.next == self.cached_head {
                if self
                    .inner
                    .endpoint_state
                    .producer_closed
                    .load(Ordering::Acquire)
                {
                    // Observing producer closure also observes every preceding
                    // publication. Reload the head so closure cannot hide the
                    // producer's final value behind an earlier empty read.
                    self.cached_head = self.inner.published_head.0.load(Ordering::Acquire);
                    if self.next == self.cached_head {
                        return Err(TryPopError::Disconnected);
                    }
                } else {
                    return Err(TryPopError::Empty);
                }
            }
        }

        let index = (self.next as usize) & (N - 1);
        let value = self.inner.slots[index].read();
        self.next = self.next.wrapping_add(1);
        self.inner
            .consumed_tail
            .0
            .store(self.next, Ordering::Release);
        Ok(value)
    }

    pub fn is_producer_closed(&self) -> bool {
        self.inner
            .endpoint_state
            .producer_closed
            .load(Ordering::Acquire)
    }

    pub(crate) fn close(&self) {
        self.inner
            .endpoint_state
            .consumer_closed
            .store(true, Ordering::Release);
    }

    #[cfg(all(test, not(feature = "loom")))]
    pub(crate) fn inject_cached_head_for_test(&mut self, cached_head: u64) {
        self.cached_head = cached_head;
    }
}

impl<T, const N: usize> Drop for Consumer<T, N> {
    fn drop(&mut self) {
        self.close();
    }
}

/// Exclusive consumer-local claim over one initialized `Copy` slot.
///
/// `value` returns a validation copy without changing ring state. Dropping or
/// cancelling the claim leaves the slot published. `commit` moves the original
/// slot value and Release-publishes capacity reclamation.
///
/// The claim is intentionally neither `Send` nor `Sync`:
///
/// ```compile_fail
/// fn require_send<T: Send>() {}
/// require_send::<aegis_event::OccupiedSlot<'static, u64, 1>>();
/// ```
///
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<aegis_event::OccupiedSlot<'static, u64, 1>>();
/// ```
#[must_use = "an occupied slot reclaims capacity only when committed"]
pub struct OccupiedSlot<'consumer, T: Copy, const N: usize> {
    slot: &'consumer Slot<T>,
    consumed_tail: &'consumer AtomicU64,
    consumer_closed: &'consumer AtomicBool,
    next: &'consumer mut u64,
    sequence: u64,
    value: T,
    _not_send_sync: PhantomData<(Rc<()>, [(); N])>,
}

impl<T: Copy, const N: usize> OccupiedSlot<'_, T, N> {
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn value(&self) -> T {
        self.value
    }

    pub(crate) fn close_consumer(self) {
        let Self {
            consumer_closed,
            slot: _,
            consumed_tail: _,
            next: _,
            sequence: _,
            value: _,
            _not_send_sync: _,
        } = self;
        consumer_closed.store(true, Ordering::Release);
    }

    pub fn commit(self) -> T {
        let Self {
            slot,
            consumed_tail,
            consumer_closed: _,
            next: consumer_next,
            sequence,
            value: _,
            _not_send_sync: _,
        } = self;
        let next = sequence.wrapping_add(1);

        let value = slot.read();
        *consumer_next = next;
        consumed_tail.store(next, Ordering::Release);
        value
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingLayout {
    pub cursor_alignment: usize,
    pub producer_sequence_offset: usize,
    pub consumer_sequence_offset: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingConfigError {
    ZeroCapacity,
    NotPowerOfTwo { capacity: usize },
    SequenceAmbiguous { capacity: usize },
}

impl fmt::Display for RingConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCapacity => write!(f, "SPSC ring capacity must be non-zero"),
            Self::NotPowerOfTwo { capacity } => {
                write!(f, "SPSC ring capacity {capacity} is not a power of two")
            }
            Self::SequenceAmbiguous { capacity } => {
                write!(f, "SPSC ring capacity {capacity} must be smaller than 2^63")
            }
        }
    }
}

impl Error for RingConfigError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingInvariantError {
    CursorDistanceExceedsCapacity {
        published_head: u64,
        consumed_tail: u64,
        capacity: usize,
    },
    SlotIndexOutOfBounds {
        sequence: u64,
        index: usize,
        slot_count: usize,
    },
}

impl fmt::Display for RingInvariantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CursorDistanceExceedsCapacity {
                published_head,
                consumed_tail,
                capacity,
            } => write!(
                f,
                "SPSC cursor distance from consumed {consumed_tail} to published {published_head} exceeds capacity {capacity}"
            ),
            Self::SlotIndexOutOfBounds {
                sequence,
                index,
                slot_count,
            } => write!(
                f,
                "SPSC sequence {sequence} selected slot {index} outside slot count {slot_count}"
            ),
        }
    }
}

impl Error for RingInvariantError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TryReserveError {
    Full,
    Disconnected,
    Invariant(RingInvariantError),
}

impl fmt::Display for TryReserveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "SPSC ring is full"),
            Self::Disconnected => write!(f, "SPSC consumer is disconnected"),
            Self::Invariant(error) => write!(f, "SPSC reservation invariant failed: {error}"),
        }
    }
}

impl Error for TryReserveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Invariant(error) => Some(error),
            Self::Full | Self::Disconnected => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TryClaimError {
    Empty,
    Disconnected,
    Invariant(RingInvariantError),
}

impl fmt::Display for TryClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "SPSC ring is empty"),
            Self::Disconnected => write!(f, "SPSC producer is disconnected"),
            Self::Invariant(error) => write!(f, "SPSC claim invariant failed: {error}"),
        }
    }
}

impl Error for TryClaimError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Invariant(error) => Some(error),
            Self::Empty | Self::Disconnected => None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum TryPushError<T> {
    Full(T),
    Disconnected(T),
}

impl<T> TryPushError<T> {
    pub fn into_inner(self) -> T {
        match self {
            Self::Full(value) | Self::Disconnected(value) => value,
        }
    }
}

impl<T> fmt::Display for TryPushError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full(_) => write!(f, "SPSC ring is full"),
            Self::Disconnected(_) => write!(f, "SPSC consumer is disconnected"),
        }
    }
}

impl<T: fmt::Debug> Error for TryPushError<T> {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TryPopError {
    Empty,
    Disconnected,
}

impl fmt::Display for TryPopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "SPSC ring is empty"),
            Self::Disconnected => write!(f, "SPSC producer is disconnected"),
        }
    }
}

impl Error for TryPopError {}

#[cfg(all(test, not(feature = "loom")))]
mod tests {
    use super::{
        RingInvariantError, SpscRing, TryClaimError, TryPopError, TryPushError, TryReserveError,
    };

    #[test]
    fn modular_sequence_wrap_preserves_fifo_and_capacity() {
        let ring = SpscRing::<u64, 4>::new_with_sequence(u64::MAX - 1).expect("valid wrapped ring");
        let (mut producer, mut consumer) = ring.split();

        for value in 0..4 {
            producer.try_push(value).expect("ring has capacity");
        }
        assert_eq!(producer.try_push(99), Err(TryPushError::Full(99)));
        for value in 0..4 {
            assert_eq!(consumer.try_pop(), Ok(value));
        }
        assert_eq!(consumer.try_pop(), Err(TryPopError::Empty));
    }

    #[test]
    fn permit_and_claim_sequences_wrap_together() {
        let ring = SpscRing::<u64, 1>::new_with_sequence(u64::MAX).expect("valid wrapped ring");
        let (mut producer, mut consumer) = ring.split();

        let permit = producer.try_reserve().expect("wrapped slot is vacant");
        assert_eq!(permit.sequence(), u64::MAX);
        permit.publish(1);
        assert_eq!(producer.next_sequence(), 0);

        let claim = consumer.try_claim().expect("wrapped slot is occupied");
        assert_eq!(claim.sequence(), u64::MAX);
        assert_eq!(claim.value(), 1);
        assert_eq!(claim.commit(), 1);

        let permit = producer.try_reserve().expect("slot was reclaimed");
        assert_eq!(permit.sequence(), 0);
        permit.publish(2);
        let claim = consumer.try_claim().expect("post-wrap value is visible");
        assert_eq!(claim.sequence(), 0);
        assert_eq!(claim.commit(), 2);
    }

    #[test]
    fn reservation_and_claim_report_typed_cursor_invariant_errors() {
        let ring = SpscRing::<u64, 2>::new().expect("valid ring");
        let (mut producer, mut consumer) = ring.split();

        producer.cached_tail = 1;
        let reserve_error = match producer.try_reserve() {
            Ok(_) => panic!("corrupt producer cursor must not reserve"),
            Err(error) => error,
        };
        assert_eq!(
            reserve_error,
            TryReserveError::Invariant(RingInvariantError::CursorDistanceExceedsCapacity {
                published_head: 0,
                consumed_tail: 1,
                capacity: 2,
            })
        );

        consumer.cached_head = 3;
        let claim_error = match consumer.try_claim() {
            Ok(_) => panic!("corrupt consumer cursor must not claim"),
            Err(error) => error,
        };
        assert_eq!(
            claim_error,
            TryClaimError::Invariant(RingInvariantError::CursorDistanceExceedsCapacity {
                published_head: 3,
                consumed_tail: 0,
                capacity: 2,
            })
        );
    }

    #[test]
    fn explicit_endpoint_close_is_idempotent() {
        let ring = SpscRing::<u64, 1>::new().expect("valid ring");
        let (mut producer, mut consumer) = ring.split();
        producer.close();
        producer.close();
        assert!(matches!(
            consumer.try_claim(),
            Err(TryClaimError::Disconnected)
        ));

        let ring = SpscRing::<u64, 1>::new().expect("valid ring");
        let (mut producer, consumer) = ring.split();
        consumer.close();
        consumer.close();
        assert!(matches!(
            producer.try_reserve(),
            Err(TryReserveError::Disconnected)
        ));
    }

    #[test]
    fn occupied_slot_can_close_consumer_without_reclaiming_the_slot() {
        let ring = SpscRing::<u64, 1>::new().expect("valid ring");
        let (mut producer, mut consumer) = ring.split();
        producer.try_reserve().expect("initial slot").publish(5);

        let claim = consumer.try_claim().expect("published slot");
        claim.close_consumer();
        assert!(matches!(
            producer.try_reserve(),
            Err(TryReserveError::Disconnected)
        ));
        assert_eq!(
            consumer.try_claim().expect("tail was not advanced").value(),
            5
        );
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::{SpscRing, TryClaimError, TryPopError, TryPushError, TryReserveError};
    use loom::thread;

    #[test]
    fn loom_publication_reuse_and_shutdown() {
        loom::model(|| {
            let ring = SpscRing::<u64, 1>::new().expect("valid model ring");
            let (mut producer, mut consumer) = ring.split();
            producer.try_push(1).expect("initial slot is free");

            let producer_thread = thread::spawn(move || {
                let mut pending = 2;
                loop {
                    match producer.try_push(pending) {
                        Ok(()) => break,
                        Err(TryPushError::Full(value)) => {
                            pending = value;
                            thread::yield_now();
                        }
                        Err(TryPushError::Disconnected(_)) => {
                            panic!("model consumer disconnected")
                        }
                    }
                }
            });

            let consumer_thread = thread::spawn(move || {
                for expected in [1, 2] {
                    loop {
                        match consumer.try_pop() {
                            Ok(actual) => {
                                assert_eq!(actual, expected);
                                break;
                            }
                            Err(TryPopError::Empty) => thread::yield_now(),
                            Err(TryPopError::Disconnected) => {
                                panic!("model producer disconnected before drain")
                            }
                        }
                    }
                }

                loop {
                    match consumer.try_pop() {
                        Err(TryPopError::Disconnected) => break,
                        Err(TryPopError::Empty) => thread::yield_now(),
                        Ok(value) => panic!("unexpected extra model value {value}"),
                    }
                }
            });

            producer_thread.join().expect("model producer succeeds");
            consumer_thread.join().expect("model consumer succeeds");
        });
    }

    #[test]
    fn loom_permit_cancel_claim_drop_commit_reuse_and_wrap() {
        loom::model(|| {
            let ring =
                SpscRing::<u64, 1>::new_with_sequence(u64::MAX).expect("valid wrapped model ring");
            let (mut producer, mut consumer) = ring.split();

            drop(producer.try_reserve().expect("initial dropped permit"));
            assert_eq!(producer.next_sequence(), u64::MAX);
            producer.try_reserve().expect("initial permit").cancel();
            assert_eq!(producer.next_sequence(), u64::MAX);

            let permit = producer.try_reserve().expect("cancelled slot is vacant");
            assert_eq!(permit.sequence(), u64::MAX);
            permit.publish(1);
            assert_eq!(producer.next_sequence(), 0);

            let claim = consumer.try_claim().expect("published slot is claimable");
            assert_eq!(claim.sequence(), u64::MAX);
            assert_eq!(claim.value(), 1);
            drop(claim);
            assert_eq!(producer.try_reserve().err(), Some(TryReserveError::Full));

            let claim = consumer.try_claim().expect("dropped claim retries");
            assert_eq!(claim.commit(), 1);
            let permit = producer.try_reserve().expect("commit reclaimed slot");
            assert_eq!(permit.sequence(), 0);
            permit.publish(2);
            assert_eq!(consumer.try_claim().expect("second claim").commit(), 2);
        });
    }

    #[test]
    fn loom_reserved_publication_may_race_consumer_close() {
        loom::model(|| {
            let ring = SpscRing::<u64, 1>::new().expect("valid model ring");
            let (mut producer, consumer) = ring.split();
            let permit = producer
                .try_reserve()
                .expect("permit is irrevocable after issuance");

            let close_thread = thread::spawn(move || drop(consumer));
            thread::yield_now();
            permit.publish(1);
            drop(producer);
            close_thread.join().expect("consumer close succeeds");
        });
    }

    #[test]
    fn loom_claim_withholds_reuse_until_commit_and_drains_close() {
        loom::model(|| {
            let ring = SpscRing::<u64, 1>::new().expect("valid model ring");
            let (mut producer, mut consumer) = ring.split();

            let producer_thread = thread::spawn(move || {
                producer.try_reserve().expect("initial slot").publish(1);

                loop {
                    match producer.try_reserve() {
                        Ok(permit) => {
                            permit.publish(2);
                            break;
                        }
                        Err(TryReserveError::Full) => thread::yield_now(),
                        Err(error) => panic!("unexpected model reservation error: {error}"),
                    }
                }
            });

            let consumer_thread = thread::spawn(move || {
                let first = loop {
                    match consumer.try_claim() {
                        Ok(claim) => break claim,
                        Err(TryClaimError::Empty) => thread::yield_now(),
                        Err(error) => panic!("unexpected first model claim error: {error}"),
                    }
                };
                assert_eq!(first.value(), 1);
                drop(first);

                let first = consumer.try_claim().expect("dropped claim retries");
                assert_eq!(first.commit(), 1);

                let second = loop {
                    match consumer.try_claim() {
                        Ok(claim) => break claim,
                        Err(TryClaimError::Empty) => thread::yield_now(),
                        Err(error) => panic!("unexpected second model claim error: {error}"),
                    }
                };
                assert_eq!(second.value(), 2);
                assert_eq!(second.commit(), 2);

                loop {
                    match consumer.try_claim() {
                        Err(TryClaimError::Disconnected) => break,
                        Err(TryClaimError::Empty) => thread::yield_now(),
                        Err(error) => panic!("unexpected close model claim error: {error}"),
                        Ok(_) => panic!("unexpected extra model slot"),
                    }
                }
            });

            producer_thread.join().expect("model producer succeeds");
            consumer_thread.join().expect("model consumer succeeds");
        });
    }
}
