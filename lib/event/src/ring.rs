//! Cache-padded, bounded single-producer/single-consumer ring.
//!
//! # Safety invariants
//!
//! - `SpscRing::split` creates exactly one non-cloneable producer and consumer.
//! - Endpoint mutation requires `&mut self`; endpoint marker fields make them
//!   `!Sync`, while `T: Send` permits ownership transfer to another thread.
//! - The producer is the only writer to a free slot. Its `Release` publication
//!   follows initialization, and the consumer reads only after an `Acquire`.
//! - The consumer moves each value once. Its `Release` consumption follows the
//!   move, and the producer reuses a slot only after an `Acquire`.
//! - Published minus consumed distance never exceeds capacity. Capacity is a
//!   power of two below `2^63`, making modular sequence distance unambiguous.
//! - The final `Inner` drop runs only after both endpoints are gone and drops
//!   exactly the still-published range. An invalid distance panics in debug and
//!   leaks in release rather than dereferencing an unproven slot.

use std::{cell::Cell, error::Error, fmt, marker::PhantomData, mem::MaybeUninit};

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

    fn new_with_sequence(sequence: u64) -> Result<Self, RingConfigError> {
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

fn validate_capacity<const N: usize>() -> Result<(), RingConfigError> {
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
}

impl<T, const N: usize> Drop for Producer<T, N> {
    fn drop(&mut self) {
        self.inner
            .endpoint_state
            .producer_closed
            .store(true, Ordering::Release);
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
}

impl<T, const N: usize> Drop for Consumer<T, N> {
    fn drop(&mut self) {
        self.inner
            .endpoint_state
            .consumer_closed
            .store(true, Ordering::Release);
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
    use super::{SpscRing, TryPopError, TryPushError};

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
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::{SpscRing, TryPopError, TryPushError};
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
}
