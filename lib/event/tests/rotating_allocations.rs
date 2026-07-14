//! Thread-local allocation check for the native ADR-0010 rotating hot path.
//!
//! # Safety invariants
//!
//! - The test allocator delegates every operation to `System` with the exact
//!   layout and pointer supplied by the caller.
//! - Counting uses const-initialized thread-local `Cell`s and performs no heap
//!   allocation, recursion, pointer access, or ownership change.
//! - Tracking is enabled only on the test thread around warmed admit/claim/
//!   commit and rotation/rebind work; channel construction, assertions, and
//!   drop are outside the measured boundary.

#![cfg(all(not(miri), not(feature = "loom")))]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use aegis_event::{
    RotatingAdmissionChannel, SlabPageConfig, TryRotatingAdmitError, TryRotatingConsumeError,
};

struct ThreadTrackingAllocator;

thread_local! {
    static TRACK_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    static ALLOCATION_COUNT: Cell<usize> = const { Cell::new(0) };
}

fn record_allocation() {
    let tracking = TRACK_ALLOCATIONS.try_with(Cell::get).unwrap_or(false);
    if tracking {
        let _ = ALLOCATION_COUNT.try_with(|count| count.set(count.get().saturating_add(1)));
    }
}

// SAFETY: Each method delegates unchanged pointer/layout semantics to the
// process `System` allocator. The additional thread-local accounting neither
// dereferences nor retains allocation pointers.
unsafe impl GlobalAlloc for ThreadTrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: The caller supplies the `GlobalAlloc` layout contract, which
        // is forwarded unchanged to `System`.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: The caller supplies the `GlobalAlloc` layout contract, which
        // is forwarded unchanged to `System`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: The pointer/layout pair came from this allocator, which
        // delegates allocation unchanged to `System`.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation();
        // SAFETY: The pointer/layout pair came from `System`; `new_size` is
        // forwarded unchanged under the `GlobalAlloc::realloc` contract.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: ThreadTrackingAllocator = ThreadTrackingAllocator;

fn config(descriptor_capacity: usize) -> SlabPageConfig {
    SlabPageConfig {
        arena_id: 3,
        arena_generation: 0,
        byte_capacity: 64 * descriptor_capacity.max(1),
        descriptor_capacity,
        first_sequence: 7,
    }
}

fn start_tracking() {
    let _ = crc32c::crc32c(b"warmup");
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(true));
    ALLOCATION_COUNT.with(|count| count.set(0));
}

fn stop_tracking() -> usize {
    let allocations = ALLOCATION_COUNT.with(Cell::get);
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
    allocations
}

/// Admit + claim + commit with a forced rotation (descriptor_capacity = 1).
#[test]
fn warmed_rotating_admit_claim_commit_with_rotation_allocates_nothing() {
    let channel = RotatingAdmissionChannel::<8, 4>::new(config(1)).expect("bounded channel");
    let (mut producer, mut consumer) = channel.split();

    start_tracking();

    let t0 = producer
        .try_admit(b"epoch-0", 1, 0)
        .expect("epoch 0 admit fits");
    let t1 = producer
        .try_admit(b"epoch-1", 1, 0)
        .expect("rotation + epoch 1 admit");
    let f0 = consumer.try_next().expect("epoch 0 frame");
    assert_eq!(f0.payload(), b"epoch-0");
    let c0 = f0.commit();
    let f1 = consumer.try_next().expect("epoch 1 frame");
    assert_eq!(f1.payload(), b"epoch-1");
    let c1 = f1.commit();

    let allocations = stop_tracking();
    assert_eq!(t0.sequence(), 7);
    assert_eq!(t1.sequence(), 8);
    assert_eq!(c0.sequence(), 7);
    assert_eq!(c1.sequence(), 8);
    assert_eq!(
        allocations, 0,
        "rotating admit/claim/commit allocated unexpectedly"
    );
}

/// Full pool → typed quota refusal must not allocate or mutate for the refused call.
#[test]
fn rotating_page_quota_exhausted_allocates_nothing() {
    let channel = RotatingAdmissionChannel::<8, 2>::new(config(1)).expect("bounded channel");
    let (mut producer, _consumer) = channel.split();
    producer
        .try_admit(b"slot-0", 1, 0)
        .expect("epoch 0 occupies slot 0");
    producer
        .try_admit(b"slot-1", 1, 0)
        .expect("epoch 1 occupies slot 1");

    start_tracking();
    let result = producer.try_admit(b"refused", 1, 0);
    let allocations = stop_tracking();

    assert!(matches!(
        result,
        Err(TryRotatingAdmitError::PageQuotaExhausted {
            live_epochs: 2,
            pool: 2
        })
    ));
    assert_eq!(allocations, 0, "quota refusal allocated unexpectedly");
    assert_eq!(
        producer.epoch(),
        1,
        "refused rotation must not advance epoch"
    );
}

/// More epochs than pool capacity rebinds released slots without allocating.
#[test]
fn multi_epoch_pool_rebind_allocates_nothing_after_construction() {
    let channel = RotatingAdmissionChannel::<16, 2>::new(config(1)).expect("bounded channel");
    let (mut producer, mut consumer) = channel.split();

    start_tracking();

    for i in 0u8..6 {
        let payload = [i; 8];
        loop {
            match producer.try_admit(&payload, 1, 0) {
                Ok(_) => break,
                Err(TryRotatingAdmitError::PageQuotaExhausted { .. }) => {
                    let frame = consumer.try_next().expect("drain lagging consumer");
                    frame.commit();
                }
                Err(error) => panic!("unexpected admit error: {error}"),
            }
        }
    }
    producer.finish().expect("clean finish");
    loop {
        match consumer.try_next() {
            Ok(frame) => {
                frame.commit();
            }
            Err(TryRotatingConsumeError::CleanEnd) => break,
            Err(TryRotatingConsumeError::Empty) => continue,
            Err(error) => panic!("unexpected drain error: {error}"),
        }
    }

    let allocations = stop_tracking();
    assert_eq!(consumer.total_committed(), 6);
    assert_eq!(
        allocations, 0,
        "multi-epoch rebind path allocated unexpectedly after construction"
    );
}
