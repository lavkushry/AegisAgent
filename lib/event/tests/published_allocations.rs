//! Thread-local allocation check for the native published-prefix hot operation.
//!
//! # Safety invariants
//!
//! - The test allocator delegates every operation to `System` with the exact
//!   layout and pointer supplied by the caller.
//! - Counting uses const-initialized thread-local `Cell`s and performs no heap
//!   allocation, recursion, pointer access, or ownership change.
//! - Tracking is enabled only on the test thread around one warmed append and
//!   resolve; setup, page allocation, assertions, and drop are outside the
//!   measured boundary.

#![cfg(all(not(miri), not(feature = "loom")))]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use aegis_event::{PublishedSlabPage, SlabPageConfig, TryAdmitError, VolatileAdmissionChannel};

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

#[test]
fn warmed_native_append_and_resolve_allocate_nothing() {
    let page = PublishedSlabPage::new(SlabPageConfig {
        arena_id: 3,
        arena_generation: 5,
        byte_capacity: 64,
        descriptor_capacity: 2,
        first_sequence: 7,
    })
    .expect("bounded page");
    let (mut writer, reader) = page.split();

    // Warm architecture-specific CRC dispatch before the measured boundary.
    let _ = crc32c::crc32c(b"warmup");
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(true));
    ALLOCATION_COUNT.with(|count| count.set(0));

    let descriptor = writer
        .try_append(b"allocation-free", 1, 0)
        .expect("preallocated append fits");
    let payload = reader
        .resolve(&descriptor)
        .expect("published descriptor resolves");
    let allocations = ALLOCATION_COUNT.with(Cell::get);
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));

    assert_eq!(payload.as_ref(), b"allocation-free");
    assert_eq!(allocations, 0, "append + resolve allocated unexpectedly");
}

#[test]
fn warmed_admission_claim_validation_and_commit_allocate_nothing() {
    let channel = VolatileAdmissionChannel::<2>::new(SlabPageConfig {
        arena_id: 3,
        arena_generation: 5,
        byte_capacity: 64,
        descriptor_capacity: 2,
        first_sequence: 7,
    })
    .expect("bounded channel");
    let (mut producer, mut consumer) = channel.split();

    // Warm architecture-specific CRC dispatch before the measured boundary.
    let _ = crc32c::crc32c(b"warmup");
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(true));
    ALLOCATION_COUNT.with(|count| count.set(0));

    let token = producer
        .try_admit(b"allocation-free", 1, 0)
        .expect("preallocated admission fits");
    let frame = consumer.try_next().expect("admitted frame validates");
    let payload_matches = frame.payload() == b"allocation-free";
    let committed = frame.commit();
    let allocations = ALLOCATION_COUNT.with(Cell::get);
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));

    assert!(payload_matches);
    assert_eq!(token, committed);
    assert_eq!(
        allocations, 0,
        "admit + claim + validate + commit allocated unexpectedly"
    );
}

#[test]
fn full_admission_rejection_allocates_nothing_and_does_not_mutate_the_page() {
    let channel = VolatileAdmissionChannel::<1>::new(SlabPageConfig {
        arena_id: 3,
        arena_generation: 5,
        byte_capacity: 64,
        descriptor_capacity: 2,
        first_sequence: 7,
    })
    .expect("bounded channel");
    let (mut producer, _consumer) = channel.split();
    producer
        .try_admit(b"occupy-ring", 1, 0)
        .expect("first admission fits");
    let used_before = producer.used_bytes();
    let count_before = producer.published_count();
    let sequence_before = producer.next_sequence();

    TRACK_ALLOCATIONS.with(|tracking| tracking.set(true));
    ALLOCATION_COUNT.with(|count| count.set(0));
    let result = producer.try_admit(b"must-not-copy", 1, 0);
    let allocations = ALLOCATION_COUNT.with(Cell::get);
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));

    assert_eq!(result, Err(TryAdmitError::RingFull));
    assert_eq!(producer.used_bytes(), used_before);
    assert_eq!(producer.published_count(), count_before);
    assert_eq!(producer.next_sequence(), sequence_before);
    assert_eq!(allocations, 0, "full rejection allocated unexpectedly");
}
