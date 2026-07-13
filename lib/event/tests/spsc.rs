#![cfg(not(feature = "loom"))]

use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread,
};

use aegis_event::{RingConfigError, SpscRing, TryPopError, TryPushError, CACHE_LINE_BYTES};

#[test]
fn constructor_rejects_invalid_capacities() {
    assert!(matches!(
        SpscRing::<u8, 0>::new(),
        Err(RingConfigError::ZeroCapacity)
    ));
    assert!(matches!(
        SpscRing::<u8, 3>::new(),
        Err(RingConfigError::NotPowerOfTwo { capacity: 3 })
    ));
}

#[test]
fn fifo_full_and_empty_transitions_preserve_value_ownership() {
    let ring = SpscRing::<String, 2>::new().expect("valid ring");
    let (mut producer, mut consumer) = ring.split();

    assert_eq!(producer.capacity(), 2);
    assert_eq!(consumer.capacity(), 2);
    assert_eq!(consumer.try_pop(), Err(TryPopError::Empty));
    assert_eq!(producer.try_push("one".to_owned()), Ok(()));
    assert_eq!(producer.try_push("two".to_owned()), Ok(()));

    let rejected = "three".to_owned();
    assert_eq!(
        producer.try_push(rejected.clone()),
        Err(TryPushError::Full(rejected))
    );
    assert_eq!(consumer.try_pop(), Ok("one".to_owned()));
    assert_eq!(producer.try_push("three".to_owned()), Ok(()));
    assert_eq!(consumer.try_pop(), Ok("two".to_owned()));
    assert_eq!(consumer.try_pop(), Ok("three".to_owned()));
    assert_eq!(consumer.try_pop(), Err(TryPopError::Empty));
}

#[test]
fn consumer_drains_published_values_before_reporting_disconnect() {
    let ring = SpscRing::<u64, 2>::new().expect("valid ring");
    let (mut producer, mut consumer) = ring.split();

    producer.try_push(9).expect("ring has capacity");
    drop(producer);

    assert_eq!(consumer.try_pop(), Ok(9));
    assert_eq!(consumer.try_pop(), Err(TryPopError::Disconnected));
}

#[test]
fn producer_returns_the_value_when_the_consumer_is_closed() {
    let ring = SpscRing::<u64, 2>::new().expect("valid ring");
    let (mut producer, consumer) = ring.split();
    drop(consumer);

    assert_eq!(producer.try_push(11), Err(TryPushError::Disconnected(11)));
}

#[derive(Clone, Debug)]
struct DropProbe(Arc<AtomicUsize>);

impl Drop for DropProbe {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn final_ring_drop_destroys_each_unread_value_once() {
    let drops = Arc::new(AtomicUsize::new(0));
    let ring = SpscRing::<DropProbe, 4>::new().expect("valid ring");
    let (mut producer, consumer) = ring.split();

    producer
        .try_push(DropProbe(Arc::clone(&drops)))
        .expect("ring has capacity");
    producer
        .try_push(DropProbe(Arc::clone(&drops)))
        .expect("ring has capacity");

    drop(consumer);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    drop(producer);
    assert_eq!(drops.load(Ordering::Relaxed), 2);
}

#[test]
fn producer_and_consumer_sequences_are_on_distinct_cache_lines() {
    let ring = SpscRing::<u64, 2>::new().expect("valid ring");
    let layout = ring.layout();

    assert_eq!(layout.cursor_alignment, CACHE_LINE_BYTES);
    assert!(layout.consumer_sequence_offset >= layout.producer_sequence_offset + CACHE_LINE_BYTES);
    assert_eq!(
        layout.consumer_sequence_offset - layout.producer_sequence_offset,
        CACHE_LINE_BYTES
    );
}

#[test]
fn native_cross_thread_stress_has_no_loss_duplicates_or_reordering() {
    let event_count = if cfg!(miri) { 512_u64 } else { 250_000_u64 };
    let ring = SpscRing::<u64, 1024>::new().expect("valid ring");
    let (mut producer, mut consumer) = ring.split();

    let producer_thread = thread::spawn(move || {
        for sequence in 0..event_count {
            let mut pending = sequence;
            loop {
                match producer.try_push(pending) {
                    Ok(()) => break,
                    Err(TryPushError::Full(value)) => {
                        pending = value;
                        thread::yield_now();
                    }
                    Err(TryPushError::Disconnected(_)) => {
                        panic!("consumer disconnected during stress test")
                    }
                }
            }
        }
    });

    for expected in 0..event_count {
        loop {
            match consumer.try_pop() {
                Ok(actual) => {
                    assert_eq!(actual, expected);
                    break;
                }
                Err(TryPopError::Empty) => thread::yield_now(),
                Err(TryPopError::Disconnected) => {
                    panic!("producer disconnected before publishing all values")
                }
            }
        }
    }

    producer_thread.join().expect("producer thread succeeds");
    assert_eq!(consumer.try_pop(), Err(TryPopError::Disconnected));
}
