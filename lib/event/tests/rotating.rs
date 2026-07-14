//! Cross-thread stress for the ADR-0010 rotating admission prototype: many
//! page rotations under concurrent produce/consume, exercised natively and
//! under the ASan/TSan CI lanes. Asserts no loss, duplication, reordering,
//! or payload mismatch across epoch seams, quota backpressure included.
//!
//! Disabled under `--features loom`: `RotatingAdmissionChannel` swaps in Loom
//! atomics, which must only run inside `loom::model` (see unit `loom_tests`).
//! Native `std::thread` stress here would panic outside a Loom model. Same
//! gate as `admission.rs` / `published_slab.rs` / `spsc.rs`.

#![cfg(not(feature = "loom"))]

use std::thread;

use aegis_event::{
    RotatingAdmissionChannel, SlabPageConfig, TryRotatingAdmitError, TryRotatingConsumeError,
};

fn payload_for(i: u32) -> Vec<u8> {
    // Variable length 1..=13 so rotations land at byte and descriptor
    // boundaries alike; contents derive from the index for exact checking.
    let len = (i % 13 + 1) as usize;
    (0..len).map(|j| (i as u8).wrapping_add(j as u8)).collect()
}

#[test]
fn cross_thread_stress_rotates_losslessly_under_quota_backpressure() {
    const EVENTS: u32 = 10_000;
    let config = SlabPageConfig {
        arena_id: 42,
        arena_generation: 0,
        byte_capacity: 128,
        descriptor_capacity: 8,
        first_sequence: 100,
    };
    let channel = RotatingAdmissionChannel::<8, 4>::new(config).expect("stress channel");
    let (mut producer, mut consumer) = channel.split();

    let producer_thread = thread::spawn(move || {
        let mut rotations_refused: u64 = 0;
        for i in 0..EVENTS {
            let payload = payload_for(i);
            loop {
                match producer.try_admit(&payload, 1, 0) {
                    Ok(token) => {
                        assert_eq!(token.sequence(), 100 + u64::from(i));
                        break;
                    }
                    Err(TryRotatingAdmitError::RingFull) => thread::yield_now(),
                    Err(TryRotatingAdmitError::PageQuotaExhausted { .. }) => {
                        rotations_refused += 1;
                        thread::yield_now();
                    }
                    Err(error) => panic!("producer failed at event {i}: {error}"),
                }
            }
        }
        producer.finish().expect("clean finish");
        rotations_refused
    });

    let consumer_thread = thread::spawn(move || {
        let mut next: u32 = 0;
        loop {
            match consumer.try_next() {
                Ok(frame) => {
                    assert_eq!(
                        frame.descriptor().sequence,
                        100 + u64::from(next),
                        "in-order delivery across epoch seams"
                    );
                    assert_eq!(frame.payload(), payload_for(next), "payload integrity");
                    frame.commit();
                    next += 1;
                }
                Err(TryRotatingConsumeError::Empty) => thread::yield_now(),
                Err(TryRotatingConsumeError::CleanEnd) => break,
                Err(error) => panic!("consumer failed at event {next}: {error}"),
            }
        }
        assert_eq!(next, EVENTS, "every admitted event was committed");
        (consumer.epoch(), consumer.total_committed())
    });

    let _rotations_refused = producer_thread.join().expect("producer joins");
    let (final_epoch, committed) = consumer_thread.join().expect("consumer joins");
    assert_eq!(committed, EVENTS as usize);
    // 10k events over pages holding at most 8 descriptors: rotation happened
    // many times and the consumer followed every seam.
    assert!(final_epoch >= u64::from(EVENTS) / 8 - 1);
}

#[test]
fn slow_consumer_bounds_live_pages_at_the_pool_capacity() {
    let config = SlabPageConfig {
        arena_id: 42,
        arena_generation: 0,
        byte_capacity: 1024,
        descriptor_capacity: 1,
        first_sequence: 0,
    };
    let channel = RotatingAdmissionChannel::<16, 2>::new(config).expect("channel");
    let (mut producer, mut consumer) = channel.split();

    // descriptor_capacity = 1 and P = 2: two admissions fill both slots.
    producer.try_admit(b"e0", 1, 0).expect("epoch 0");
    producer.try_admit(b"e1", 1, 0).expect("epoch 1");
    assert!(matches!(
        producer.try_admit(b"e2", 1, 0),
        Err(TryRotatingAdmitError::PageQuotaExhausted {
            live_epochs: 2,
            pool: 2
        })
    ));

    // Crossing one seam releases epoch 0 and unblocks exactly one rotation.
    let frame = consumer.try_next().expect("epoch 0 frame");
    frame.commit();
    let frame = consumer.try_next().expect("epoch 1 frame crosses the seam");
    frame.commit();
    producer
        .try_admit(b"e2", 1, 0)
        .expect("epoch 2 after release");
}
