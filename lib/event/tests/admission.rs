#![cfg(not(feature = "loom"))]

use std::{collections::VecDeque, thread};

use aegis_event::{
    AdmissionConfigError, RingConfigError, SlabAppendError, SlabPageBuilder, SlabPageConfig,
    TelemetryDescriptor, TryAdmitError, TryConsumeError, VolatileAdmissionChannel,
};

fn config(byte_capacity: usize, descriptor_capacity: usize) -> SlabPageConfig {
    SlabPageConfig {
        arena_id: 17,
        arena_generation: 23,
        byte_capacity,
        descriptor_capacity,
        first_sequence: 41,
    }
}

#[test]
fn construction_validates_ring_and_page_before_exposing_endpoints() {
    assert!(matches!(
        VolatileAdmissionChannel::<3>::new(config(8, 2)),
        Err(AdmissionConfigError::Ring(RingConfigError::NotPowerOfTwo {
            capacity: 3
        }))
    ));
    assert!(matches!(
        VolatileAdmissionChannel::<2>::new(config(0, 2)),
        Err(AdmissionConfigError::Slab(_))
    ));
}

#[test]
fn frame_claim_withholds_ring_capacity_until_explicit_commit() {
    let channel = VolatileAdmissionChannel::<1>::new(config(32, 3)).expect("bounded channel");
    let (mut producer, mut consumer) = channel.split();

    let first = producer
        .try_admit(b"first", 7, 1)
        .expect("first event is volatile-ring visible");
    assert_eq!(first.sequence(), 41);

    let frame = consumer.try_next().expect("first event validates");
    assert_eq!(frame.descriptor().sequence, 41);
    assert_eq!(frame.payload(), b"first");
    assert_eq!(
        producer.try_admit(b"second", 8, 2),
        Err(TryAdmitError::RingFull)
    );
    assert_eq!(producer.published_count(), 1);
    assert_eq!(producer.used_bytes(), 5);
    assert_eq!(producer.next_sequence(), 42);

    frame.commit();
    let second = producer
        .try_admit(b"second", 8, 2)
        .expect("claim commit releases ring capacity");
    assert_eq!(second.sequence(), 42);

    let frame = consumer.try_next().expect("second event validates");
    assert_eq!(frame.payload(), b"second");
    frame.commit();
    assert!(matches!(consumer.try_next(), Err(TryConsumeError::Empty)));
}

#[test]
fn dropping_a_frame_claim_retries_the_same_descriptor_without_tail_advance() {
    let channel = VolatileAdmissionChannel::<1>::new(config(16, 2)).expect("bounded channel");
    let (mut producer, mut consumer) = channel.split();
    producer.try_admit(b"retry", 1, 0).expect("event admitted");

    {
        let frame = consumer.try_next().expect("event validates");
        assert_eq!(frame.payload(), b"retry");
    }

    assert_eq!(
        producer.try_admit(b"blocked", 1, 0),
        Err(TryAdmitError::RingFull)
    );
    let frame = consumer
        .try_next()
        .expect("uncommitted claim is offered again");
    assert_eq!(frame.descriptor().sequence, 41);
    frame.commit();
}

#[test]
fn invalid_and_page_capacity_errors_leave_ring_and_page_transactional() {
    let channel = VolatileAdmissionChannel::<2>::new(config(3, 1)).expect("bounded channel");
    let (mut producer, mut consumer) = channel.split();

    assert_eq!(
        producer.try_admit(&[], 1, 0),
        Err(TryAdmitError::Slab(SlabAppendError::EmptyPayload))
    );
    assert_eq!(producer.published_count(), 0);
    assert_eq!(producer.used_bytes(), 0);
    assert_eq!(producer.next_sequence(), 41);
    assert!(matches!(consumer.try_next(), Err(TryConsumeError::Empty)));

    producer
        .try_admit(b"abc", 1, 0)
        .expect("exact page capacity fits");
    let frame = consumer.try_next().expect("event validates");
    frame.commit();

    assert_eq!(
        producer.try_admit(b"x", 1, 0),
        Err(TryAdmitError::Slab(
            SlabAppendError::DescriptorCapacityExhausted { capacity: 1 }
        ))
    );
    assert_eq!(producer.published_count(), 1);
    assert_eq!(producer.used_bytes(), 3);
    assert_eq!(producer.next_sequence(), 42);
    assert!(matches!(consumer.try_next(), Err(TryConsumeError::Empty)));
}

#[test]
fn full_ring_rejection_does_not_copy_or_consume_page_sequence_space() {
    let channel = VolatileAdmissionChannel::<1>::new(config(32, 3)).expect("bounded channel");
    let (mut producer, mut consumer) = channel.split();
    producer
        .try_admit(b"one", 1, 0)
        .expect("first event admitted");

    assert_eq!(
        producer.try_admit(b"must-not-copy", 2, 0),
        Err(TryAdmitError::RingFull)
    );
    assert_eq!(producer.published_count(), 1);
    assert_eq!(producer.used_bytes(), 3);
    assert_eq!(producer.next_sequence(), 42);

    consumer.try_next().expect("first event").commit();
    let retry = producer
        .try_admit(b"must-not-copy", 2, 0)
        .expect("same caller bytes can be retried");
    assert_eq!(retry.sequence(), 42);
    assert_eq!(producer.published_count(), 2);
    assert_eq!(producer.used_bytes(), 16);
}

#[test]
fn disconnected_consumer_rejects_before_page_mutation() {
    let channel = VolatileAdmissionChannel::<2>::new(config(16, 2)).expect("bounded channel");
    let (mut producer, consumer) = channel.split();
    drop(consumer);

    assert_eq!(
        producer.try_admit(b"never-copied", 1, 0),
        Err(TryAdmitError::ConsumerDisconnected)
    );
    assert_eq!(producer.published_count(), 0);
    assert_eq!(producer.used_bytes(), 0);
    assert_eq!(producer.next_sequence(), 41);
}

#[test]
fn explicit_finish_drains_every_event_then_reports_clean_end() {
    let channel = VolatileAdmissionChannel::<4>::new(config(32, 3)).expect("bounded channel");
    let (mut producer, mut consumer) = channel.split();
    for payload in [b"one".as_slice(), b"two", b"three"] {
        producer.try_admit(payload, 1, 0).expect("event admitted");
    }
    producer.finish().expect("open producer finishes cleanly");

    for expected in [b"one".as_slice(), b"two", b"three"] {
        let frame = consumer.try_next().expect("published event drains");
        assert_eq!(frame.payload(), expected);
        frame.commit();
    }
    assert!(matches!(
        consumer.try_next(),
        Err(TryConsumeError::CleanEnd)
    ));
}

#[test]
fn ordinary_producer_drop_is_faulted_even_when_counts_match() {
    let channel = VolatileAdmissionChannel::<2>::new(config(16, 1)).expect("bounded channel");
    let (mut producer, mut consumer) = channel.split();
    producer.try_admit(b"event", 1, 0).expect("event admitted");
    drop(producer);

    consumer
        .try_next()
        .expect("event remains drainable")
        .commit();
    assert!(matches!(
        consumer.try_next(),
        Err(TryConsumeError::ProducerFaulted {
            published: 1,
            committed: 1,
        })
    ));
}

#[test]
fn sequence_wrap_is_identical_for_page_ring_and_consumer() {
    let mut cfg = config(8, 2);
    cfg.first_sequence = u64::MAX;
    let channel = VolatileAdmissionChannel::<2>::new(cfg).expect("bounded channel");
    let (mut producer, mut consumer) = channel.split();

    assert_eq!(
        producer.try_admit(b"a", 1, 0).expect("first").sequence(),
        u64::MAX
    );
    assert_eq!(
        producer.try_admit(b"b", 1, 0).expect("second").sequence(),
        0
    );
    producer.finish().expect("clean finish");

    assert_eq!(
        consumer
            .try_next()
            .expect("wrapped first")
            .commit()
            .sequence(),
        u64::MAX
    );
    assert_eq!(
        consumer
            .try_next()
            .expect("wrapped second")
            .commit()
            .sequence(),
        0
    );
    assert!(matches!(
        consumer.try_next(),
        Err(TryConsumeError::CleanEnd)
    ));
}

#[test]
fn held_frame_payload_can_source_a_disjoint_later_admission() {
    let channel = VolatileAdmissionChannel::<2>::new(config(32, 2)).expect("bounded channel");
    let (mut producer, mut consumer) = channel.split();
    producer
        .try_admit(b"source", 1, 0)
        .expect("first event admitted");

    let first = consumer.try_next().expect("source validates");
    producer
        .try_admit(first.payload(), 2, 0)
        .expect("append-only destination is disjoint");
    assert_eq!(first.payload(), b"source");
    first.commit();

    let second = consumer.try_next().expect("copied event validates");
    assert_eq!(second.payload(), b"source");
    second.commit();
}

#[test]
fn deterministic_short_traces_match_a_safe_vecdeque_and_sealed_page_oracle() {
    const OP_COUNT: usize = 5;
    const TRACE_LEN: usize = 5;
    let trace_count = if cfg!(miri) {
        32
    } else {
        OP_COUNT.pow(TRACE_LEN as u32)
    };

    for encoded_trace in 0..trace_count {
        let cfg = config(4, 3);
        let channel = VolatileAdmissionChannel::<2>::new(cfg).expect("bounded channel");
        let (mut producer, mut consumer) = channel.split();
        let mut sealed_oracle = SlabPageBuilder::new(cfg).expect("bounded safe page");
        let mut queue = VecDeque::<(TelemetryDescriptor, Vec<u8>)>::with_capacity(2);
        let mut accepted = Vec::new();
        let mut actual = Vec::new();
        let mut used_bytes = 0_usize;
        let mut descriptor_count = 0_usize;
        let mut next_sequence = cfg.first_sequence;
        let mut trace = encoded_trace;

        for step in 0..TRACE_LEN {
            let operation = trace % OP_COUNT;
            trace /= OP_COUNT;
            match operation {
                0..=2 => {
                    let payload: &[u8] = match operation {
                        0 => b"a",
                        1 => b"bb",
                        2 => b"",
                        _ => unreachable!("operation is bounded above"),
                    };
                    let schema_id = step as u32;
                    let flags = (encoded_trace as u16) ^ step as u16;
                    let expected_error = if payload.is_empty() {
                        Some(TryAdmitError::Slab(SlabAppendError::EmptyPayload))
                    } else if descriptor_count == cfg.descriptor_capacity {
                        Some(TryAdmitError::Slab(
                            SlabAppendError::DescriptorCapacityExhausted {
                                capacity: cfg.descriptor_capacity,
                            },
                        ))
                    } else if payload.len() > cfg.byte_capacity - used_bytes {
                        Some(TryAdmitError::Slab(SlabAppendError::PageFull {
                            requested: payload.len(),
                            remaining: cfg.byte_capacity - used_bytes,
                        }))
                    } else if queue.len() == queue.capacity() {
                        Some(TryAdmitError::RingFull)
                    } else {
                        None
                    };

                    let result = producer.try_admit(payload, schema_id, flags);
                    if let Some(error) = expected_error {
                        assert_eq!(result, Err(error), "trace {encoded_trace}, step {step}");
                    } else {
                        let token = result.expect("oracle predicted admission success");
                        assert_eq!(token.sequence(), next_sequence);
                        sealed_oracle
                            .try_append(payload, schema_id, flags)
                            .expect("safe oracle append succeeds");
                        let descriptor = TelemetryDescriptor {
                            sequence: next_sequence,
                            arena_generation: cfg.arena_generation,
                            arena_id: cfg.arena_id,
                            flags,
                            offset: used_bytes as u32,
                            len: payload.len() as u32,
                            crc32c: crc32c::crc32c(payload),
                            schema_id,
                        };
                        queue.push_back((descriptor, payload.to_vec()));
                        accepted.push(descriptor);
                        used_bytes += payload.len();
                        descriptor_count += 1;
                        next_sequence = next_sequence.wrapping_add(1);
                    }
                }
                3 => {
                    if let Some((descriptor, payload)) = queue.pop_front() {
                        let frame = consumer.try_next().expect("oracle queue is non-empty");
                        assert_eq!(*frame.descriptor(), descriptor);
                        assert_eq!(frame.payload(), payload.as_slice());
                        actual.push(*frame.descriptor());
                        frame.commit();
                    } else {
                        assert!(matches!(consumer.try_next(), Err(TryConsumeError::Empty)));
                    }
                }
                4 => {
                    if let Some((descriptor, payload)) = queue.front() {
                        let frame = consumer.try_next().expect("oracle queue is non-empty");
                        assert_eq!(frame.descriptor(), descriptor);
                        assert_eq!(frame.payload(), payload.as_slice());
                        drop(frame);
                    } else {
                        assert!(matches!(consumer.try_next(), Err(TryConsumeError::Empty)));
                    }
                }
                _ => unreachable!("operation is reduced modulo OP_COUNT"),
            }

            assert_eq!(producer.used_bytes(), used_bytes);
            assert_eq!(producer.published_count(), descriptor_count);
            assert_eq!(producer.next_sequence(), next_sequence);
        }

        producer.finish().expect("open oracle producer finishes");
        while let Some((descriptor, payload)) = queue.pop_front() {
            let frame = consumer.try_next().expect("remaining oracle event drains");
            assert_eq!(*frame.descriptor(), descriptor);
            assert_eq!(frame.payload(), payload.as_slice());
            actual.push(*frame.descriptor());
            frame.commit();
        }
        assert!(matches!(
            consumer.try_next(),
            Err(TryConsumeError::CleanEnd)
        ));

        let sealed = sealed_oracle.seal();
        assert_eq!(sealed.descriptors(), accepted.as_slice());
        assert_eq!(actual, accepted);
    }
}

#[test]
fn tiny_ring_cross_thread_stress_has_no_loss_duplicates_or_reordering() {
    let event_count = if cfg!(miri) { 64_u64 } else { 50_000_u64 };
    let channel = VolatileAdmissionChannel::<2>::new(config(
        usize::try_from(event_count * 8).expect("test capacity fits"),
        usize::try_from(event_count).expect("test count fits"),
    ))
    .expect("bounded channel");
    let (mut producer, mut consumer) = channel.split();

    let consumer_thread = thread::spawn(move || {
        for expected in 0..event_count {
            loop {
                match consumer.try_next() {
                    Ok(frame) => {
                        assert_eq!(frame.descriptor().sequence, 41_u64.wrapping_add(expected));
                        let bytes: [u8; 8] =
                            frame.payload().try_into().expect("test payload is one u64");
                        assert_eq!(u64::from_le_bytes(bytes), expected);
                        frame.commit();
                        break;
                    }
                    Err(TryConsumeError::Empty) => thread::yield_now(),
                    Err(error) => panic!("unexpected consumer error: {error}"),
                }
            }
        }
        loop {
            match consumer.try_next() {
                Err(TryConsumeError::CleanEnd) => break,
                Err(TryConsumeError::Empty) => thread::yield_now(),
                Ok(frame) => panic!(
                    "received unexpected sequence {} after the complete corpus",
                    frame.descriptor().sequence
                ),
                Err(error) => panic!("unexpected terminal consumer error: {error}"),
            }
        }
    });

    for value in 0..event_count {
        loop {
            match producer.try_admit(&value.to_le_bytes(), 1, 0) {
                Ok(token) => {
                    assert_eq!(token.sequence(), 41_u64.wrapping_add(value));
                    break;
                }
                Err(TryAdmitError::RingFull) => thread::yield_now(),
                Err(error) => panic!("unexpected producer error: {error}"),
            }
        }
    }
    producer.finish().expect("clean producer finish");
    consumer_thread.join().expect("consumer thread succeeds");
}
