use aegis_event::{
    SlabAppendError, SlabConfigError, SlabPageBuilder, SlabPageConfig, SlabReadError,
    MAX_FRAME_BYTES, MAX_SLAB_DESCRIPTORS, MAX_SLAB_PAGE_BYTES,
};
#[cfg(not(feature = "loom"))]
use aegis_event::{SpscRing, TryPopError};

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
fn slab_configuration_rejects_unbounded_or_empty_pages() {
    assert_eq!(
        SlabPageBuilder::new(config(0, 1)).expect_err("zero byte capacity must fail"),
        SlabConfigError::ZeroByteCapacity
    );
    assert_eq!(
        SlabPageBuilder::new(config(MAX_SLAB_PAGE_BYTES + 1, 1))
            .expect_err("oversized page must fail before allocation"),
        SlabConfigError::ByteCapacityTooLarge {
            requested: MAX_SLAB_PAGE_BYTES + 1,
            maximum: MAX_SLAB_PAGE_BYTES,
        }
    );
    assert_eq!(
        SlabPageBuilder::new(config(1, 0)).expect_err("zero descriptors must fail"),
        SlabConfigError::ZeroDescriptorCapacity
    );
    assert_eq!(
        SlabPageBuilder::new(config(1, MAX_SLAB_DESCRIPTORS + 1))
            .expect_err("oversized descriptor budget must fail before allocation"),
        SlabConfigError::DescriptorCapacityTooLarge {
            requested: MAX_SLAB_DESCRIPTORS + 1,
            maximum: MAX_SLAB_DESCRIPTORS,
        }
    );
}

#[test]
fn append_then_seal_builds_checked_descriptors_without_reencoding_payloads() {
    let mut builder = SlabPageBuilder::new(config(64, 4)).expect("bounded page");

    builder
        .try_append(b"123456789", 7, 0x0001)
        .expect("first frame fits");
    builder
        .try_append(b"second", 8, 0x0002)
        .expect("second frame fits");

    assert_eq!(builder.used_bytes(), 15);
    assert_eq!(builder.descriptor_count(), 2);
    assert_eq!(builder.remaining_bytes(), 49);
    assert_eq!(builder.remaining_descriptors(), 2);

    let sealed = builder.seal();
    let descriptors = sealed.descriptors();

    assert_eq!(sealed.arena_id(), 17);
    assert_eq!(sealed.arena_generation(), 23);
    assert_eq!(sealed.used_bytes(), 15);
    assert_eq!(descriptors.len(), 2);
    assert_eq!(descriptors[0].sequence, 41);
    assert_eq!(descriptors[0].offset, 0);
    assert_eq!(descriptors[0].len, 9);
    assert_eq!(descriptors[0].crc32c, 0xe306_9283);
    assert_eq!(descriptors[0].schema_id, 7);
    assert_eq!(descriptors[0].flags, 0x0001);
    assert_eq!(descriptors[1].sequence, 42);
    assert_eq!(descriptors[1].offset, 9);
    assert_eq!(descriptors[1].len, 6);

    let reader = sealed.reader();
    assert_eq!(
        reader.resolve(&descriptors[0]).expect("valid first view"),
        b"123456789"
    );
    assert_eq!(
        reader.resolve(&descriptors[1]).expect("valid second view"),
        b"second"
    );
}

#[test]
fn failed_appends_leave_the_builder_state_unchanged() {
    let mut builder = SlabPageBuilder::new(config(4, 2)).expect("bounded page");

    assert_eq!(
        builder.try_append(&[], 1, 0),
        Err(SlabAppendError::EmptyPayload)
    );
    assert_eq!(builder.used_bytes(), 0);
    assert_eq!(builder.descriptor_count(), 0);

    builder
        .try_append(b"abc", 1, 0)
        .expect("first payload fits");
    assert_eq!(
        builder.try_append(b"de", 1, 0),
        Err(SlabAppendError::PageFull {
            requested: 2,
            remaining: 1,
        })
    );
    assert_eq!(builder.used_bytes(), 3);
    assert_eq!(builder.descriptor_count(), 1);

    builder
        .try_append(b"d", 2, 0)
        .expect("a failed append did not consume bytes or sequence");

    let oversized = vec![0_u8; MAX_FRAME_BYTES + 1];
    assert_eq!(
        builder.try_append(&oversized, 1, 0),
        Err(SlabAppendError::FrameTooLarge {
            len: MAX_FRAME_BYTES + 1,
            maximum: MAX_FRAME_BYTES,
        })
    );
    assert_eq!(builder.used_bytes(), 4);
    assert_eq!(builder.descriptor_count(), 2);

    let sealed = builder.seal();
    assert_eq!(sealed.descriptors()[0].sequence, 41);
    assert_eq!(sealed.descriptors()[1].sequence, 42);
    assert_eq!(sealed.next_sequence(), 43);
}

#[test]
fn descriptor_budget_exhaustion_is_explicit_and_non_mutating() {
    let mut builder = SlabPageBuilder::new(config(8, 1)).expect("bounded page");
    builder.try_append(b"one", 1, 0).expect("first frame fits");

    assert_eq!(
        builder.try_append(b"two", 1, 0),
        Err(SlabAppendError::DescriptorCapacityExhausted { capacity: 1 })
    );
    assert_eq!(builder.used_bytes(), 3);
    assert_eq!(builder.descriptor_count(), 1);
}

#[test]
fn sequence_generation_is_monotonic_modulo_u64() {
    let mut cfg = config(8, 2);
    cfg.first_sequence = u64::MAX;
    let mut builder = SlabPageBuilder::new(cfg).expect("bounded page");
    builder.try_append(b"a", 1, 0).expect("first frame fits");
    builder.try_append(b"b", 1, 0).expect("second frame fits");

    let sealed = builder.seal();
    assert_eq!(sealed.descriptors()[0].sequence, u64::MAX);
    assert_eq!(sealed.descriptors()[1].sequence, 0);
    assert_eq!(sealed.next_sequence(), 1);
    let reader = sealed.reader();
    assert_eq!(
        reader
            .resolve(&sealed.descriptors()[0])
            .expect("wrapped first descriptor resolves"),
        b"a"
    );
    assert_eq!(
        reader
            .resolve(&sealed.descriptors()[1])
            .expect("wrapped second descriptor resolves"),
        b"b"
    );

    let mut next_page_config = config(8, 1);
    next_page_config.arena_generation = 24;
    next_page_config.first_sequence = sealed.next_sequence();
    let mut next_page = SlabPageBuilder::new(next_page_config).expect("next bounded page");
    next_page
        .try_append(b"c", 1, 0)
        .expect("next-page payload fits");
    assert_eq!(next_page.seal().descriptors()[0].sequence, 1);
}

#[test]
fn resolver_fails_closed_on_identity_generation_and_metadata_mismatch() {
    let mut builder = SlabPageBuilder::new(config(32, 2)).expect("bounded page");
    builder.try_append(b"verified", 9, 0).expect("payload fits");
    builder
        .try_append(b"redirect", 10, 1)
        .expect("second payload fits");
    let sealed = builder.seal();
    let reader = sealed.reader();
    let descriptor = sealed.descriptors()[0];
    let second = sealed.descriptors()[1];

    let mut wrong_arena = descriptor;
    wrong_arena.arena_id = 99;
    assert_eq!(
        reader.resolve(&wrong_arena),
        Err(SlabReadError::ArenaIdMismatch {
            page: 17,
            descriptor: 99,
        })
    );

    let mut stale_generation = descriptor;
    stale_generation.arena_generation = 22;
    assert_eq!(
        reader.resolve(&stale_generation),
        Err(SlabReadError::GenerationMismatch {
            page: 23,
            descriptor: 22,
        })
    );

    let mut empty = descriptor;
    empty.len = 0;
    empty.crc32c = 0;
    assert_eq!(reader.resolve(&empty), Err(SlabReadError::EmptyPayload));

    let mut outside_used_bytes = descriptor;
    outside_used_bytes.offset = 15;
    outside_used_bytes.len = 2;
    assert_eq!(
        reader.resolve(&outside_used_bytes),
        Err(SlabReadError::DescriptorMismatch { sequence: 41 })
    );

    let mut wrong_crc = descriptor;
    wrong_crc.crc32c ^= 1;
    assert_eq!(
        reader.resolve(&wrong_crc),
        Err(SlabReadError::DescriptorMismatch { sequence: 41 })
    );

    let mut unknown_sequence = descriptor;
    unknown_sequence.sequence = 500;
    assert_eq!(
        reader.resolve(&unknown_sequence),
        Err(SlabReadError::UnknownSequence {
            first: 41,
            count: 2,
            descriptor: 500,
        })
    );

    let mut relabeled = descriptor;
    relabeled.schema_id = 10;
    assert_eq!(
        reader.resolve(&relabeled),
        Err(SlabReadError::DescriptorMismatch { sequence: 41 })
    );

    let mut redirected = descriptor;
    redirected.offset = second.offset;
    redirected.len = second.len;
    redirected.crc32c = second.crc32c;
    assert_eq!(
        reader.resolve(&redirected),
        Err(SlabReadError::DescriptorMismatch { sequence: 41 })
    );

    let mut changed_flags = descriptor;
    changed_flags.flags ^= 1;
    assert_eq!(
        reader.resolve(&changed_flags),
        Err(SlabReadError::DescriptorMismatch { sequence: 41 })
    );

    let mut swapped_sequence = descriptor;
    swapped_sequence.sequence = second.sequence;
    assert_eq!(
        reader.resolve(&swapped_sequence),
        Err(SlabReadError::DescriptorMismatch {
            sequence: second.sequence,
        })
    );
}

#[test]
fn page_level_reader_lease_keeps_immutable_payload_alive() {
    let mut builder = SlabPageBuilder::new(config(16, 1)).expect("bounded page");
    builder.try_append(b"lease", 1, 0).expect("payload fits");
    let sealed = builder.seal();
    let descriptor = sealed.descriptors()[0];
    let reader = sealed.reader();
    drop(sealed);

    assert_eq!(
        reader.resolve(&descriptor).expect("lease remains live"),
        b"lease"
    );
}

#[test]
fn arbitrary_descriptor_metadata_never_exposes_an_unregistered_view() {
    let mut builder = SlabPageBuilder::new(config(32, 2)).expect("bounded page");
    builder.try_append(b"abc", 1, 0).expect("first frame fits");
    builder
        .try_append(b"defg", 2, 1)
        .expect("second frame fits");
    let sealed = builder.seal();
    let reader = sealed.reader();
    let registered = sealed.descriptors();
    let attempts = if cfg!(miri) { 64 } else { 1_024 };
    let lengths = [0, 1, 3, 4, (MAX_FRAME_BYTES + 1) as u32, u32::MAX];
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;

    for attempt in 0..attempts {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let descriptor = aegis_event::TelemetryDescriptor {
            sequence: state,
            arena_generation: (state >> 16) as u32,
            arena_id: (state >> 48) as u16,
            flags: state as u16,
            offset: (state >> 32) as u32,
            len: lengths[attempt % lengths.len()],
            crc32c: state as u32,
            schema_id: (state >> 8) as u32,
        };

        if let Ok(payload) = reader.resolve(&descriptor) {
            assert!(registered.contains(&descriptor));
            let range = descriptor
                .checked_payload_range(sealed.used_bytes())
                .expect("registered descriptor has a valid range");
            assert_eq!(payload, &b"abcdefg"[range]);
        }
    }
}

#[test]
#[cfg(not(feature = "loom"))]
fn spsc_ring_transfers_only_descriptors_for_a_sealed_page() {
    let mut builder = SlabPageBuilder::new(config(16, 2)).expect("bounded page");
    builder.try_append(b"one", 1, 0).expect("first frame fits");
    builder.try_append(b"two", 1, 0).expect("second frame fits");
    let sealed = builder.seal();
    let reader = sealed.reader();

    let ring = SpscRing::<_, 2>::new().expect("valid descriptor ring");
    let (mut producer, mut consumer) = ring.split();
    let consumer_thread = std::thread::spawn(move || {
        let (first, second) = {
            let mut pop_next = || loop {
                match consumer.try_pop() {
                    Ok(descriptor) => break descriptor,
                    Err(TryPopError::Empty) => std::thread::yield_now(),
                    Err(TryPopError::Disconnected) => {
                        panic!("producer disconnected before expected descriptor")
                    }
                }
            };
            (pop_next(), pop_next())
        };
        assert_eq!(reader.resolve(&first).expect("first page view"), b"one");
        assert_eq!(reader.resolve(&second).expect("second page view"), b"two");
        loop {
            match consumer.try_pop() {
                Err(TryPopError::Disconnected) => break,
                Err(TryPopError::Empty) => std::thread::yield_now(),
                Ok(_) => panic!("descriptor ring returned an unexpected third value"),
            }
        }
    });

    for descriptor in sealed.descriptors() {
        producer
            .try_push(*descriptor)
            .expect("descriptor ring has capacity");
    }
    drop(producer);
    drop(sealed);
    consumer_thread
        .join()
        .expect("descriptor consumer thread succeeds");
}
