#![cfg(not(feature = "loom"))]

use std::thread;

use aegis_event::{
    PublishedSlabPage, PublishedSlabReadError, SlabAppendError, SlabConfigError, SlabPageBuilder,
    SlabPageConfig, SpscRing, TelemetryDescriptor, TryPopError, TryPushError, CACHE_LINE_BYTES,
    MAX_FRAME_BYTES, MAX_SLAB_DESCRIPTORS, MAX_SLAB_PAGE_BYTES,
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
fn published_page_reuses_the_bounded_slab_configuration_contract() {
    assert_eq!(
        PublishedSlabPage::new(config(0, 1)).expect_err("zero byte capacity must fail"),
        SlabConfigError::ZeroByteCapacity
    );
    assert_eq!(
        PublishedSlabPage::new(config(MAX_SLAB_PAGE_BYTES + 1, 1))
            .expect_err("oversized bytes must fail before allocation"),
        SlabConfigError::ByteCapacityTooLarge {
            requested: MAX_SLAB_PAGE_BYTES + 1,
            maximum: MAX_SLAB_PAGE_BYTES,
        }
    );
    assert_eq!(
        PublishedSlabPage::new(config(1, 0)).expect_err("zero descriptors must fail"),
        SlabConfigError::ZeroDescriptorCapacity
    );
    assert_eq!(
        PublishedSlabPage::new(config(1, MAX_SLAB_DESCRIPTORS + 1))
            .expect_err("oversized descriptor budget must fail before allocation"),
        SlabConfigError::DescriptorCapacityTooLarge {
            requested: MAX_SLAB_DESCRIPTORS + 1,
            maximum: MAX_SLAB_DESCRIPTORS,
        }
    );
}

#[test]
fn append_release_publishes_each_descriptor_without_sealing_the_page() {
    let page = PublishedSlabPage::new(config(64, 4)).expect("bounded page");
    let (mut writer, reader) = page.split();

    let first = writer
        .try_append(b"123456789", 7, 0x0001)
        .expect("first frame fits");
    assert_eq!(first.sequence, 41);
    assert_eq!(first.offset, 0);
    assert_eq!(first.len, 9);
    assert_eq!(first.crc32c, 0xe306_9283);
    assert_eq!(first.schema_id, 7);
    assert_eq!(first.flags, 0x0001);
    assert_eq!(reader.published_count(), 1);
    assert_eq!(reader.published_bytes(), 9);
    assert_eq!(
        reader
            .resolve(&first)
            .expect("first frame is published")
            .as_ref(),
        b"123456789"
    );

    let second = writer
        .try_append(b"second", 8, 0x0002)
        .expect("second frame fits");
    assert_eq!(second.sequence, 42);
    assert_eq!(second.offset, 9);
    assert_eq!(second.len, 6);
    assert_eq!(reader.published_count(), 2);
    assert_eq!(reader.published_bytes(), 15);
    assert_eq!(
        reader
            .resolve(&second)
            .expect("second frame is published")
            .as_ref(),
        b"second"
    );

    assert_eq!(writer.used_bytes(), 15);
    assert_eq!(writer.published_count(), 2);
    assert_eq!(writer.remaining_bytes(), 49);
    assert_eq!(writer.remaining_descriptors(), 2);
    assert_eq!(writer.next_sequence(), 43);
}

#[test]
fn failed_appends_do_not_publish_or_advance_writer_state() {
    let page = PublishedSlabPage::new(config(4, 2)).expect("bounded page");
    let (mut writer, reader) = page.split();

    assert_eq!(
        writer.try_append(&[], 1, 0),
        Err(SlabAppendError::EmptyPayload)
    );
    assert_eq!(writer.used_bytes(), 0);
    assert_eq!(writer.published_count(), 0);
    assert_eq!(writer.next_sequence(), 41);
    assert_eq!(reader.published_count(), 0);

    let first = writer.try_append(b"abc", 1, 0).expect("first frame fits");
    assert_eq!(
        writer.try_append(b"de", 1, 0),
        Err(SlabAppendError::PageFull {
            requested: 2,
            remaining: 1,
        })
    );
    assert_eq!(writer.used_bytes(), 3);
    assert_eq!(writer.published_count(), 1);
    assert_eq!(writer.next_sequence(), 42);
    assert_eq!(reader.published_count(), 1);
    assert_eq!(
        reader
            .resolve(&first)
            .expect("first remains valid")
            .as_ref(),
        b"abc"
    );

    let second = writer.try_append(b"d", 2, 0).expect("remaining byte fits");
    assert_eq!(second.sequence, 42);
    assert_eq!(
        writer.try_append(b"x", 3, 0),
        Err(SlabAppendError::DescriptorCapacityExhausted { capacity: 2 })
    );
    assert_eq!(writer.used_bytes(), 4);
    assert_eq!(writer.published_count(), 2);
    assert_eq!(writer.next_sequence(), 43);
    assert_eq!(reader.published_count(), 2);
}

#[test]
fn resolver_rejects_unpublished_and_forged_descriptors_before_payload_access() {
    let page = PublishedSlabPage::new(config(32, 3)).expect("bounded page");
    let (mut writer, reader) = page.split();
    let first = writer.try_append(b"verified", 9, 0).expect("payload fits");

    let mut wrong_arena = first;
    wrong_arena.arena_id = 99;
    assert_eq!(
        reader.resolve(&wrong_arena),
        Err(PublishedSlabReadError::ArenaIdMismatch {
            page: 17,
            descriptor: 99,
        })
    );

    let mut stale_generation = first;
    stale_generation.arena_generation = 22;
    assert_eq!(
        reader.resolve(&stale_generation),
        Err(PublishedSlabReadError::GenerationMismatch {
            page: 23,
            descriptor: 22,
        })
    );

    let mut future = first;
    future.sequence = 42;
    assert_eq!(
        reader.resolve(&future),
        Err(PublishedSlabReadError::UnpublishedSequence {
            first: 41,
            committed: 1,
            descriptor: 42,
        })
    );

    for forged in [
        {
            let mut value = first;
            value.offset = 1;
            value
        },
        {
            let mut value = first;
            value.len = 0;
            value
        },
        {
            let mut value = first;
            value.crc32c ^= 1;
            value
        },
        {
            let mut value = first;
            value.schema_id = 10;
            value
        },
        {
            let mut value = first;
            value.flags ^= 1;
            value
        },
    ] {
        assert_eq!(
            reader.resolve(&forged),
            Err(PublishedSlabReadError::DescriptorMismatch { sequence: 41 })
        );
    }

    let second = writer
        .try_append(b"redirect", 10, 1)
        .expect("second payload fits");
    let mut redirected = first;
    redirected.offset = second.offset;
    redirected.len = second.len;
    redirected.crc32c = second.crc32c;
    assert_eq!(
        reader.resolve(&redirected),
        Err(PublishedSlabReadError::DescriptorMismatch { sequence: 41 })
    );

    let mut sequence_swap = first;
    sequence_swap.sequence = second.sequence;
    assert_eq!(
        reader.resolve(&sequence_swap),
        Err(PublishedSlabReadError::DescriptorMismatch {
            sequence: second.sequence,
        })
    );
}

#[test]
fn modular_sequence_wrap_remains_unambiguous_within_one_page() {
    let mut cfg = config(8, 2);
    cfg.first_sequence = u64::MAX;
    let page = PublishedSlabPage::new(cfg).expect("bounded page");
    let (mut writer, reader) = page.split();

    let first = writer.try_append(b"a", 1, 0).expect("first frame fits");
    let second = writer.try_append(b"b", 1, 0).expect("second frame fits");

    assert_eq!(first.sequence, u64::MAX);
    assert_eq!(second.sequence, 0);
    assert_eq!(writer.next_sequence(), 1);
    assert_eq!(
        reader.resolve(&first).expect("wrapped first").as_ref(),
        b"a"
    );
    assert_eq!(
        reader.resolve(&second).expect("wrapped second").as_ref(),
        b"b"
    );
}

#[test]
fn native_borrowed_prefix_stays_stable_while_writer_appends_a_disjoint_suffix() {
    let page = PublishedSlabPage::new(config(32, 3)).expect("bounded page");
    let (mut writer, reader) = page.split();
    let first = writer
        .try_append(b"prefix", 1, 0)
        .expect("first frame fits");

    let first_view = reader.resolve(&first).expect("first frame resolves");
    let first_pointer = first_view.as_ptr();
    let second = writer
        .try_append(b"suffix", 2, 0)
        .expect("writer may append a disjoint suffix while the prefix is borrowed");

    assert_eq!(first_view.as_ptr(), first_pointer);
    assert_eq!(first_view.as_ref(), b"prefix");
    assert_eq!(
        reader.resolve(&second).expect("suffix resolves").as_ref(),
        b"suffix"
    );
    assert_eq!(
        reader
            .resolve(&first)
            .expect("prefix still resolves")
            .as_ptr(),
        first_pointer
    );
}

#[test]
fn an_earlier_published_view_can_be_the_source_for_a_disjoint_append() {
    let page = PublishedSlabPage::new(config(32, 2)).expect("bounded page");
    let (mut writer, reader) = page.split();
    let first = writer
        .try_append(b"source", 1, 0)
        .expect("first frame fits");
    let source = reader.resolve(&first).expect("source frame resolves");

    let second = writer
        .try_append(source.as_ref(), 2, 0)
        .expect("source and append-only destination are disjoint");

    assert_eq!(source.as_ref(), b"source");
    assert_eq!(
        reader
            .resolve(&second)
            .expect("copied frame resolves")
            .as_ref(),
        b"source"
    );
    assert_ne!(
        source.as_ptr(),
        reader.resolve(&second).expect("view").as_ptr()
    );
}

#[test]
fn published_page_matches_the_safe_sealed_page_oracle() {
    let cfg = config(64, 4);
    let mut sealed_builder = SlabPageBuilder::new(cfg).expect("bounded safe page");
    let page = PublishedSlabPage::new(cfg).expect("bounded published page");
    let (mut writer, reader) = page.split();
    let frames: [(&[u8], u32, u16); 3] =
        [(b"one", 1, 0), (b"two-two", 2, 1), (b"three", 3, 0x8000)];
    let mut published_descriptors = Vec::new();

    for (payload, schema_id, flags) in frames {
        sealed_builder
            .try_append(payload, schema_id, flags)
            .expect("safe oracle append fits");
        published_descriptors.push(
            writer
                .try_append(payload, schema_id, flags)
                .expect("published append fits"),
        );
    }

    let sealed = sealed_builder.seal();
    let sealed_reader = sealed.reader();
    assert_eq!(published_descriptors.as_slice(), sealed.descriptors());
    for descriptor in &published_descriptors {
        assert_eq!(
            reader.resolve(descriptor).expect("published view").as_ref(),
            sealed_reader.resolve(descriptor).expect("safe oracle view")
        );
    }
}

#[test]
fn deterministic_variable_length_corpus_matches_the_safe_oracle() {
    let frame_count = if cfg!(miri) { 16_usize } else { 512_usize };
    let cfg = config(frame_count * 257, frame_count);
    let mut sealed_builder = SlabPageBuilder::new(cfg).expect("bounded safe page");
    let page = PublishedSlabPage::new(cfg).expect("bounded published page");
    let (mut writer, reader) = page.split();
    let mut expected_payloads = Vec::with_capacity(frame_count);
    let mut published_descriptors = Vec::with_capacity(frame_count);
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;

    for index in 0..frame_count {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let len = (state as usize % 257) + 1;
        let mut payload = Vec::with_capacity(len);
        for byte_index in 0..len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            payload.push((state as u8) ^ byte_index as u8);
        }
        let schema_id = (index % 11) as u32;
        let flags = (state >> 48) as u16;

        sealed_builder
            .try_append(&payload, schema_id, flags)
            .expect("safe corpus append fits");
        published_descriptors.push(
            writer
                .try_append(&payload, schema_id, flags)
                .expect("published corpus append fits"),
        );
        expected_payloads.push(payload);
    }

    let expected_exhaustion = SlabAppendError::DescriptorCapacityExhausted {
        capacity: frame_count,
    };
    assert_eq!(
        sealed_builder.try_append(b"overflow", 99, 0),
        Err(expected_exhaustion)
    );
    assert_eq!(
        writer.try_append(b"overflow", 99, 0),
        Err(expected_exhaustion)
    );

    let sealed = sealed_builder.seal();
    let sealed_reader = sealed.reader();
    assert_eq!(published_descriptors.as_slice(), sealed.descriptors());
    assert_eq!(writer.next_sequence(), sealed.next_sequence());
    for ((descriptor, expected), sealed_descriptor) in published_descriptors
        .iter()
        .zip(&expected_payloads)
        .zip(sealed.descriptors())
    {
        assert_eq!(descriptor, sealed_descriptor);
        assert_eq!(
            reader
                .resolve(descriptor)
                .expect("published corpus view")
                .as_ref(),
            expected.as_slice()
        );
        assert_eq!(
            sealed_reader
                .resolve(sealed_descriptor)
                .expect("safe corpus view"),
            expected.as_slice()
        );
    }
}

#[test]
fn exact_frame_and_page_boundaries_are_enforced_without_partial_publication() {
    let frame_len = if cfg!(miri) { 4_096 } else { MAX_FRAME_BYTES };
    let page = PublishedSlabPage::new(config(frame_len, 2)).expect("bounded page");
    let (mut writer, reader) = page.split();
    let payload = vec![0xa5; frame_len];

    let descriptor = writer
        .try_append(&payload, 3, 0)
        .expect("exact byte capacity fits");
    assert_eq!(writer.remaining_bytes(), 0);
    assert_eq!(reader.published_bytes(), frame_len);
    assert_eq!(
        writer.try_append(b"x", 3, 0),
        Err(SlabAppendError::PageFull {
            requested: 1,
            remaining: 0,
        })
    );
    assert_eq!(writer.published_count(), 1);
    assert_eq!(reader.published_count(), 1);
    assert_eq!(
        reader
            .resolve(&descriptor)
            .expect("boundary frame resolves")
            .as_ref(),
        payload.as_slice()
    );

    if !cfg!(miri) {
        let oversized = vec![0_u8; MAX_FRAME_BYTES + 1];
        assert_eq!(
            writer.try_append(&oversized, 3, 0),
            Err(SlabAppendError::FrameTooLarge {
                len: MAX_FRAME_BYTES + 1,
                maximum: MAX_FRAME_BYTES,
            })
        );
        assert_eq!(writer.published_count(), 1);
    }
}

#[test]
fn writer_drop_freezes_the_prefix_and_reader_keeps_the_page_alive() {
    let page = PublishedSlabPage::new(config(16, 1)).expect("bounded page");
    let (mut writer, reader) = page.split();
    let descriptor = writer.try_append(b"lease", 1, 0).expect("payload fits");

    assert!(!reader.is_writer_closed());
    drop(writer);
    assert!(reader.is_writer_closed());
    assert_eq!(reader.published_count(), 1);
    assert_eq!(
        reader
            .resolve(&descriptor)
            .expect("reader owns the page after writer drop")
            .as_ref(),
        b"lease"
    );
}

#[test]
fn publication_state_and_cells_have_the_reviewed_native_layout() {
    let page = PublishedSlabPage::new(config(8, 2)).expect("bounded page");
    let layout = page.layout();

    assert_eq!(layout.publication_state_alignment, CACHE_LINE_BYTES);
    assert!(layout.publication_state_size >= CACHE_LINE_BYTES);
    assert_eq!(layout.publication_state_size % CACHE_LINE_BYTES, 0);
    assert_eq!(layout.byte_cell_size, 1);
    assert_eq!(layout.byte_cell_alignment, 1);
    assert_eq!(layout.descriptor_cell_size, 32);
    assert_eq!(layout.descriptor_cell_alignment, 32);
}

#[test]
fn cross_thread_ring_stress_resolves_only_fully_published_payloads() {
    let event_count = if cfg!(miri) { 64_u64 } else { 50_000_u64 };
    let page = PublishedSlabPage::new(config(
        usize::try_from(event_count * 8).expect("test byte capacity fits usize"),
        usize::try_from(event_count).expect("test descriptor capacity fits usize"),
    ))
    .expect("bounded page");
    let (mut writer, reader) = page.split();
    let ring = SpscRing::<TelemetryDescriptor, 1024>::new().expect("valid descriptor ring");
    let (mut producer, mut consumer) = ring.split();

    let consumer_thread = thread::spawn(move || {
        for expected in 0..event_count {
            let descriptor = loop {
                match consumer.try_pop() {
                    Ok(value) => break value,
                    Err(TryPopError::Empty) => thread::yield_now(),
                    Err(TryPopError::Disconnected) => {
                        panic!("producer disconnected before every descriptor arrived")
                    }
                }
            };
            assert_eq!(descriptor.sequence, 41_u64.wrapping_add(expected));
            let payload = reader
                .resolve(&descriptor)
                .expect("ring cannot expose an incomplete append");
            let bytes: [u8; 8] = payload
                .as_ref()
                .try_into()
                .expect("test payload is one u64");
            assert_eq!(u64::from_le_bytes(bytes), expected);
        }

        loop {
            match consumer.try_pop() {
                Err(TryPopError::Disconnected) => break,
                Err(TryPopError::Empty) => thread::yield_now(),
                Ok(_) => panic!("unexpected descriptor after the test population"),
            }
        }
        assert!(reader.is_writer_closed());
        assert_eq!(reader.published_count(), event_count as usize);
    });

    for value in 0..event_count {
        let descriptor = writer
            .try_append(&value.to_le_bytes(), 1, 0)
            .expect("preallocated page has capacity");
        let mut pending = descriptor;
        loop {
            match producer.try_push(pending) {
                Ok(()) => break,
                Err(TryPushError::Full(value)) => {
                    pending = value;
                    thread::yield_now();
                }
                Err(TryPushError::Disconnected(_)) => {
                    panic!("consumer disconnected during publication stress")
                }
            }
        }
    }

    drop(writer);
    drop(producer);
    consumer_thread.join().expect("consumer thread succeeds");
}
