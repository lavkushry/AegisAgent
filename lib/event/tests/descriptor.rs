use std::mem::{align_of, offset_of, size_of};

use aegis_event::{DescriptorError, TelemetryDescriptor, MAX_FRAME_BYTES};

fn descriptor(offset: u32, len: u32) -> TelemetryDescriptor {
    TelemetryDescriptor {
        sequence: 42,
        arena_generation: 7,
        arena_id: 3,
        flags: 1,
        offset,
        len,
        crc32c: 0x1234_5678,
        schema_id: 2,
    }
}

#[test]
fn descriptor_abi_is_exactly_one_aligned_32_byte_unit() {
    assert_eq!(size_of::<TelemetryDescriptor>(), 32);
    assert_eq!(align_of::<TelemetryDescriptor>(), 32);
    assert_eq!(offset_of!(TelemetryDescriptor, sequence), 0);
    assert_eq!(offset_of!(TelemetryDescriptor, arena_generation), 8);
    assert_eq!(offset_of!(TelemetryDescriptor, arena_id), 12);
    assert_eq!(offset_of!(TelemetryDescriptor, flags), 14);
    assert_eq!(offset_of!(TelemetryDescriptor, offset), 16);
    assert_eq!(offset_of!(TelemetryDescriptor, len), 20);
    assert_eq!(offset_of!(TelemetryDescriptor, crc32c), 24);
    assert_eq!(offset_of!(TelemetryDescriptor, schema_id), 28);

    let descriptors = [descriptor(0, 1), descriptor(1, 1)];
    let first = std::ptr::addr_of!(descriptors[0]) as usize;
    let second = std::ptr::addr_of!(descriptors[1]) as usize;
    assert_eq!(second - first, 32);
}

#[test]
fn checked_payload_range_accepts_an_in_bounds_frame() {
    assert_eq!(descriptor(32, 64).checked_payload_range(128), Ok(32..96));
}

#[test]
fn checked_payload_range_rejects_frame_larger_than_the_hard_limit() {
    let len = u32::try_from(MAX_FRAME_BYTES + 1).expect("test length fits u32");
    assert_eq!(
        descriptor(0, len).checked_payload_range(MAX_FRAME_BYTES + 1),
        Err(DescriptorError::FrameTooLarge {
            len: MAX_FRAME_BYTES + 1,
            max: MAX_FRAME_BYTES,
        })
    );
}

#[test]
fn checked_payload_range_rejects_integer_overflow_before_slicing() {
    assert_eq!(
        descriptor(u32::MAX, 2).checked_payload_range(usize::MAX),
        Err(DescriptorError::OffsetLengthOverflow {
            offset: u32::MAX,
            len: 2,
        })
    );
}

#[test]
fn checked_payload_range_rejects_a_range_outside_the_arena_page() {
    assert_eq!(
        descriptor(96, 64).checked_payload_range(128),
        Err(DescriptorError::OutOfBounds {
            end: 160,
            page_len: 128,
        })
    );
}
