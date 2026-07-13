//! Bounded, generation-tagged slab pages with a seal-before-publish boundary.
//!
//! A builder is the only mutable owner. Descriptors remain private until
//! `seal` consumes that builder, after which page-level leases expose only
//! immutable payload views. This is a safe, unwired reference implementation;
//! concurrent published-prefix reads and epoch reuse remain target work under
//! ADR-0007.

use std::{error::Error, fmt, sync::Arc};

use crate::{DescriptorError, TelemetryDescriptor, MAX_FRAME_BYTES};

/// Maximum logical byte capacity of one prototype slab page (64 MiB).
pub const MAX_SLAB_PAGE_BYTES: usize = 64 << 20;

/// Maximum descriptor capacity of one prototype slab page.
pub const MAX_SLAB_DESCRIPTORS: usize = 1 << 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlabPageConfig {
    pub arena_id: u16,
    pub arena_generation: u32,
    pub byte_capacity: usize,
    pub descriptor_capacity: usize,
    pub first_sequence: u64,
}

struct PageData {
    arena_id: u16,
    arena_generation: u32,
    byte_capacity: usize,
    descriptor_capacity: usize,
    first_sequence: u64,
    next_sequence: u64,
    bytes: Vec<u8>,
    descriptors: Vec<TelemetryDescriptor>,
}

/// Single-owner mutable construction state for one slab page.
pub struct SlabPageBuilder {
    data: PageData,
}

impl SlabPageBuilder {
    pub fn new(config: SlabPageConfig) -> Result<Self, SlabConfigError> {
        validate_config(config)?;

        let mut bytes = Vec::new();
        bytes.try_reserve_exact(config.byte_capacity).map_err(|_| {
            SlabConfigError::AllocationFailed {
                resource: SlabResource::PayloadBytes,
                requested: config.byte_capacity,
            }
        })?;

        let mut descriptors = Vec::new();
        descriptors
            .try_reserve_exact(config.descriptor_capacity)
            .map_err(|_| SlabConfigError::AllocationFailed {
                resource: SlabResource::Descriptors,
                requested: config.descriptor_capacity,
            })?;

        Ok(Self {
            data: PageData {
                arena_id: config.arena_id,
                arena_generation: config.arena_generation,
                byte_capacity: config.byte_capacity,
                descriptor_capacity: config.descriptor_capacity,
                first_sequence: config.first_sequence,
                next_sequence: config.first_sequence,
                bytes,
                descriptors,
            },
        })
    }

    /// Copies one complete payload into the pre-reserved page.
    ///
    /// Validation and CRC calculation finish before the builder state changes.
    /// Successful appends do not grow either backing allocation.
    pub fn try_append(
        &mut self,
        payload: &[u8],
        schema_id: u32,
        flags: u16,
    ) -> Result<(), SlabAppendError> {
        let len = payload.len();
        if len == 0 {
            return Err(SlabAppendError::EmptyPayload);
        }
        if len > MAX_FRAME_BYTES {
            return Err(SlabAppendError::FrameTooLarge {
                len,
                maximum: MAX_FRAME_BYTES,
            });
        }
        if self.data.descriptors.len() == self.data.descriptor_capacity {
            return Err(SlabAppendError::DescriptorCapacityExhausted {
                capacity: self.data.descriptor_capacity,
            });
        }

        let offset = self.data.bytes.len();
        let end = offset
            .checked_add(len)
            .ok_or(SlabAppendError::OffsetLengthOverflow { offset, len })?;
        if end > self.data.byte_capacity {
            return Err(SlabAppendError::PageFull {
                requested: len,
                remaining: self.data.byte_capacity - offset,
            });
        }

        let offset =
            u32::try_from(offset).map_err(|_| SlabAppendError::OffsetNotAddressable { offset })?;
        let descriptor_len =
            u32::try_from(len).map_err(|_| SlabAppendError::LengthNotAddressable { len })?;
        let checksum = crc32c::crc32c(payload);
        let descriptor = TelemetryDescriptor {
            sequence: self.data.next_sequence,
            arena_generation: self.data.arena_generation,
            arena_id: self.data.arena_id,
            flags,
            offset,
            len: descriptor_len,
            crc32c: checksum,
            schema_id,
        };

        self.data.bytes.extend_from_slice(payload);
        self.data.descriptors.push(descriptor);
        self.data.next_sequence = self.data.next_sequence.wrapping_add(1);
        Ok(())
    }

    pub fn seal(self) -> SealedSlabPage {
        SealedSlabPage {
            data: Arc::new(self.data),
        }
    }

    pub fn arena_id(&self) -> u16 {
        self.data.arena_id
    }

    pub fn arena_generation(&self) -> u32 {
        self.data.arena_generation
    }

    pub fn byte_capacity(&self) -> usize {
        self.data.byte_capacity
    }

    pub fn descriptor_capacity(&self) -> usize {
        self.data.descriptor_capacity
    }

    pub fn used_bytes(&self) -> usize {
        self.data.bytes.len()
    }

    pub fn descriptor_count(&self) -> usize {
        self.data.descriptors.len()
    }

    pub fn remaining_bytes(&self) -> usize {
        self.data.byte_capacity - self.data.bytes.len()
    }

    pub fn remaining_descriptors(&self) -> usize {
        self.data.descriptor_capacity - self.data.descriptors.len()
    }

    pub fn next_sequence(&self) -> u64 {
        self.data.next_sequence
    }
}

impl fmt::Debug for SlabPageBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlabPageBuilder")
            .field("arena_id", &self.arena_id())
            .field("arena_generation", &self.arena_generation())
            .field("byte_capacity", &self.byte_capacity())
            .field("descriptor_capacity", &self.descriptor_capacity())
            .field("used_bytes", &self.used_bytes())
            .field("descriptor_count", &self.descriptor_count())
            .field("next_sequence", &self.next_sequence())
            .finish()
    }
}

/// Immutable page owner that exposes the descriptors created before sealing.
pub struct SealedSlabPage {
    data: Arc<PageData>,
}

impl SealedSlabPage {
    pub fn descriptors(&self) -> &[TelemetryDescriptor] {
        &self.data.descriptors
    }

    /// Creates one page-level reader lease. Callers must not do this per event.
    pub fn reader(&self) -> SlabPageReader {
        SlabPageReader {
            data: Arc::clone(&self.data),
        }
    }

    pub fn arena_id(&self) -> u16 {
        self.data.arena_id
    }

    pub fn arena_generation(&self) -> u32 {
        self.data.arena_generation
    }

    pub fn byte_capacity(&self) -> usize {
        self.data.byte_capacity
    }

    pub fn descriptor_capacity(&self) -> usize {
        self.data.descriptor_capacity
    }

    pub fn used_bytes(&self) -> usize {
        self.data.bytes.len()
    }

    pub fn descriptor_count(&self) -> usize {
        self.data.descriptors.len()
    }

    pub fn next_sequence(&self) -> u64 {
        self.data.next_sequence
    }
}

impl fmt::Debug for SealedSlabPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedSlabPage")
            .field("arena_id", &self.arena_id())
            .field("arena_generation", &self.arena_generation())
            .field("byte_capacity", &self.byte_capacity())
            .field("descriptor_capacity", &self.descriptor_capacity())
            .field("used_bytes", &self.used_bytes())
            .field("descriptor_count", &self.descriptor_count())
            .field("next_sequence", &self.next_sequence())
            .finish()
    }
}

/// Page-level immutable payload lease.
pub struct SlabPageReader {
    data: Arc<PageData>,
}

impl SlabPageReader {
    /// Validates identity, exact sealed-table membership, range, and CRC32C.
    pub fn resolve(&self, descriptor: &TelemetryDescriptor) -> Result<&[u8], SlabReadError> {
        if descriptor.arena_id != self.data.arena_id {
            return Err(SlabReadError::ArenaIdMismatch {
                page: self.data.arena_id,
                descriptor: descriptor.arena_id,
            });
        }
        if descriptor.arena_generation != self.data.arena_generation {
            return Err(SlabReadError::GenerationMismatch {
                page: self.data.arena_generation,
                descriptor: descriptor.arena_generation,
            });
        }
        if descriptor.len == 0 {
            return Err(SlabReadError::EmptyPayload);
        }

        let distance = descriptor.sequence.wrapping_sub(self.data.first_sequence);
        if distance >= self.data.descriptors.len() as u64 {
            return Err(SlabReadError::UnknownSequence {
                first: self.data.first_sequence,
                count: self.data.descriptors.len(),
                descriptor: descriptor.sequence,
            });
        }
        let index = distance as usize;
        if self.data.descriptors[index] != *descriptor {
            return Err(SlabReadError::DescriptorMismatch {
                sequence: descriptor.sequence,
            });
        }

        let canonical = &self.data.descriptors[index];
        let range = canonical
            .checked_payload_range(self.data.bytes.len())
            .map_err(SlabReadError::Descriptor)?;
        let payload = &self.data.bytes[range];
        if crc32c::crc32c(payload) != canonical.crc32c {
            return Err(SlabReadError::CrcMismatch {
                sequence: canonical.sequence,
            });
        }

        Ok(payload)
    }

    pub fn arena_id(&self) -> u16 {
        self.data.arena_id
    }

    pub fn arena_generation(&self) -> u32 {
        self.data.arena_generation
    }

    pub fn used_bytes(&self) -> usize {
        self.data.bytes.len()
    }

    pub fn descriptor_count(&self) -> usize {
        self.data.descriptors.len()
    }
}

impl fmt::Debug for SlabPageReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlabPageReader")
            .field("arena_id", &self.arena_id())
            .field("arena_generation", &self.arena_generation())
            .field("used_bytes", &self.used_bytes())
            .field("descriptor_count", &self.descriptor_count())
            .finish()
    }
}

pub(crate) fn validate_config(config: SlabPageConfig) -> Result<(), SlabConfigError> {
    if config.byte_capacity == 0 {
        return Err(SlabConfigError::ZeroByteCapacity);
    }
    if config.byte_capacity > MAX_SLAB_PAGE_BYTES {
        return Err(SlabConfigError::ByteCapacityTooLarge {
            requested: config.byte_capacity,
            maximum: MAX_SLAB_PAGE_BYTES,
        });
    }
    if config.descriptor_capacity == 0 {
        return Err(SlabConfigError::ZeroDescriptorCapacity);
    }
    if config.descriptor_capacity > MAX_SLAB_DESCRIPTORS {
        return Err(SlabConfigError::DescriptorCapacityTooLarge {
            requested: config.descriptor_capacity,
            maximum: MAX_SLAB_DESCRIPTORS,
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlabResource {
    PayloadBytes,
    Descriptors,
}

impl fmt::Display for SlabResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadBytes => write!(f, "payload bytes"),
            Self::Descriptors => write!(f, "descriptors"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlabConfigError {
    ZeroByteCapacity,
    ByteCapacityTooLarge {
        requested: usize,
        maximum: usize,
    },
    ZeroDescriptorCapacity,
    DescriptorCapacityTooLarge {
        requested: usize,
        maximum: usize,
    },
    AllocationFailed {
        resource: SlabResource,
        requested: usize,
    },
}

impl fmt::Display for SlabConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroByteCapacity => write!(f, "slab page byte capacity must be non-zero"),
            Self::ByteCapacityTooLarge { requested, maximum } => write!(
                f,
                "slab page byte capacity {requested} exceeds maximum {maximum}"
            ),
            Self::ZeroDescriptorCapacity => {
                write!(f, "slab page descriptor capacity must be non-zero")
            }
            Self::DescriptorCapacityTooLarge { requested, maximum } => write!(
                f,
                "slab page descriptor capacity {requested} exceeds maximum {maximum}"
            ),
            Self::AllocationFailed {
                resource,
                requested,
            } => write!(
                f,
                "failed to reserve slab page {resource} capacity {requested}"
            ),
        }
    }
}

impl Error for SlabConfigError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlabAppendError {
    WriterPoisoned,
    EmptyPayload,
    FrameTooLarge { len: usize, maximum: usize },
    DescriptorCapacityExhausted { capacity: usize },
    OffsetLengthOverflow { offset: usize, len: usize },
    PageFull { requested: usize, remaining: usize },
    OffsetNotAddressable { offset: usize },
    LengthNotAddressable { len: usize },
}

impl fmt::Display for SlabAppendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WriterPoisoned => write!(f, "published slab writer is poisoned"),
            Self::EmptyPayload => write!(f, "slab payload must be non-empty"),
            Self::FrameTooLarge { len, maximum } => {
                write!(f, "slab payload length {len} exceeds maximum {maximum}")
            }
            Self::DescriptorCapacityExhausted { capacity } => {
                write!(f, "slab descriptor capacity {capacity} is exhausted")
            }
            Self::OffsetLengthOverflow { offset, len } => {
                write!(f, "slab offset {offset} + length {len} overflows")
            }
            Self::PageFull {
                requested,
                remaining,
            } => write!(
                f,
                "slab page has {remaining} bytes remaining; append requested {requested}"
            ),
            Self::OffsetNotAddressable { offset } => {
                write!(f, "slab offset {offset} is not addressable by a descriptor")
            }
            Self::LengthNotAddressable { len } => {
                write!(f, "slab length {len} is not addressable by a descriptor")
            }
        }
    }
}

impl Error for SlabAppendError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlabReadError {
    ArenaIdMismatch {
        page: u16,
        descriptor: u16,
    },
    GenerationMismatch {
        page: u32,
        descriptor: u32,
    },
    EmptyPayload,
    Descriptor(DescriptorError),
    CrcMismatch {
        sequence: u64,
    },
    UnknownSequence {
        first: u64,
        count: usize,
        descriptor: u64,
    },
    DescriptorMismatch {
        sequence: u64,
    },
}

impl fmt::Display for SlabReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArenaIdMismatch { page, descriptor } => write!(
                f,
                "descriptor arena ID {descriptor} does not match slab page {page}"
            ),
            Self::GenerationMismatch { page, descriptor } => write!(
                f,
                "descriptor generation {descriptor} does not match slab page {page}"
            ),
            Self::EmptyPayload => write!(f, "descriptor payload must be non-empty"),
            Self::Descriptor(error) => write!(f, "invalid slab descriptor range: {error}"),
            Self::CrcMismatch { sequence } => {
                write!(f, "slab payload CRC32C mismatch for sequence {sequence}")
            }
            Self::UnknownSequence { first, count, descriptor } => write!(
                f,
                "descriptor sequence {descriptor} is outside sealed page sequence {first} with count {count}"
            ),
            Self::DescriptorMismatch { sequence } => write!(
                f,
                "descriptor metadata for sequence {sequence} does not match the sealed page table"
            ),
        }
    }
}

impl Error for SlabReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Descriptor(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> SlabPageConfig {
        SlabPageConfig {
            arena_id: 1,
            arena_generation: 2,
            byte_capacity: 64,
            descriptor_capacity: 4,
            first_sequence: 3,
        }
    }

    #[test]
    fn successful_appends_do_not_relocate_pre_reserved_storage() {
        let mut builder = SlabPageBuilder::new(config()).expect("bounded page");
        let bytes_ptr = builder.data.bytes.as_ptr();
        let descriptor_ptr = builder.data.descriptors.as_ptr();
        let byte_capacity = builder.data.bytes.capacity();
        let descriptor_capacity = builder.data.descriptors.capacity();

        builder.try_append(b"one", 1, 0).expect("first append");
        builder.try_append(b"two", 1, 0).expect("second append");

        assert_eq!(builder.data.bytes.as_ptr(), bytes_ptr);
        assert_eq!(builder.data.descriptors.as_ptr(), descriptor_ptr);
        assert_eq!(builder.data.bytes.capacity(), byte_capacity);
        assert_eq!(builder.data.descriptors.capacity(), descriptor_capacity);
    }

    #[test]
    fn seal_and_resolve_do_not_move_storage_or_increment_page_lease() {
        let mut builder = SlabPageBuilder::new(config()).expect("bounded page");
        builder.try_append(b"payload", 1, 0).expect("append");
        let bytes_ptr = builder.data.bytes.as_ptr();
        let sealed = builder.seal();
        assert_eq!(sealed.data.bytes.as_ptr(), bytes_ptr);

        let reader = sealed.reader();
        let lease_count = Arc::strong_count(&reader.data);
        let descriptor = sealed.descriptors()[0];
        let payload = reader.resolve(&descriptor).expect("resolve");

        assert_eq!(payload.as_ptr(), bytes_ptr);
        assert_eq!(Arc::strong_count(&reader.data), lease_count);
    }

    #[test]
    fn payload_corruption_is_reported_without_exposing_checksum_values() {
        let mut builder = SlabPageBuilder::new(config()).expect("bounded page");
        builder.try_append(b"payload", 1, 0).expect("append");
        builder.data.bytes[0] ^= 1;
        let sealed = builder.seal();
        let descriptor = sealed.descriptors()[0];
        let reader = sealed.reader();

        assert_eq!(
            reader.resolve(&descriptor),
            Err(SlabReadError::CrcMismatch { sequence: 3 })
        );
        assert_eq!(
            SlabReadError::CrcMismatch { sequence: 3 }.to_string(),
            "slab payload CRC32C mismatch for sequence 3"
        );
    }

    #[test]
    fn canonical_descriptor_range_corruption_fails_before_slicing() {
        let mut builder = SlabPageBuilder::new(config()).expect("bounded page");
        builder.try_append(b"payload", 1, 0).expect("append");
        builder.data.descriptors[0].offset = 6;
        builder.data.descriptors[0].len = 2;
        let sealed = builder.seal();
        let descriptor = sealed.descriptors()[0];
        let reader = sealed.reader();

        assert_eq!(
            reader.resolve(&descriptor),
            Err(SlabReadError::Descriptor(DescriptorError::OutOfBounds {
                end: 8,
                page_len: 7,
            }))
        );
    }

    #[test]
    fn crc_dependency_matches_a_scalar_castagnoli_oracle() {
        fn scalar_crc32c(bytes: &[u8]) -> u32 {
            let mut crc = !0_u32;
            for byte in bytes {
                crc ^= u32::from(*byte);
                for _ in 0..8 {
                    let mask = 0_u32.wrapping_sub(crc & 1);
                    crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
                }
            }
            !crc
        }

        assert_eq!(crc32c::crc32c(b"123456789"), 0xe306_9283);

        let maximum_length = if cfg!(miri) { 64 } else { 256 };
        let corpus: Vec<u8> = (0..maximum_length + 8)
            .map(|index| (index as u8).wrapping_mul(31).wrapping_add(17))
            .collect();
        for offset in 0..=7 {
            for len in 0..=maximum_length {
                let payload = &corpus[offset..offset + len];
                assert_eq!(crc32c::crc32c(payload), scalar_crc32c(payload));
            }
        }
    }
}
