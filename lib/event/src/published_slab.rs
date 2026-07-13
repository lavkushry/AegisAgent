//! Append-only slab pages with an atomically published immutable prefix.
//!
//! This is a current, unwired prototype under Proposed ADR-0008. It has no
//! registry, reset/reuse, epoch reclamation, NUMA allocation, protected-evidence
//! authority, or production integration.
//!
//! # Safety invariants
//!
//! - Construction fills fixed-length byte and descriptor cell vectors before
//!   sharing the page. Their lengths, capacities, and backing addresses never
//!   change afterward.
//! - `split` creates exactly one non-cloneable writer and reader. Both endpoints
//!   are `!Sync`; the writer mutates only through `&mut self`.
//! - The writer initializes each payload byte cell and descriptor cell exactly
//!   once, in append order. It never writes a committed cell.
//! - Every range, index, and integer conversion is validated before the first
//!   write. The mutation interval contains no fallible or indexing operation;
//!   caught unwinding poisons the writer so a partial suffix cannot be reused.
//! - A `Release` store of the packed publication state follows complete payload
//!   and descriptor initialization. A reader touches a descriptor cell only
//!   after an `Acquire` snapshot proves its index is committed.
//! - The same state snapshot includes a byte watermark. A reader constructs a
//!   payload view only from an exact canonical descriptor whose checked range
//!   is contained in that watermark.
//! - Native `ByteCell` and `DescriptorCell` wrappers are transparent over
//!   `UnsafeCell<MaybeUninit<T>>`, which has `T`'s representation. Raw pointers
//!   remain allocation-derived, aligned, and bounded by prevalidated slices.
//! - A native payload slice covers initialized committed `u8` cells only. Later
//!   appends target a disjoint suffix, and committed bytes are immutable for the
//!   rest of the allocation lifetime.
//! - Returned slices borrow the reader, whose page-level `Arc` keeps the fixed
//!   allocation alive. Final drop occurs only after both endpoints and all
//!   reader borrows are gone.
//! - Uncommitted cells contain `MaybeUninit<u8>` or
//!   `MaybeUninit<TelemetryDescriptor>` and have no drop obligation. This module
//!   has no persistent, cross-process, or endian ABI.

use std::{
    cell::Cell,
    error::Error,
    fmt,
    marker::PhantomData,
    mem::{align_of, size_of, MaybeUninit},
    ops::Deref,
};

#[cfg(feature = "loom")]
use loom::{
    cell::UnsafeCell,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
#[cfg(not(feature = "loom"))]
use std::{
    cell::UnsafeCell,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use crate::{
    slab::validate_config, DescriptorError, SlabAppendError, SlabConfigError, SlabPageConfig,
    SlabResource, TelemetryDescriptor, MAX_FRAME_BYTES,
};

const PUBLISHED_BYTES_MASK: u64 = u32::MAX as u64;
const PUBLISHED_COUNT_SHIFT: u32 = 32;
const PUBLISHED_COUNT_MASK: u64 = (1_u64 << 17) - 1;
const WRITER_CLOSED_BIT: u64 = 1_u64 << 63;
const VALID_STATE_MASK: u64 =
    PUBLISHED_BYTES_MASK | (PUBLISHED_COUNT_MASK << PUBLISHED_COUNT_SHIFT) | WRITER_CLOSED_BIT;
const RESERVED_STATE_MASK: u64 = !VALID_STATE_MASK;

#[derive(Clone, Copy)]
struct PublicationSnapshot {
    published_bytes: u32,
    published_count: u32,
    writer_closed: bool,
    reserved_bits: u64,
}

impl PublicationSnapshot {
    const fn decode(raw: u64) -> Self {
        Self {
            published_bytes: (raw & PUBLISHED_BYTES_MASK) as u32,
            published_count: ((raw >> PUBLISHED_COUNT_SHIFT) & PUBLISHED_COUNT_MASK) as u32,
            writer_closed: raw & WRITER_CLOSED_BIT != 0,
            reserved_bits: raw & RESERVED_STATE_MASK,
        }
    }
}

const fn encode_publication_state(published_count: u32, published_bytes: u32, closed: bool) -> u64 {
    let state = (published_bytes as u64) | ((published_count as u64) << PUBLISHED_COUNT_SHIFT);
    if closed {
        state | WRITER_CLOSED_BIT
    } else {
        state
    }
}

#[repr(align(64))]
struct PaddedPublicationState(AtomicU64);

#[repr(transparent)]
struct ByteCell(UnsafeCell<MaybeUninit<u8>>);

impl ByteCell {
    fn uninit() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }

    #[cfg(feature = "loom")]
    fn write(&self, value: u8) {
        self.0.with_mut(|cell| {
            // SAFETY: The sole writer owns this unpublished cell, writes it
            // exactly once, and publishes only after every byte is initialized.
            unsafe { (*cell).write(value) };
        });
    }

    #[cfg(feature = "loom")]
    fn read(&self) -> u8 {
        self.0.with(|cell| {
            // SAFETY: The reader reached this cell only after an Acquire state
            // snapshot proved the canonical byte range was initialized.
            unsafe { *(*cell).assume_init_ref() }
        })
    }

    #[cfg(all(test, not(feature = "loom")))]
    fn write_for_test(&self, value: u8) {
        // SAFETY: Each caller in this module's native tests proves it has no
        // concurrent cell access or outstanding view. Tests use the hook either
        // to inject committed-byte corruption or an unreachable partial suffix;
        // production code never calls it.
        unsafe { self.0.get().write(MaybeUninit::new(value)) };
    }
}

// SAFETY: Shared access is restricted to the single-assignment publication
// protocol above. The writer alone mutates an unpublished cell; readers access
// only committed cells after an Acquire snapshot and committed cells never
// change.
unsafe impl Sync for ByteCell {}

#[repr(transparent)]
struct DescriptorCell(UnsafeCell<MaybeUninit<TelemetryDescriptor>>);

impl DescriptorCell {
    fn uninit() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }

    #[cfg(not(feature = "loom"))]
    fn write(&self, descriptor: TelemetryDescriptor) {
        // SAFETY: The sole writer owns this unpublished descriptor slot and
        // initializes it exactly once before the Release publication store.
        unsafe { (*self.0.get()).write(descriptor) };
    }

    #[cfg(feature = "loom")]
    fn write(&self, descriptor: TelemetryDescriptor) {
        self.0.with_mut(|slot| {
            // SAFETY: The same single-writer and publication proof as the native
            // path applies; Loom tracks exclusive access to this modeled cell.
            unsafe { (*slot).write(descriptor) };
        });
    }

    #[cfg(not(feature = "loom"))]
    fn read(&self) -> TelemetryDescriptor {
        // SAFETY: An Acquire snapshot proved this slot was initialized, and the
        // writer never mutates a committed descriptor. The descriptor is Copy.
        unsafe { *(*self.0.get()).assume_init_ref() }
    }

    #[cfg(feature = "loom")]
    fn read(&self) -> TelemetryDescriptor {
        self.0.with(|slot| {
            // SAFETY: The same committed-slot proof as the native path applies;
            // Loom tracks immutable access to this modeled cell.
            unsafe { *(*slot).assume_init_ref() }
        })
    }
}

// SAFETY: The sole writer initializes each descriptor cell once before Release
// publication. Readers access only slots proven committed by an Acquire state
// snapshot, and committed descriptors are never changed.
unsafe impl Sync for DescriptorCell {}

#[repr(C)]
struct PublishedInner {
    publication: PaddedPublicationState,
    arena_id: u16,
    arena_generation: u32,
    byte_capacity: usize,
    descriptor_capacity: usize,
    first_sequence: u64,
    bytes: Vec<ByteCell>,
    descriptors: Vec<DescriptorCell>,
}

impl PublishedInner {
    fn snapshot_is_valid(&self, snapshot: PublicationSnapshot) -> bool {
        let published_count = snapshot.published_count as usize;
        let published_bytes = snapshot.published_bytes as usize;
        let empty_fields_disagree = (published_count == 0) != (published_bytes == 0);

        snapshot.reserved_bits == 0
            && published_count <= self.descriptor_capacity
            && published_bytes <= self.byte_capacity
            && published_bytes >= published_count
            && !empty_fields_disagree
    }

    fn load_snapshot(&self) -> Result<PublicationSnapshot, PublishedSlabReadError> {
        let snapshot = PublicationSnapshot::decode(self.publication.0.load(Ordering::Acquire));
        if !self.snapshot_is_valid(snapshot) {
            return Err(PublishedSlabReadError::PublicationStateInvalid);
        }

        Ok(snapshot)
    }

    #[cfg(not(feature = "loom"))]
    fn payload(
        &self,
        range: std::ops::Range<usize>,
    ) -> Result<PublishedPayload<'_>, PublishedSlabReadError> {
        let cells = self
            .bytes
            .get(range)
            .ok_or(PublishedSlabReadError::PublicationStateInvalid)?;
        if cells.is_empty() {
            return Err(PublishedSlabReadError::PublicationStateInvalid);
        }

        // SAFETY: `ByteCell` is transparent over
        // `UnsafeCell<MaybeUninit<u8>>`, so this allocation-derived pointer is
        // aligned for `u8`. The canonical non-empty range was checked against
        // the Acquire-published byte watermark. Every cell in it was initialized
        // before that Release store, will never be written again, and remains
        // alive for the returned borrow through this page-owning reader.
        let bytes = unsafe { std::slice::from_raw_parts(cells.as_ptr().cast::<u8>(), cells.len()) };
        Ok(PublishedPayload {
            bytes,
            _reader: PhantomData,
        })
    }

    #[cfg(feature = "loom")]
    fn payload(
        &self,
        range: std::ops::Range<usize>,
    ) -> Result<PublishedPayload<'_>, PublishedSlabReadError> {
        let cells = self
            .bytes
            .get(range)
            .ok_or(PublishedSlabReadError::PublicationStateInvalid)?;
        if cells.is_empty() {
            return Err(PublishedSlabReadError::PublicationStateInvalid);
        }

        // Loom pointers may not escape `UnsafeCell::with`; copy each modeled
        // byte while its access guard is active. This model-only allocation is
        // excluded from the native zero-copy boundary and documented in ADR-0008.
        let bytes = cells.iter().map(ByteCell::read).collect();
        Ok(PublishedPayload {
            bytes,
            _reader: PhantomData,
        })
    }
}

/// Setup handle for one fixed-capacity append-only page.
pub struct PublishedSlabPage {
    inner: Arc<PublishedInner>,
}

impl PublishedSlabPage {
    pub fn new(config: SlabPageConfig) -> Result<Self, SlabConfigError> {
        validate_config(config)?;

        let mut bytes = Vec::new();
        bytes.try_reserve_exact(config.byte_capacity).map_err(|_| {
            SlabConfigError::AllocationFailed {
                resource: SlabResource::PayloadBytes,
                requested: config.byte_capacity,
            }
        })?;
        bytes.resize_with(config.byte_capacity, ByteCell::uninit);

        let mut descriptors = Vec::new();
        descriptors
            .try_reserve_exact(config.descriptor_capacity)
            .map_err(|_| SlabConfigError::AllocationFailed {
                resource: SlabResource::Descriptors,
                requested: config.descriptor_capacity,
            })?;
        descriptors.resize_with(config.descriptor_capacity, DescriptorCell::uninit);

        Ok(Self {
            inner: Arc::new(PublishedInner {
                publication: PaddedPublicationState(AtomicU64::new(0)),
                arena_id: config.arena_id,
                arena_generation: config.arena_generation,
                byte_capacity: config.byte_capacity,
                descriptor_capacity: config.descriptor_capacity,
                first_sequence: config.first_sequence,
                bytes,
                descriptors,
            }),
        })
    }

    pub fn split(self) -> (PublishedSlabWriter, PublishedSlabReader) {
        let Self { inner } = self;
        let reader_inner = Arc::clone(&inner);
        let first_sequence = inner.first_sequence;

        (
            PublishedSlabWriter {
                inner,
                used_bytes: 0,
                descriptor_count: 0,
                next_sequence: first_sequence,
                poisoned: false,
                _not_sync: PhantomData,
            },
            PublishedSlabReader {
                inner: reader_inner,
                _not_sync: PhantomData,
            },
        )
    }

    pub fn layout(&self) -> PublishedSlabLayout {
        PublishedSlabLayout {
            publication_state_alignment: align_of::<PaddedPublicationState>(),
            publication_state_size: size_of::<PaddedPublicationState>(),
            byte_cell_size: size_of::<ByteCell>(),
            byte_cell_alignment: align_of::<ByteCell>(),
            descriptor_cell_size: size_of::<DescriptorCell>(),
            descriptor_cell_alignment: align_of::<DescriptorCell>(),
        }
    }

    pub fn arena_id(&self) -> u16 {
        self.inner.arena_id
    }

    pub fn arena_generation(&self) -> u32 {
        self.inner.arena_generation
    }

    pub fn byte_capacity(&self) -> usize {
        self.inner.byte_capacity
    }

    pub fn descriptor_capacity(&self) -> usize {
        self.inner.descriptor_capacity
    }
}

impl fmt::Debug for PublishedSlabPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublishedSlabPage")
            .field("arena_id", &self.arena_id())
            .field("arena_generation", &self.arena_generation())
            .field("byte_capacity", &self.byte_capacity())
            .field("descriptor_capacity", &self.descriptor_capacity())
            .finish()
    }
}

/// Single-owner append capability for one published-prefix page.
///
/// The endpoint intentionally implements neither `Sync` nor `Clone`:
///
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<aegis_event::PublishedSlabWriter>();
/// ```
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<aegis_event::PublishedSlabWriter>();
/// ```
pub struct PublishedSlabWriter {
    inner: Arc<PublishedInner>,
    used_bytes: u32,
    descriptor_count: u32,
    next_sequence: u64,
    poisoned: bool,
    _not_sync: PhantomData<Cell<()>>,
}

#[derive(Clone, Copy)]
struct AppendPlan {
    descriptor_index: usize,
    offset: usize,
    end: usize,
    descriptor_offset: u32,
    descriptor_len: u32,
    published_bytes: u32,
    next_count: u32,
    next_sequence: u64,
}

impl PublishedSlabWriter {
    fn append_plan(&self, len: usize) -> Result<AppendPlan, SlabAppendError> {
        if self.poisoned {
            return Err(SlabAppendError::WriterPoisoned);
        }
        if len == 0 {
            return Err(SlabAppendError::EmptyPayload);
        }
        if len > MAX_FRAME_BYTES {
            return Err(SlabAppendError::FrameTooLarge {
                len,
                maximum: MAX_FRAME_BYTES,
            });
        }

        let descriptor_index = self.descriptor_count as usize;
        if descriptor_index >= self.inner.descriptor_capacity {
            return Err(SlabAppendError::DescriptorCapacityExhausted {
                capacity: self.inner.descriptor_capacity,
            });
        }

        let offset = self.used_bytes as usize;
        let remaining =
            self.inner
                .byte_capacity
                .checked_sub(offset)
                .ok_or(SlabAppendError::PageFull {
                    requested: len,
                    remaining: 0,
                })?;
        let end = offset
            .checked_add(len)
            .ok_or(SlabAppendError::OffsetLengthOverflow { offset, len })?;
        if len > remaining || end > self.inner.byte_capacity {
            return Err(SlabAppendError::PageFull {
                requested: len,
                remaining,
            });
        }

        let descriptor_offset =
            u32::try_from(offset).map_err(|_| SlabAppendError::OffsetNotAddressable { offset })?;
        let descriptor_len =
            u32::try_from(len).map_err(|_| SlabAppendError::LengthNotAddressable { len })?;
        let published_bytes = u32::try_from(end)
            .map_err(|_| SlabAppendError::OffsetNotAddressable { offset: end })?;

        Ok(AppendPlan {
            descriptor_index,
            offset,
            end,
            descriptor_offset,
            descriptor_len,
            published_bytes,
            next_count: self.descriptor_count + 1,
            next_sequence: self.next_sequence.wrapping_add(1),
        })
    }

    /// Checks every payload-length and current-capacity condition without CRC,
    /// allocation, page mutation, or publication.
    pub(crate) fn preflight_append(&self, len: usize) -> Result<(), SlabAppendError> {
        self.append_plan(len).map(|_| ())
    }

    /// Replaces the last canonical descriptor for corrupt-input tests.
    ///
    /// # Safety
    ///
    /// No reader may access the page before this test-only rewrite completes.
    /// The method deliberately violates published-prefix immutability and must
    /// never be used outside a single-threaded corruption fixture.
    #[cfg(all(test, not(feature = "loom")))]
    pub(crate) unsafe fn overwrite_last_descriptor_for_test(
        &mut self,
        descriptor: TelemetryDescriptor,
    ) {
        let index =
            self.descriptor_count
                .checked_sub(1)
                .expect("test corruption requires one published descriptor") as usize;
        let cell = self
            .inner
            .descriptors
            .get(index)
            .expect("published test descriptor index remains in bounds");
        cell.write(descriptor);
    }

    /// Copies, initializes, and Release-publishes one complete payload.
    ///
    /// FlatBuffer verification and redaction are upstream preconditions. Every
    /// returned error is transactional; no descriptor escapes before the state
    /// publication store.
    pub fn try_append(
        &mut self,
        payload: &[u8],
        schema_id: u32,
        flags: u16,
    ) -> Result<TelemetryDescriptor, SlabAppendError> {
        let len = payload.len();
        let plan = self.append_plan(len)?;
        let checksum = crc32c::crc32c(payload);
        let descriptor = TelemetryDescriptor {
            sequence: self.next_sequence,
            arena_generation: self.inner.arena_generation,
            arena_id: self.inner.arena_id,
            flags,
            offset: plan.descriptor_offset,
            len: plan.descriptor_len,
            crc32c: checksum,
            schema_id,
        };
        let next_state = encode_publication_state(plan.next_count, plan.published_bytes, false);

        // Stage every bounds-checked reference and native pointer before the
        // first cell is touched. No indexing or fallible work follows.
        let payload_cells =
            self.inner
                .bytes
                .get(plan.offset..plan.end)
                .ok_or(SlabAppendError::PageFull {
                    requested: len,
                    remaining: self.inner.byte_capacity - plan.offset,
                })?;
        let descriptor_cell = self.inner.descriptors.get(plan.descriptor_index).ok_or(
            SlabAppendError::DescriptorCapacityExhausted {
                capacity: self.inner.descriptor_capacity,
            },
        )?;

        #[cfg(not(feature = "loom"))]
        let payload_destination = payload_cells.as_ptr().cast::<u8>().cast_mut();

        self.poisoned = true;

        #[cfg(not(feature = "loom"))]
        {
            // SAFETY: Source and destination both contain `len` initialized-byte
            // positions. The destination is a checked never-written suffix. A
            // source borrowed from this page can only be an earlier committed
            // range, which is disjoint from the append-only destination.
            unsafe {
                std::ptr::copy_nonoverlapping(payload.as_ptr(), payload_destination, len);
            }
        }

        #[cfg(feature = "loom")]
        for (cell, value) in payload_cells.iter().zip(payload.iter().copied()) {
            cell.write(value);
        }

        descriptor_cell.write(descriptor);
        self.inner
            .publication
            .0
            .store(next_state, Ordering::Release);
        self.used_bytes = plan.published_bytes;
        self.descriptor_count = plan.next_count;
        self.next_sequence = plan.next_sequence;
        self.poisoned = false;

        Ok(descriptor)
    }

    pub fn arena_id(&self) -> u16 {
        self.inner.arena_id
    }

    pub fn arena_generation(&self) -> u32 {
        self.inner.arena_generation
    }

    pub fn byte_capacity(&self) -> usize {
        self.inner.byte_capacity
    }

    pub fn descriptor_capacity(&self) -> usize {
        self.inner.descriptor_capacity
    }

    pub fn used_bytes(&self) -> usize {
        self.used_bytes as usize
    }

    pub fn published_count(&self) -> usize {
        self.descriptor_count as usize
    }

    pub fn remaining_bytes(&self) -> usize {
        self.inner.byte_capacity - self.used_bytes as usize
    }

    pub fn remaining_descriptors(&self) -> usize {
        self.inner.descriptor_capacity - self.descriptor_count as usize
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub(crate) fn close(&mut self) {
        self.inner
            .publication
            .0
            .fetch_or(WRITER_CLOSED_BIT, Ordering::Release);
    }
}

impl Drop for PublishedSlabWriter {
    fn drop(&mut self) {
        // The atomic word, rather than writer-private staged cursors, is the
        // authoritative committed prefix. `fetch_or` cannot regress or expose a
        // partially written suffix if unwinding interrupts an append.
        self.close();
    }
}

impl fmt::Debug for PublishedSlabWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublishedSlabWriter")
            .field("arena_id", &self.arena_id())
            .field("arena_generation", &self.arena_generation())
            .field("byte_capacity", &self.byte_capacity())
            .field("descriptor_capacity", &self.descriptor_capacity())
            .field("used_bytes", &self.used_bytes())
            .field("published_count", &self.published_count())
            .field("next_sequence", &self.next_sequence())
            .field("poisoned", &self.is_poisoned())
            .finish()
    }
}

/// Single-owner reader capability for one atomically published prefix.
///
/// The endpoint intentionally implements neither `Sync` nor `Clone`:
///
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<aegis_event::PublishedSlabReader>();
/// ```
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<aegis_event::PublishedSlabReader>();
/// ```
pub struct PublishedSlabReader {
    inner: Arc<PublishedInner>,
    _not_sync: PhantomData<Cell<()>>,
}

impl PublishedSlabReader {
    /// Resolves one exact canonical descriptor to a page-backed payload view.
    pub fn resolve(
        &self,
        descriptor: &TelemetryDescriptor,
    ) -> Result<PublishedPayload<'_>, PublishedSlabReadError> {
        if descriptor.arena_id != self.inner.arena_id {
            return Err(PublishedSlabReadError::ArenaIdMismatch {
                page: self.inner.arena_id,
                descriptor: descriptor.arena_id,
            });
        }
        if descriptor.arena_generation != self.inner.arena_generation {
            return Err(PublishedSlabReadError::GenerationMismatch {
                page: self.inner.arena_generation,
                descriptor: descriptor.arena_generation,
            });
        }

        let snapshot = self.inner.load_snapshot()?;
        let distance = descriptor.sequence.wrapping_sub(self.inner.first_sequence);
        if distance >= snapshot.published_count as u64 {
            return Err(PublishedSlabReadError::UnpublishedSequence {
                first: self.inner.first_sequence,
                committed: snapshot.published_count as usize,
                descriptor: descriptor.sequence,
            });
        }

        let index = distance as usize;
        let canonical = self
            .inner
            .descriptors
            .get(index)
            .ok_or(PublishedSlabReadError::PublicationStateInvalid)?
            .read();
        if canonical != *descriptor {
            return Err(PublishedSlabReadError::DescriptorMismatch {
                sequence: descriptor.sequence,
            });
        }
        if canonical.len == 0 {
            return Err(PublishedSlabReadError::EmptyCanonicalPayload {
                sequence: canonical.sequence,
            });
        }

        let range = canonical
            .checked_payload_range(snapshot.published_bytes as usize)
            .map_err(PublishedSlabReadError::Descriptor)?;
        let payload = self.inner.payload(range)?;
        if crc32c::crc32c(payload.as_ref()) != canonical.crc32c {
            return Err(PublishedSlabReadError::CrcMismatch {
                sequence: canonical.sequence,
            });
        }

        Ok(payload)
    }

    pub fn arena_id(&self) -> u16 {
        self.inner.arena_id
    }

    pub fn arena_generation(&self) -> u32 {
        self.inner.arena_generation
    }

    pub fn byte_capacity(&self) -> usize {
        self.inner.byte_capacity
    }

    pub fn descriptor_capacity(&self) -> usize {
        self.inner.descriptor_capacity
    }

    pub fn published_count(&self) -> usize {
        PublicationSnapshot::decode(self.inner.publication.0.load(Ordering::Acquire))
            .published_count as usize
    }

    pub fn published_bytes(&self) -> usize {
        PublicationSnapshot::decode(self.inner.publication.0.load(Ordering::Acquire))
            .published_bytes as usize
    }

    pub fn is_writer_closed(&self) -> bool {
        PublicationSnapshot::decode(self.inner.publication.0.load(Ordering::Acquire)).writer_closed
    }

    /// Returns one validated, coherent publication snapshot.
    pub fn status(&self) -> Result<PublishedSlabStatus, PublishedSlabReadError> {
        let snapshot = self.inner.load_snapshot()?;
        Ok(PublishedSlabStatus {
            published_count: snapshot.published_count as usize,
            published_bytes: snapshot.published_bytes as usize,
            writer_closed: snapshot.writer_closed,
        })
    }
}

impl fmt::Debug for PublishedSlabReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let snapshot =
            PublicationSnapshot::decode(self.inner.publication.0.load(Ordering::Acquire));
        f.debug_struct("PublishedSlabReader")
            .field("arena_id", &self.arena_id())
            .field("arena_generation", &self.arena_generation())
            .field("byte_capacity", &self.byte_capacity())
            .field("descriptor_capacity", &self.descriptor_capacity())
            .field("published_count", &snapshot.published_count)
            .field("published_bytes", &snapshot.published_bytes)
            .field("writer_closed", &snapshot.writer_closed)
            .field("state_valid", &self.inner.snapshot_is_valid(snapshot))
            .finish()
    }
}

/// Borrowed native page view; Loom owns a disclosed model-only byte copy.
#[must_use]
pub struct PublishedPayload<'reader> {
    #[cfg(not(feature = "loom"))]
    bytes: &'reader [u8],
    #[cfg(feature = "loom")]
    bytes: Vec<u8>,
    _reader: PhantomData<&'reader PublishedSlabReader>,
}

impl AsRef<[u8]> for PublishedPayload<'_> {
    fn as_ref(&self) -> &[u8] {
        #[cfg(not(feature = "loom"))]
        {
            self.bytes
        }
        #[cfg(feature = "loom")]
        {
            &self.bytes
        }
    }
}

impl Deref for PublishedPayload<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl PartialEq for PublishedPayload<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for PublishedPayload<'_> {}

impl fmt::Debug for PublishedPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublishedPayload")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedSlabLayout {
    pub publication_state_alignment: usize,
    pub publication_state_size: usize,
    pub byte_cell_size: usize,
    pub byte_cell_alignment: usize,
    pub descriptor_cell_size: usize,
    pub descriptor_cell_alignment: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedSlabStatus {
    pub published_count: usize,
    pub published_bytes: usize,
    pub writer_closed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishedSlabReadError {
    ArenaIdMismatch {
        page: u16,
        descriptor: u16,
    },
    GenerationMismatch {
        page: u32,
        descriptor: u32,
    },
    PublicationStateInvalid,
    UnpublishedSequence {
        first: u64,
        committed: usize,
        descriptor: u64,
    },
    DescriptorMismatch {
        sequence: u64,
    },
    EmptyCanonicalPayload {
        sequence: u64,
    },
    Descriptor(DescriptorError),
    CrcMismatch {
        sequence: u64,
    },
}

impl fmt::Display for PublishedSlabReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArenaIdMismatch { page, descriptor } => write!(
                f,
                "descriptor arena ID {descriptor} does not match published slab page {page}"
            ),
            Self::GenerationMismatch { page, descriptor } => write!(
                f,
                "descriptor generation {descriptor} does not match published slab page {page}"
            ),
            Self::PublicationStateInvalid => {
                write!(f, "published slab page state is invalid")
            }
            Self::UnpublishedSequence {
                first,
                committed,
                descriptor,
            } => write!(
                f,
                "descriptor sequence {descriptor} is outside published slab sequence {first} with committed count {committed}"
            ),
            Self::DescriptorMismatch { sequence } => write!(
                f,
                "descriptor metadata for sequence {sequence} does not match the published page table"
            ),
            Self::EmptyCanonicalPayload { sequence } => write!(
                f,
                "published slab canonical payload is empty for sequence {sequence}"
            ),
            Self::Descriptor(error) => {
                write!(f, "invalid published slab descriptor range: {error}")
            }
            Self::CrcMismatch { sequence } => {
                write!(f, "published slab payload CRC32C mismatch for sequence {sequence}")
            }
        }
    }
}

impl Error for PublishedSlabReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Descriptor(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(all(test, not(feature = "loom")))]
mod native_tests {
    use super::{
        encode_publication_state, Arc, Ordering, PublicationSnapshot, PublishedSlabPage,
        PublishedSlabReadError,
    };
    use crate::{
        SlabAppendError, SlabPageConfig, TelemetryDescriptor, MAX_SLAB_DESCRIPTORS,
        MAX_SLAB_PAGE_BYTES,
    };

    fn config(byte_capacity: usize, descriptor_capacity: usize) -> SlabPageConfig {
        SlabPageConfig {
            arena_id: 5,
            arena_generation: 8,
            byte_capacity,
            descriptor_capacity,
            first_sequence: 13,
        }
    }

    #[test]
    fn packed_state_fields_cover_the_exact_page_limits_without_reserved_bits() {
        let snapshot = PublicationSnapshot::decode(encode_publication_state(
            MAX_SLAB_DESCRIPTORS as u32,
            MAX_SLAB_PAGE_BYTES as u32,
            true,
        ));

        assert_eq!(snapshot.published_count as usize, MAX_SLAB_DESCRIPTORS);
        assert_eq!(snapshot.published_bytes as usize, MAX_SLAB_PAGE_BYTES);
        assert!(snapshot.writer_closed);
        assert_eq!(snapshot.reserved_bits, 0);
    }

    #[test]
    fn published_resolve_does_not_change_the_page_arc_count() {
        let page = PublishedSlabPage::new(config(16, 1)).expect("bounded page");
        let (mut writer, reader) = page.split();
        let descriptor = writer.try_append(b"payload", 1, 0).expect("payload fits");
        let before = Arc::strong_count(&reader.inner);

        for _ in 0..32 {
            let payload = reader.resolve(&descriptor).expect("descriptor resolves");
            assert_eq!(payload.as_ref(), b"payload");
        }

        assert_eq!(Arc::strong_count(&reader.inner), before);
    }

    #[test]
    fn committed_byte_corruption_fails_closed_without_disclosing_checksums() {
        let page = PublishedSlabPage::new(config(16, 1)).expect("bounded page");
        let (mut writer, reader) = page.split();
        let descriptor = writer
            .try_append(b"raw-secret", 1, 0)
            .expect("payload fits");
        reader.inner.bytes[0].write_for_test(b'X');

        let error = reader
            .resolve(&descriptor)
            .expect_err("corrupt committed bytes must fail");
        assert_eq!(error, PublishedSlabReadError::CrcMismatch { sequence: 13 });
        let message = error.to_string();
        assert!(!message.contains(&format!("{:08x}", descriptor.crc32c)));
        assert!(!message.contains("raw-secret"));
    }

    #[test]
    fn poisoned_partial_suffix_is_never_published_or_reused() {
        let page = PublishedSlabPage::new(config(8, 1)).expect("bounded page");
        let (mut writer, reader) = page.split();

        writer.poisoned = true;
        writer.inner.bytes[0].write_for_test(b'X');
        assert_eq!(
            writer.try_append(b"replacement", 1, 0),
            Err(SlabAppendError::WriterPoisoned)
        );
        assert_eq!(reader.published_count(), 0);

        let unreachable = TelemetryDescriptor {
            sequence: 13,
            arena_generation: 8,
            arena_id: 5,
            flags: 0,
            offset: 0,
            len: 1,
            crc32c: crc32c::crc32c(b"X"),
            schema_id: 1,
        };
        assert_eq!(
            reader.resolve(&unreachable),
            Err(PublishedSlabReadError::UnpublishedSequence {
                first: 13,
                committed: 0,
                descriptor: 13,
            })
        );

        drop(writer);
        assert!(reader.is_writer_closed());
        assert_eq!(reader.published_count(), 0);
        assert_eq!(reader.published_bytes(), 0);
    }

    #[test]
    fn writer_drop_closes_atomic_prefix_even_if_private_cursors_are_stale() {
        let page = PublishedSlabPage::new(config(16, 1)).expect("bounded page");
        let (mut writer, reader) = page.split();
        let descriptor = writer.try_append(b"atomic", 1, 0).expect("payload fits");

        // Simulate an unwind immediately after the Release publication and
        // before the staged cursor assignments. Drop must consult the atomic
        // prefix and must never regress it to these stale private values.
        writer.used_bytes = 0;
        writer.descriptor_count = 0;
        writer.next_sequence = 13;
        writer.poisoned = true;
        drop(writer);

        assert!(reader.is_writer_closed());
        assert_eq!(reader.published_count(), 1);
        assert_eq!(reader.published_bytes(), 6);
        assert_eq!(
            reader
                .resolve(&descriptor)
                .expect("atomic prefix survives drop")
                .as_ref(),
            b"atomic"
        );
    }

    #[test]
    fn malformed_packed_state_fails_before_any_descriptor_cell_read() {
        let page = PublishedSlabPage::new(config(8, 1)).expect("bounded page");
        let (writer, reader) = page.split();
        let forged = TelemetryDescriptor {
            sequence: 13,
            arena_generation: 8,
            arena_id: 5,
            flags: 0,
            offset: 0,
            len: 1,
            crc32c: 0,
            schema_id: 1,
        };

        let reserved_bit = 1_u64 << 49;
        reader.inner.publication.0.store(
            encode_publication_state(1, 1, false) | reserved_bit,
            Ordering::Release,
        );
        assert_eq!(
            reader.resolve(&forged),
            Err(PublishedSlabReadError::PublicationStateInvalid)
        );

        reader
            .inner
            .publication
            .0
            .store(encode_publication_state(2, 2, false), Ordering::Release);
        assert_eq!(
            reader.resolve(&forged),
            Err(PublishedSlabReadError::PublicationStateInvalid)
        );

        drop(writer);
    }

    #[test]
    fn endpoints_can_move_to_their_owner_threads() {
        fn assert_send<T: Send>() {}

        assert_send::<super::PublishedSlabWriter>();
        assert_send::<super::PublishedSlabReader>();
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::{PublishedSlabPage, PublishedSlabReadError};
    use crate::{SlabPageConfig, SpscRing, TelemetryDescriptor, TryPopError, TryPushError};
    use loom::thread;

    fn config(byte_capacity: usize, descriptor_capacity: usize) -> SlabPageConfig {
        SlabPageConfig {
            arena_id: 5,
            arena_generation: 8,
            byte_capacity,
            descriptor_capacity,
            first_sequence: u64::MAX,
        }
    }

    fn descriptor(sequence: u64, offset: u32, payload: &[u8]) -> TelemetryDescriptor {
        TelemetryDescriptor {
            sequence,
            arena_generation: 8,
            arena_id: 5,
            flags: 1,
            offset,
            len: payload.len() as u32,
            crc32c: crc32c::crc32c(payload),
            schema_id: 7,
        }
    }

    #[test]
    fn loom_published_resolve_observes_nothing_or_a_complete_first_frame() {
        loom::model(|| {
            let page = PublishedSlabPage::new(config(2, 2)).expect("bounded model page");
            let (mut writer, reader) = page.split();
            let expected = descriptor(u64::MAX, 0, b"A");

            let writer_thread = thread::spawn(move || {
                let actual = writer.try_append(b"A", 7, 1).expect("model append fits");
                assert_eq!(actual, expected);
            });
            let reader_thread = thread::spawn(move || match reader.resolve(&expected) {
                Ok(payload) => assert_eq!(payload.as_ref(), b"A"),
                Err(PublishedSlabReadError::UnpublishedSequence {
                    first,
                    committed,
                    descriptor,
                }) => {
                    assert_eq!(first, u64::MAX);
                    assert_eq!(committed, 0);
                    assert_eq!(descriptor, u64::MAX);
                }
                Err(error) => panic!("unexpected publication result: {error}"),
            });

            writer_thread.join().expect("model writer succeeds");
            reader_thread.join().expect("model reader succeeds");
        });
    }

    #[test]
    fn loom_published_later_state_also_publishes_every_earlier_slot() {
        loom::model(|| {
            let page = PublishedSlabPage::new(config(2, 2)).expect("bounded model page");
            let (mut writer, reader) = page.split();
            let first = descriptor(u64::MAX, 0, b"A");
            let second = descriptor(0, 1, b"B");

            let writer_thread = thread::spawn(move || {
                writer.try_append(b"A", 7, 1).expect("first append fits");
                thread::yield_now();
                writer.try_append(b"B", 7, 1).expect("second append fits");
            });
            let reader_thread = thread::spawn(move || {
                let first_attempt = reader.resolve(&first);
                let second_attempt = reader.resolve(&second);

                match second_attempt {
                    Ok(second_payload) => {
                        assert_eq!(second_payload.as_ref(), b"B");
                        assert_eq!(
                            reader
                                .resolve(&first)
                                .expect("later state publishes prefix")
                                .as_ref(),
                            b"A"
                        );
                    }
                    Err(PublishedSlabReadError::UnpublishedSequence { committed, .. }) => {
                        assert!(committed <= 1);
                    }
                    Err(error) => panic!("unexpected second-frame result: {error}"),
                }
                match first_attempt {
                    Ok(first_payload) => assert_eq!(first_payload.as_ref(), b"A"),
                    Err(PublishedSlabReadError::UnpublishedSequence { committed, .. }) => {
                        assert_eq!(committed, 0);
                    }
                    Err(error) => panic!("unexpected first-frame result: {error}"),
                }

                if reader.is_writer_closed() {
                    assert_eq!(reader.published_count(), 2);
                    assert_eq!(reader.published_bytes(), 2);
                    assert_eq!(reader.resolve(&first).expect("closed first").as_ref(), b"A");
                    assert_eq!(
                        reader.resolve(&second).expect("closed second").as_ref(),
                        b"B"
                    );
                }
            });

            writer_thread.join().expect("model writer succeeds");
            reader_thread.join().expect("model reader succeeds");
        });
    }

    #[test]
    fn loom_published_writer_drop_closes_the_complete_final_prefix() {
        loom::model(|| {
            let page = PublishedSlabPage::new(config(2, 2)).expect("bounded model page");
            let (mut writer, reader) = page.split();
            let first = descriptor(u64::MAX, 0, b"A");
            let second = descriptor(0, 1, b"B");

            let writer_thread = thread::spawn(move || {
                writer.try_append(b"A", 7, 1).expect("first append fits");
                writer.try_append(b"B", 7, 1).expect("second append fits");
            });
            writer_thread.join().expect("model writer closes cleanly");

            assert!(reader.is_writer_closed());
            assert_eq!(reader.published_count(), 2);
            assert_eq!(reader.published_bytes(), 2);
            assert_eq!(reader.resolve(&first).expect("final first").as_ref(), b"A");
            assert_eq!(
                reader.resolve(&second).expect("final second").as_ref(),
                b"B"
            );
        });
    }

    #[test]
    fn loom_published_page_and_ring_compose_without_partial_visibility() {
        loom::model(|| {
            let page = PublishedSlabPage::new(config(1, 1)).expect("bounded model page");
            let (mut writer, reader) = page.split();
            let ring = SpscRing::<TelemetryDescriptor, 1>::new().expect("model ring");
            let (mut producer, mut consumer) = ring.split();

            let writer_thread = thread::spawn(move || {
                let mut pending = writer.try_append(b"A", 7, 1).expect("model append fits");
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

            let reader_thread = thread::spawn(move || {
                let published = loop {
                    match consumer.try_pop() {
                        Ok(value) => break value,
                        Err(TryPopError::Empty) => thread::yield_now(),
                        Err(TryPopError::Disconnected) => {
                            panic!("model producer disconnected before publication")
                        }
                    }
                };
                assert_eq!(
                    reader
                        .resolve(&published)
                        .expect("ring publication implies page publication")
                        .as_ref(),
                    b"A"
                );
            });

            writer_thread.join().expect("model writer succeeds");
            reader_thread.join().expect("model reader succeeds");
        });
    }
}
