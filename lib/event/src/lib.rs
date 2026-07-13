//! Bounded event-transfer primitives for the target AegisAgent data plane.
//!
//! This crate contains unwired prototypes governed by Proposed ADR-0006,
//! ADR-0007, ADR-0008, and ADR-0009. It does not carry production telemetry or
//! protected evidence.
//!
//! The optional `loom` feature is model-checking infrastructure, not a runtime
//! configuration. Loom-backed primitives must execute only inside
//! `loom::model`.

#![forbid(unsafe_op_in_unsafe_fn)]

mod admission;
mod descriptor;
mod published_slab;
mod ring;
mod slab;

pub use admission::{
    AdmissionConfigError, AdmissionConsumer, AdmissionProducer, AdmittedEvent, AdmittedSequence,
    FinishError, TryAdmitError, TryConsumeError, VolatileAdmissionChannel,
};
pub use descriptor::{DescriptorError, TelemetryDescriptor, MAX_FRAME_BYTES};
pub use published_slab::{
    PublishedPayload, PublishedSlabLayout, PublishedSlabPage, PublishedSlabReadError,
    PublishedSlabReader, PublishedSlabStatus, PublishedSlabWriter,
};
pub use ring::{
    Consumer, OccupiedSlot, Producer, RingConfigError, RingInvariantError, RingLayout, SpscRing,
    TryClaimError, TryPopError, TryPushError, TryReserveError, VacantSlot, CACHE_LINE_BYTES,
};
pub use slab::{
    SealedSlabPage, SlabAppendError, SlabConfigError, SlabPageBuilder, SlabPageConfig,
    SlabPageReader, SlabReadError, SlabResource, MAX_SLAB_DESCRIPTORS, MAX_SLAB_PAGE_BYTES,
};
