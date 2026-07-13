//! Bounded event-transfer primitives for the target AegisAgent data plane.
//!
//! This crate contains unwired prototypes governed by Proposed ADR-0006,
//! ADR-0007, and ADR-0008. It does not carry production telemetry or protected
//! evidence.
//!
//! The optional `loom` feature is model-checking infrastructure, not a runtime
//! configuration. Loom-backed primitives must execute only inside
//! `loom::model`.

#![forbid(unsafe_op_in_unsafe_fn)]

mod descriptor;
mod published_slab;
mod ring;
mod slab;

pub use descriptor::{DescriptorError, TelemetryDescriptor, MAX_FRAME_BYTES};
pub use published_slab::{
    PublishedPayload, PublishedSlabLayout, PublishedSlabPage, PublishedSlabReadError,
    PublishedSlabReader, PublishedSlabWriter,
};
pub use ring::{
    Consumer, Producer, RingConfigError, RingLayout, SpscRing, TryPopError, TryPushError,
    CACHE_LINE_BYTES,
};
pub use slab::{
    SealedSlabPage, SlabAppendError, SlabConfigError, SlabPageBuilder, SlabPageConfig,
    SlabPageReader, SlabReadError, SlabResource, MAX_SLAB_DESCRIPTORS, MAX_SLAB_PAGE_BYTES,
};
