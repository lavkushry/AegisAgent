//! v2 wire-contract schemas for the target AegisAgent data plane.
//!
//! This crate holds UNWIRED prototypes governed by Proposed ADR-0011. It
//! carries no production telemetry, mints no `allow`, and commits no evidence.
//! Protobuf remains the public source of truth (`aegis_api::grpc::aegis_v2`);
//! this crate owns the analytical **Arrow logical event schema** (docs/LLD.md
//! §9.2) and its stable fingerprint, and will grow the FlatBuffer telemetry
//! frame (§23) and conversion corpus as later increments under the same ADR.
//!
//! The Arrow schema is defined in hand-written Rust against `arrow-schema`
//! logical types only — no compute kernels, no external codegen binary.

#![forbid(unsafe_code)]

pub mod arrow;
pub mod version;

pub use arrow::event_schema::{event_schema, schema_fingerprint, EVENT_FIELD_COUNT};
pub use version::{EVENT_SCHEMA_FINGERPRINT_HEX, EVENT_SCHEMA_VERSION};
