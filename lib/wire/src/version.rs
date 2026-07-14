//! Version and fingerprint constants for the v2 wire contracts (ADR-0011).

/// Logical schema version carried in the event `schema_version` column and the
/// FlatBuffer `SecurityEvent.schema_version` default (LLD §9.2, §23).
pub const EVENT_SCHEMA_VERSION: u16 = 2;

/// Pinned lowercase-hex SHA-256 fingerprint of the Arrow logical event schema.
///
/// Frozen contract: this changes only alongside a schema version bump and an
/// ADR. `arrow::event_schema::fingerprint_is_stable_and_pinned` enforces it.
pub const EVENT_SCHEMA_FINGERPRINT_HEX: &str =
    "af3ec64ad8e779c5404d3b8b80fc692e846ba79187afdbb45dc7a45016b72d6e";
