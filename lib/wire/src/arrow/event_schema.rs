//! Arrow logical event schema — the analytical shape of a security event
//! (docs/LLD.md §9.2), defined in hand-written Rust against `arrow-schema`
//! logical types only.
//!
//! The schema is the frozen v2 analytical contract under Proposed ADR-0011.
//! Its [`schema_fingerprint`] is computed over a canonical, version-independent
//! rendering of the fields (not `arrow-schema`'s `Debug`/`Display`, which may
//! change across crate releases) so the fingerprint that a browser stream
//! resume compares (LLD §24) stays stable as long as the logical shape does.

use arrow_schema::{DataType, Field, Fields, Schema, TimeUnit};
use sha2::{Digest, Sha256};

/// Number of leaf fields in the logical event schema (LLD §9.2). The two
/// two-field rows in the spec table (`run_id, trace_id` and
/// `action_hash, receipt_hash`) expand to four fields.
pub const EVENT_FIELD_COUNT: usize = 19;

const TENANT_ID_BYTES: i32 = 16;
const ID128_BYTES: i32 = 16;
const HASH256_BYTES: i32 = 32;

/// Build the logical Arrow event schema exactly as LLD §9.2 specifies.
///
/// Only `run_id`, `trace_id`, `action_hash`, and `receipt_hash` are nullable,
/// per the spec table; every other field is non-nullable.
pub fn event_schema() -> Schema {
    let payload_ref = DataType::Struct(Fields::from(vec![
        Field::new("offset", DataType::UInt32, false),
        Field::new("len", DataType::UInt32, false),
        Field::new("codec", DataType::UInt8, false),
    ]));

    let fields = vec![
        Field::new(
            "tenant_id",
            DataType::FixedSizeBinary(TENANT_ID_BYTES),
            false,
        ),
        Field::new("event_id", DataType::FixedSizeBinary(ID128_BYTES), false),
        Field::new(
            "ts_wall_ns",
            DataType::Timestamp(TimeUnit::Nanosecond, Some("UTC".into())),
            false,
        ),
        Field::new("ts_mono_ns", DataType::UInt64, false),
        Field::new("source_sequence", DataType::UInt64, false),
        Field::new("event_type", dictionary(DataType::UInt16), false),
        Field::new("severity", DataType::UInt8, false),
        Field::new("agent_id", dictionary(DataType::UInt32), false),
        Field::new("run_id", DataType::FixedSizeBinary(ID128_BYTES), true),
        Field::new("trace_id", DataType::FixedSizeBinary(ID128_BYTES), true),
        Field::new("source_component", dictionary(DataType::UInt16), false),
        Field::new("trust", DataType::UInt8, false),
        Field::new("decision", DataType::UInt8, false),
        Field::new(
            "action_hash",
            DataType::FixedSizeBinary(HASH256_BYTES),
            true,
        ),
        Field::new(
            "receipt_hash",
            DataType::FixedSizeBinary(HASH256_BYTES),
            true,
        ),
        Field::new("policy_generation", DataType::UInt64, false),
        Field::new("schema_version", DataType::UInt16, false),
        Field::new("redaction_flags", DataType::UInt32, false),
        Field::new("payload_ref", payload_ref, false),
    ];

    debug_assert_eq!(fields.len(), EVENT_FIELD_COUNT);
    Schema::new(fields)
}

/// Dictionary-encoded UTF-8 values keyed by the given integer type.
fn dictionary(key: DataType) -> DataType {
    DataType::Dictionary(Box::new(key), Box::new(DataType::Utf8))
}

/// SHA-256 over a canonical, version-independent rendering of the schema.
///
/// Two schemas with the same field names, logical types, and nullability
/// produce the same fingerprint regardless of the `arrow-schema` version.
pub fn schema_fingerprint() -> [u8; 32] {
    let schema = event_schema();
    let mut hasher = Sha256::new();
    for field in schema.fields() {
        hasher.update(field.name().as_bytes());
        hasher.update([0x1f]); // unit separator
        hasher.update(canonical_type(field.data_type()).as_bytes());
        hasher.update([0x1f]);
        hasher.update([u8::from(field.is_nullable())]);
        hasher.update([0x1e]); // record separator
    }
    hasher.finalize().into()
}

/// Lowercase-hex form of [`schema_fingerprint`].
pub fn schema_fingerprint_hex() -> String {
    let mut out = String::with_capacity(64);
    for byte in schema_fingerprint() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Stable textual rendering of a logical type. Covers exactly the variants the
/// event schema uses; an unexpected variant is a schema-drift bug and renders
/// verbosely so a test diff is legible rather than silently colliding.
fn canonical_type(dt: &DataType) -> String {
    match dt {
        DataType::UInt8 => "u8".to_string(),
        DataType::UInt16 => "u16".to_string(),
        DataType::UInt32 => "u32".to_string(),
        DataType::UInt64 => "u64".to_string(),
        DataType::Utf8 => "utf8".to_string(),
        DataType::FixedSizeBinary(n) => format!("fixedbinary({n})"),
        DataType::Timestamp(unit, tz) => {
            format!(
                "timestamp({},{})",
                canonical_time_unit(unit),
                tz.as_deref().unwrap_or("")
            )
        }
        DataType::Dictionary(key, value) => {
            format!("dict({},{})", canonical_type(key), canonical_type(value))
        }
        DataType::Struct(fields) => {
            let inner: Vec<String> = fields
                .iter()
                .map(|f| {
                    format!(
                        "{}:{}:{}",
                        f.name(),
                        canonical_type(f.data_type()),
                        u8::from(f.is_nullable())
                    )
                })
                .collect();
            format!("struct({})", inner.join(","))
        }
        other => format!("unsupported({other:?})"),
    }
}

fn canonical_time_unit(unit: &TimeUnit) -> &'static str {
    match unit {
        TimeUnit::Second => "s",
        TimeUnit::Millisecond => "ms",
        TimeUnit::Microsecond => "us",
        TimeUnit::Nanosecond => "ns",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::{EVENT_SCHEMA_FINGERPRINT_HEX, EVENT_SCHEMA_VERSION};

    #[test]
    fn schema_has_the_full_field_set_in_spec_order() {
        let schema = event_schema();
        let names: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
        assert_eq!(
            names,
            vec![
                "tenant_id",
                "event_id",
                "ts_wall_ns",
                "ts_mono_ns",
                "source_sequence",
                "event_type",
                "severity",
                "agent_id",
                "run_id",
                "trace_id",
                "source_component",
                "trust",
                "decision",
                "action_hash",
                "receipt_hash",
                "policy_generation",
                "schema_version",
                "redaction_flags",
                "payload_ref",
            ]
        );
        assert_eq!(names.len(), EVENT_FIELD_COUNT);
    }

    #[test]
    fn only_the_four_spec_fields_are_nullable() {
        let schema = event_schema();
        let nullable: Vec<&str> = schema
            .fields()
            .iter()
            .filter(|f| f.is_nullable())
            .map(|f| f.name().as_str())
            .collect();
        assert_eq!(
            nullable,
            vec!["run_id", "trace_id", "action_hash", "receipt_hash"]
        );
    }

    #[test]
    fn hash_and_id_widths_match_spec() {
        let schema = event_schema();
        let width = |name: &str| match schema.field_with_name(name).unwrap().data_type() {
            DataType::FixedSizeBinary(n) => *n,
            other => panic!("{name} is not fixed-size binary: {other:?}"),
        };
        assert_eq!(width("tenant_id"), 16);
        assert_eq!(width("event_id"), 16);
        assert_eq!(width("run_id"), 16);
        assert_eq!(width("trace_id"), 16);
        assert_eq!(width("action_hash"), 32);
        assert_eq!(width("receipt_hash"), 32);
    }

    #[test]
    fn payload_ref_is_the_spec_struct() {
        let schema = event_schema();
        match schema.field_with_name("payload_ref").unwrap().data_type() {
            DataType::Struct(fields) => {
                let inner: Vec<(&str, &DataType)> = fields
                    .iter()
                    .map(|f| (f.name().as_str(), f.data_type()))
                    .collect();
                assert_eq!(
                    inner,
                    vec![
                        ("offset", &DataType::UInt32),
                        ("len", &DataType::UInt32),
                        ("codec", &DataType::UInt8),
                    ]
                );
            }
            other => panic!("payload_ref must be a struct, got {other:?}"),
        }
    }

    #[test]
    fn fingerprint_is_stable_and_pinned() {
        // Golden: this value freezes the v2 analytical contract. It changes only
        // when the logical schema changes, which requires a new schema version
        // and an ADR — never a silent edit.
        assert_eq!(schema_fingerprint_hex(), EVENT_SCHEMA_FINGERPRINT_HEX);
        assert_eq!(schema_fingerprint_hex().len(), 64);
    }

    #[test]
    fn schema_version_field_matches_declared_version() {
        // The schema carries a `schema_version` column; its declared value is
        // the crate-level EVENT_SCHEMA_VERSION.
        assert_eq!(EVENT_SCHEMA_VERSION, 2);
        assert!(event_schema().field_with_name("schema_version").is_ok());
    }
}
