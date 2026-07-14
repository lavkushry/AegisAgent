//! Round-trip and malformed-input gates for the Proposed ADR-0011 v2 control
//! skeleton (`grpc::aegis_v2`, docs/LLD.md §22). These lock the wire contract
//! before any conversion corpus or `shadow` wiring:
//!
//! - encode → decode equality across the populated control messages;
//! - the two opaque payload fields are `bytes::Bytes`, not `Vec<u8>`;
//! - malformed length prefixes are rejected without allocating the claimed size;
//! - proto3 zero defaults land on the fail-closed / unspecified enum arms.

use prost::Message;

use crate::grpc::aegis_v2::{
    authorize_response::Decision, provenance::Trust, Action, ArrowChunk, AuthorizeRequest,
    AuthorizeResponse, IngestFrame, Provenance,
};

fn sample_request() -> AuthorizeRequest {
    AuthorizeRequest {
        request_id: vec![0x01, 0x02, 0x03, 0x04],
        nonce: vec![0xaa, 0xbb, 0xcc, 0xdd],
        issued_at_unix_ns: 1_752_500_000_000_000_000,
        action: Some(Action {
            tool: "github".to_string(),
            operation: "merge_pr".to_string(),
            resource: "org/repo#42".to_string(),
            mutates_state: true,
            canonical_json_parameters: br#"{"branch":"main"}"#.to_vec(),
        }),
        provenance: Some(Provenance {
            source_trust: Trust::UntrustedExternal as i32,
            root_trust: Trust::SemiTrustedCustomer as i32,
            trace_id: vec![0x10; 16],
            parent_event_id: vec![0x20; 16],
        }),
        environment: "production".to_string(),
    }
}

fn sample_response() -> AuthorizeResponse {
    AuthorizeResponse {
        decision: Decision::RequireApproval as i32,
        action_hash_sha256: vec![0x5a; 32],
        policy_generation: 7,
        reason_code: "trust.escalation.required".to_string(),
        approval_id: vec![0x11; 16],
        receipt_id: vec![0x22; 16],
        receipt_hash_sha256: vec![0x33; 32],
        expires_at_unix_ns: 1_752_500_900_000_000_000,
    }
}

#[test]
fn authorize_request_round_trips_losslessly() {
    let original = sample_request();
    let encoded = original.encode_to_vec();
    let decoded = AuthorizeRequest::decode(encoded.as_slice()).expect("decode request");
    assert_eq!(decoded, original, "AuthorizeRequest survives encode/decode");
}

#[test]
fn authorize_response_round_trips_losslessly() {
    let original = sample_response();
    let encoded = original.encode_to_vec();
    let decoded = AuthorizeResponse::decode(encoded.as_slice()).expect("decode response");
    assert_eq!(
        decoded, original,
        "AuthorizeResponse survives encode/decode"
    );
}

#[test]
fn opaque_payload_fields_are_bytes_not_vec() {
    // Compile-time proof that the build.rs `.bytes([...])` mapping took: these
    // fields are `bytes::Bytes`, so ingest/query streaming avoids a Vec clone.
    fn frame_payload(f: IngestFrame) -> ::prost::bytes::Bytes {
        f.flatbuffer_frame
    }
    fn chunk_payload(c: ArrowChunk) -> ::prost::bytes::Bytes {
        c.ipc_message
    }

    let frame = IngestFrame {
        schema_id: 2,
        stream_sequence: 100,
        flatbuffer_frame: ::prost::bytes::Bytes::from_static(b"AEF2payload"),
        crc32c: 0xdead_beef,
    };
    let chunk = ArrowChunk {
        stream_id: 9,
        sequence: 3,
        ipc_message: ::prost::bytes::Bytes::from_static(b"arrow-ipc"),
        crc32c: 0x0bad_c0de,
        end_of_stream: true,
    };

    assert_eq!(frame_payload(frame).as_ref(), b"AEF2payload");
    assert_eq!(chunk_payload(chunk).as_ref(), b"arrow-ipc");
}

#[test]
fn malformed_length_prefix_is_rejected_without_allocating() {
    // Field 1 (request_id), wire type 2 (length-delimited), length varint that
    // claims ~268 MB but the buffer holds no payload bytes. A correct decoder
    // returns Err without reserving the advertised capacity.
    let malformed = [0x0a, 0xff, 0xff, 0xff, 0x7f];
    let result = AuthorizeRequest::decode(malformed.as_slice());
    assert!(
        result.is_err(),
        "truncated length-delimited field must be rejected, got {result:?}"
    );
}

#[test]
fn truncated_varint_is_rejected() {
    // Field 3 (issued_at_unix_ns), wire type 0, followed by a varint whose
    // continuation bits never terminate before the buffer ends.
    let malformed = [0x18, 0xff, 0xff, 0xff];
    let result = AuthorizeRequest::decode(malformed.as_slice());
    assert!(result.is_err(), "unterminated varint must be rejected");
}

#[test]
fn proto3_zero_defaults_are_fail_closed() {
    // The 0 arm of every decision/trust enum is the unspecified/least-trusted
    // value, so a zero-initialized or field-absent message never defaults to a
    // permissive decision.
    let response = AuthorizeResponse::default();
    assert_eq!(response.decision, Decision::Unspecified as i32);
    assert_eq!(Decision::try_from(0), Ok(Decision::Unspecified));

    let provenance = Provenance::default();
    assert_eq!(provenance.source_trust, Trust::Unspecified as i32);
    assert_eq!(Trust::try_from(0), Ok(Trust::Unspecified));
}
