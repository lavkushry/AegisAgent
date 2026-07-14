use super::*;
use crate::error::StatusError;
use axum::http::{HeaderMap, StatusCode};
use tonic::Code;

#[test]
fn auth_and_policy_failures_are_not_collapsed_to_internal() {
    // The exact defect this replaces: a policy deny (403) and a bad token
    // (401) must NOT reach the gRPC client as `Internal`.
    assert_eq!(
        error_reason_to_tonic_code(ErrorReason::Forbidden),
        Code::PermissionDenied
    );
    assert_eq!(
        error_reason_to_tonic_code(ErrorReason::Unauthorized),
        Code::Unauthenticated
    );
    assert_eq!(
        error_reason_to_tonic_code(ErrorReason::TooManyRequests),
        Code::ResourceExhausted
    );
    assert_ne!(
        error_reason_to_tonic_code(ErrorReason::BadRequest),
        Code::Internal
    );
}

#[test]
fn outcome_to_authorize_result_maps_status_error_to_aegis_error() {
    let outcome = AuthorizedOutcome::status_error(StatusError::unauthorized("bad token"));
    let err = outcome_to_authorize_result(outcome).expect_err("must err");
    match err {
        aegis_common::errors::AegisError::Unauthorized(m) => {
            assert_eq!(m, "bad token");
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }
}

#[test]
fn outcome_to_authorize_result_passes_through_decision() {
    let resp = AuthorizeResponse {
        decision_id: uuid::Uuid::nil(),
        decision: "allow".into(),
        risk_score: 0,
        risk_level: "low".into(),
        composite_risk_score: 0,
        reason: "ok".into(),
        matched_policies: vec![],
        approval: None,
        redacted_fields: vec![],
        root_trust_level: "trusted_internal_unsigned".into(),
        dry_run: false,
        receipt: None,
    };
    let outcome = AuthorizedOutcome::decision(resp.clone());
    let got = outcome_to_authorize_result(outcome).expect("ok");
    assert_eq!(got.decision, "allow");
    assert_eq!(got.reason, "ok");
}

#[test]
fn aegis_error_status_error_round_trip_preserves_class() {
    let se = StatusError::not_found("missing");
    let ae = status_error_to_aegis(se.clone());
    let back = aegis_error_to_status_error(ae);
    assert_eq!(back.reason, ErrorReason::NotFound);
    assert_eq!(back.message, "missing");
}

#[test]
fn only_genuine_server_errors_map_to_internal() {
    assert_eq!(
        error_reason_to_tonic_code(ErrorReason::InternalError),
        Code::Internal
    );
    assert_eq!(
        error_reason_to_tonic_code(ErrorReason::Unknown),
        Code::Internal
    );
}

#[test]
fn every_reason_maps_consistently_with_its_http_status() {
    // The gRPC code and the HTTP status a StatusError already yields must
    // agree on the coarse success/client-error/server-error class, so the
    // two protocols never disagree about whose fault a failure is.
    for reason in [
        ErrorReason::BadRequest,
        ErrorReason::Unauthorized,
        ErrorReason::Forbidden,
        ErrorReason::NotFound,
        ErrorReason::Conflict,
        ErrorReason::AlreadyExists,
        ErrorReason::Invalid,
        ErrorReason::Timeout,
        ErrorReason::TooManyRequests,
        ErrorReason::NotImplemented,
        ErrorReason::UnsupportedMediaType,
        ErrorReason::InternalError,
        ErrorReason::ServiceUnavailable,
        ErrorReason::Unknown,
    ] {
        let http = reason.status_code();
        let code = error_reason_to_tonic_code(reason);
        let http_is_server_error = http.is_server_error();
        // 501 NotImplemented → Unimplemented and 503 → Unavailable are
        // server-side in both models; 5xx Internal matches Internal/Unknown.
        let grpc_is_server_error = matches!(
            code,
            Code::Internal | Code::Unavailable | Code::Unknown | Code::Unimplemented
        );
        if http == StatusCode::SERVICE_UNAVAILABLE {
            assert_eq!(code, Code::Unavailable);
        } else if http == StatusCode::NOT_IMPLEMENTED {
            assert_eq!(code, Code::Unimplemented);
        } else {
            assert_eq!(
                http_is_server_error, grpc_is_server_error,
                "reason {reason:?}: HTTP {http} vs gRPC {code:?} disagree on server-vs-client fault"
            );
        }
    }
}

#[test]
fn status_error_to_tonic_preserves_message_and_code() {
    let err = StatusError::unauthorized("Invalid or quarantined agent token");
    let status = status_error_to_tonic(&err);
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(status.message(), "Invalid or quarantined agent token");
}

#[test]
fn aegis_error_to_tonic_maps_not_found_and_conflict() {
    let s = aegis_error_to_tonic(aegis_common::errors::AegisError::NotFound(
        "Incident not found".into(),
    ));
    assert_eq!(s.code(), Code::NotFound);
    assert_eq!(s.message(), "Incident not found");

    let s = aegis_error_to_tonic(aegis_common::errors::AegisError::Conflict(
        "Tenant already exists".into(),
    ));
    assert_eq!(s.code(), Code::Aborted);
    assert_eq!(s.message(), "Tenant already exists");
}

#[test]
fn serialize_error_to_tonic_is_invalid_argument() {
    let s = serialize_error_to_tonic("serialize dashboard", "boom");
    assert_eq!(s.code(), Code::InvalidArgument);
    assert!(s.message().contains("serialize dashboard"));
}

#[test]
fn outcome_to_tonic_maps_status_error_without_axum_body() {
    let outcome = AuthorizedOutcome::status_error(StatusError::forbidden("policy deny"));
    let err = outcome_to_tonic(outcome).expect_err("must be error");
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), "policy deny");
}

#[test]
fn outcome_to_tonic_maps_json_deny_by_http_status() {
    let outcome = AuthorizedOutcome {
        status: StatusCode::FORBIDDEN,
        body: AuthorizedBody::Json(serde_json::json!({
            "decision": "deny",
            "reason": "agent frozen"
        })),
    };
    let err = outcome_to_tonic(outcome).expect_err("must be error");
    assert_eq!(err.code(), Code::PermissionDenied);
    assert!(err.message().contains("agent frozen"));
}

#[test]
fn outcome_to_response_round_trips_status_error() {
    let outcome = AuthorizedOutcome::status_error(StatusError::unauthorized("bad token"));
    let response = outcome_to_response(outcome);
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn http_error_to_tonic_parses_status_error_envelope() {
    let err = StatusError::forbidden("policy deny");
    let body = serde_json::to_vec(&err).expect("serialize");
    let status = http_error_to_tonic(StatusCode::FORBIDDEN, &body);
    assert_eq!(status.code(), Code::PermissionDenied);
    assert_eq!(status.message(), "policy deny");
}

#[test]
fn http_error_to_tonic_maps_partial_decision_deny_by_status() {
    let body = br#"{"decision":"deny","reason":"agent frozen"}"#;
    let status = http_error_to_tonic(StatusCode::FORBIDDEN, body);
    assert_eq!(status.code(), Code::PermissionDenied);
    assert!(status.message().contains("agent frozen"));
}

#[test]
fn build_service_headers_sets_tenant_bearer_and_signature() {
    let addr = std::net::SocketAddr::from(([203, 0, 113, 9], 5555));
    let ctx = AuthorizeContext::new(
        "tenant_x",
        addr,
        Transport::Grpc,
        AuthCredential::BearerToken("secret-token".into()),
    )
    .with_request_signature(Some("sig-abc".into()));
    let headers = build_service_headers(&ctx).expect("headers");
    assert_eq!(
        headers
            .get("X-Aegis-Tenant-ID")
            .and_then(|v| v.to_str().ok()),
        Some("tenant_x")
    );
    assert_eq!(
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok()),
        Some("Bearer secret-token")
    );
    assert_eq!(
        headers
            .get("x-aegis-request-signature")
            .and_then(|v| v.to_str().ok()),
        Some("sig-abc")
    );
    assert!(headers.get(crate::mtls::MTLS_CN_HEADER).is_none());
}

#[test]
fn build_service_headers_sets_mtls_cn_without_bearer() {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
    let ctx = AuthorizeContext::new(
        "t1",
        addr,
        Transport::Rest,
        AuthCredential::MtlsCn("agent.example".into()),
    );
    let headers = build_service_headers(&ctx).expect("headers");
    assert_eq!(
        headers
            .get(crate::mtls::MTLS_CN_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some("agent.example")
    );
    assert!(headers.get(axum::http::header::AUTHORIZATION).is_none());
}

#[test]
fn decision_outcome_to_authorized_maps_decision_body() {
    let resp = AuthorizeResponse {
        decision_id: uuid::Uuid::nil(),
        decision: "allow".into(),
        risk_score: 10,
        risk_level: "low".into(),
        composite_risk_score: 10,
        reason: "ok".into(),
        matched_policies: vec!["p1".into()],
        approval: None,
        redacted_fields: vec![],
        root_trust_level: "trusted_internal_unsigned".into(),
        dry_run: false,
        receipt: None,
    };
    let outcome = DecisionOutcome {
        http_status: 200,
        body: DecisionBody::Decision(Box::new(resp.clone())),
    };
    let wired = decision_outcome_to_authorized(outcome);
    assert_eq!(wired.status, StatusCode::OK);
    match wired.body {
        AuthorizedBody::Decision(got) => {
            assert_eq!(got.decision, "allow");
            assert_eq!(got.reason, "ok");
            assert_eq!(got.matched_policies, vec!["p1".to_string()]);
        }
        other => panic!("expected Decision, got {other:?}"),
    }
}

#[test]
fn decision_outcome_to_authorized_maps_failure_preserving_http_status() {
    let outcome = DecisionOutcome {
        http_status: 429,
        body: DecisionBody::Failure(DecisionFailure::too_many_requests("rate limited")),
    };
    let wired = decision_outcome_to_authorized(outcome);
    assert_eq!(wired.status, StatusCode::TOO_MANY_REQUESTS);
    match wired.body {
        AuthorizedBody::Status(err) => {
            assert_eq!(err.reason, ErrorReason::TooManyRequests);
            assert_eq!(err.message, "rate limited");
            assert_eq!(err.code, 429);
        }
        other => panic!("expected Status, got {other:?}"),
    }
}

#[test]
fn decision_outcome_to_authorized_maps_partial_deny_to_json_403() {
    let outcome = DecisionOutcome {
        http_status: 403,
        body: DecisionBody::PartialDeny {
            reason: "agent not permitted to call tool 'echo'".into(),
        },
    };
    let wired = decision_outcome_to_authorized(outcome);
    assert_eq!(wired.status, StatusCode::FORBIDDEN);
    match wired.body {
        AuthorizedBody::Json(v) => {
            assert_eq!(v.get("decision").and_then(|x| x.as_str()), Some("deny"));
            assert_eq!(
                v.get("reason").and_then(|x| x.as_str()),
                Some("agent not permitted to call tool 'echo'")
            );
        }
        other => panic!("expected Json partial deny, got {other:?}"),
    }
}

#[test]
fn authorize_context_from_headers_bearer_and_tenant() {
    let mut headers = HeaderMap::new();
    headers.insert("X-Aegis-Tenant-ID", "tenant_z".parse().expect("hv"));
    headers.insert(
        axum::http::header::AUTHORIZATION,
        "Bearer tok-xyz".parse().expect("hv"),
    );
    headers.insert("x-aegis-request-signature", "sig-1".parse().expect("hv"));
    let addr = std::net::SocketAddr::from(([198, 51, 100, 7], 4443));
    let ctx = authorize_context_from_headers(&headers, addr).expect("ctx");
    assert_eq!(ctx.tenant_id, "tenant_z");
    assert_eq!(ctx.client_addr, addr);
    assert_eq!(ctx.transport, Transport::Rest);
    match ctx.credential {
        AuthCredential::BearerToken(t) => assert_eq!(t, "tok-xyz"),
        AuthCredential::MtlsCn(_) => panic!("expected bearer"),
    }
    assert_eq!(ctx.request_signature.as_deref(), Some("sig-1"));
}

#[test]
fn authorize_context_from_headers_prefers_mtls_cn() {
    let mut headers = HeaderMap::new();
    headers.insert("X-Tenant-ID", "t-mtls".parse().expect("hv"));
    headers.insert(crate::mtls::MTLS_CN_HEADER, "agent.cn".parse().expect("hv"));
    // Bearer present but mTLS CN wins when header is set.
    headers.insert(
        axum::http::header::AUTHORIZATION,
        "Bearer ignored".parse().expect("hv"),
    );
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 9));
    let ctx = authorize_context_from_headers(&headers, addr).expect("ctx");
    assert_eq!(ctx.tenant_id, "t-mtls");
    match ctx.credential {
        AuthCredential::MtlsCn(cn) => assert_eq!(cn, "agent.cn"),
        AuthCredential::BearerToken(_) => panic!("expected mtls"),
    }
}

#[test]
fn authorize_context_from_headers_missing_tenant_is_bad_request() {
    let headers = HeaderMap::new();
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
    let err = authorize_context_from_headers(&headers, addr).expect_err("no tenant");
    assert_eq!(err.reason, ErrorReason::BadRequest);
    assert!(err.message.contains("Tenant"));
}
