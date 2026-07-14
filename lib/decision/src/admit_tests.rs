use super::*;
use crate::context::{AuthCredential, AuthorizeContext, Transport};
use crate::outcome::DecisionBody;
use crate::test_runtime::MockRuntime;
use std::net::SocketAddr;

fn addr() -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 1], 4443))
}

fn minimal_body(env: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "agent": {
            "id": "a1",
            "environment": env,
            "framework": "test"
        },
        "tool_call": {
            "tool": "echo",
            "action": "run",
            "parameters": {},
            "mutates_state": false
        },
        "context": {
            "source_trust": "trusted_internal_unsigned",
            "contains_sensitive_data": false
        }
    }))
    .expect("json")
}

#[tokio::test]
async fn admit_rejects_invalid_json() {
    let rt = MockRuntime {
        agent: None,
        auth_blocked: false,
        ..MockRuntime::default()
    };
    let ctx = AuthorizeContext::new(
        "t1",
        addr(),
        Transport::Rest,
        AuthCredential::BearerToken("tok".into()),
    );
    let err = admit_authorize(&rt, &ctx, b"not-json")
        .await
        .expect_err("must fail");
    assert_eq!(err.http_status, 400);
}

#[tokio::test]
async fn admit_rejects_bad_token_and_records_failure() {
    let rt = MockRuntime {
        agent: None,
        auth_blocked: false,
        ..MockRuntime::default()
    };
    let ctx = AuthorizeContext::new(
        "t1",
        addr(),
        Transport::Rest,
        AuthCredential::BearerToken("bad".into()),
    );
    let body = minimal_body("dev");
    let err = admit_authorize(&rt, &ctx, &body)
        .await
        .expect_err("must fail");
    assert_eq!(err.http_status, 401);
    assert_eq!(*rt.auth_failures.lock().expect("lock"), 1);
    match err.body {
        DecisionBody::Failure(f) => {
            assert!(f.message.contains("Invalid or quarantined"));
        }
        _ => panic!("expected failure body"),
    }
}

#[tokio::test]
async fn admit_lockout_returns_429() {
    let rt = MockRuntime {
        agent: None,
        auth_blocked: true,
        ..MockRuntime::default()
    };
    let ctx = AuthorizeContext::new(
        "t1",
        addr(),
        Transport::Rest,
        AuthCredential::BearerToken("tok".into()),
    );
    let body = minimal_body("dev");
    let err = admit_authorize(&rt, &ctx, &body)
        .await
        .expect_err("must fail");
    assert_eq!(err.http_status, 429);
}

#[tokio::test]
async fn admit_empty_tenant_is_bad_request() {
    let rt = MockRuntime::default();
    let ctx = AuthorizeContext::new(
        "   ",
        addr(),
        Transport::Rest,
        AuthCredential::BearerToken("tok".into()),
    );
    let err = admit_authorize(&rt, &ctx, &minimal_body("dev"))
        .await
        .expect_err("empty tenant");
    assert_eq!(err.http_status, 400);
    match err.body {
        DecisionBody::Failure(f) => assert!(f.message.contains("tenant")),
        other => panic!("expected Failure, got {other:?}"),
    }
}

#[tokio::test]
async fn admit_empty_mtls_cn_unauthorized() {
    let rt = MockRuntime::default();
    let ctx = AuthorizeContext::new(
        "tenant-1",
        addr(),
        Transport::Rest,
        AuthCredential::MtlsCn("".into()),
    );
    let err = admit_authorize(&rt, &ctx, &minimal_body("dev"))
        .await
        .expect_err("empty cn");
    assert_eq!(err.http_status, 401);
    match err.body {
        DecisionBody::Failure(f) => assert!(f.message.contains("Missing agent token")),
        other => panic!("expected Failure, got {other:?}"),
    }
    assert_eq!(*rt.auth_failures.lock().expect("l"), 1);
}

#[tokio::test]
async fn admit_empty_bearer_token_unauthorized() {
    let rt = MockRuntime::default();
    let ctx = AuthorizeContext::new(
        "tenant-1",
        addr(),
        Transport::Rest,
        AuthCredential::BearerToken("".into()),
    );
    let err = admit_authorize(&rt, &ctx, &minimal_body("dev"))
        .await
        .expect_err("empty token");
    assert_eq!(err.http_status, 401);
    match err.body {
        DecisionBody::Failure(f) => assert!(f.message.contains("Missing agent token")),
        other => panic!("expected Failure, got {other:?}"),
    }
    assert_eq!(*rt.auth_failures.lock().expect("l"), 1);
}

#[tokio::test]
async fn admit_success_bearer() {
    let mut agent = AuthorizeAgent::new("agent-1", "tenant-1", "low");
    agent.allowed_environments = None;
    let rt = MockRuntime {
        agent: Some(agent),
        auth_blocked: false,
        ..MockRuntime::default()
    };
    let ctx = AuthorizeContext::new(
        "tenant-1",
        addr(),
        Transport::Rest,
        AuthCredential::BearerToken("good".into()),
    );
    let body = minimal_body("production");
    let admitted = admit_authorize(&rt, &ctx, &body).await.expect("ok");
    assert_eq!(admitted.agent.id, "agent-1");
    assert!(!admitted.used_mtls);
    assert!(!admitted.dry_run);
    assert_eq!(admitted.root_trust_level, "trusted_internal_unsigned");
}

#[tokio::test]
async fn admit_success_mtls() {
    let rt = MockRuntime {
        agent: Some(AuthorizeAgent::new("agent-1", "tenant-1", "low")),
        ..MockRuntime::default()
    };
    let ctx = AuthorizeContext::new(
        "tenant-1",
        addr(),
        Transport::Rest,
        AuthCredential::MtlsCn("agent.cn".into()),
    );
    let admitted = admit_authorize(&rt, &ctx, &minimal_body("dev"))
        .await
        .expect("mtls ok");
    assert!(admitted.used_mtls);
    assert_eq!(admitted.agent.id, "agent-1");
}

#[tokio::test]
async fn admit_unrecognized_mtls_cn_unauthorized() {
    let rt = MockRuntime {
        agent: None,
        ..MockRuntime::default()
    };
    let ctx = AuthorizeContext::new(
        "tenant-1",
        addr(),
        Transport::Rest,
        AuthCredential::MtlsCn("unknown.cn".into()),
    );
    let err = admit_authorize(&rt, &ctx, &minimal_body("dev"))
        .await
        .expect_err("mtls");
    assert_eq!(err.http_status, 401);
    match err.body {
        DecisionBody::Failure(f) => {
            assert!(f.message.contains("mTLS") || f.message.contains("certificate"));
        }
        other => panic!("expected Failure, got {other:?}"),
    }
    assert_eq!(*rt.auth_failures.lock().expect("l"), 1);
}

#[tokio::test]
async fn admit_requires_signature_when_agent_has_signing_key() {
    let mut agent = AuthorizeAgent::new("agent-1", "tenant-1", "low");
    agent.signing_key = Some("unit-test-key".into());
    let rt = MockRuntime {
        agent: Some(agent),
        ..MockRuntime::default()
    };
    let body = minimal_body("dev");
    let ctx = AuthorizeContext::new(
        "tenant-1",
        addr(),
        Transport::Rest,
        AuthCredential::BearerToken("tok".into()),
    );
    let err = admit_authorize(&rt, &ctx, &body)
        .await
        .expect_err("missing sig");
    assert_eq!(err.http_status, 401);
    match err.body {
        DecisionBody::Failure(f) => assert!(f.message.contains("missing_request_signature")),
        other => panic!("expected Failure, got {other:?}"),
    }

    let sig = aegis_common::hash::request_signature_header("unit-test-key", &body).expect("sign");
    let ctx = AuthorizeContext::new(
        "tenant-1",
        addr(),
        Transport::Rest,
        AuthCredential::BearerToken("tok".into()),
    )
    .with_request_signature(Some(sig));
    let admitted = admit_authorize(&rt, &ctx, &body).await.expect("signed ok");
    assert_eq!(admitted.agent.id, "agent-1");
}

#[tokio::test]
async fn admit_rejects_invalid_request_signature() {
    let mut agent = AuthorizeAgent::new("agent-1", "tenant-1", "low");
    agent.signing_key = Some("unit-test-key".into());
    let rt = MockRuntime {
        agent: Some(agent),
        ..MockRuntime::default()
    };
    let body = minimal_body("dev");
    let ctx = AuthorizeContext::new(
        "tenant-1",
        addr(),
        Transport::Rest,
        AuthCredential::BearerToken("tok".into()),
    )
    .with_request_signature(Some("sha256=deadbeef".into()));
    let err = admit_authorize(&rt, &ctx, &body)
        .await
        .expect_err("bad sig");
    assert_eq!(err.http_status, 401);
    match err.body {
        DecisionBody::Failure(f) => assert!(f.message.contains("invalid_request_signature")),
        other => panic!("expected Failure, got {other:?}"),
    }
}

#[tokio::test]
async fn admit_environment_restriction_partial_deny() {
    let mut agent = AuthorizeAgent::new("agent-1", "tenant-1", "low");
    agent.allowed_environments = Some(r#"["staging"]"#.into());
    let rt = MockRuntime {
        agent: Some(agent),
        auth_blocked: false,
        ..MockRuntime::default()
    };
    let ctx = AuthorizeContext::new(
        "tenant-1",
        addr(),
        Transport::Rest,
        AuthCredential::BearerToken("good".into()),
    );
    let body = minimal_body("production");
    let err = admit_authorize(&rt, &ctx, &body)
        .await
        .expect_err("must deny");
    assert_eq!(err.http_status, 403);
    match err.body {
        DecisionBody::PartialDeny { reason } => {
            assert!(!reason.is_empty());
        }
        _ => panic!("expected partial deny"),
    }
}
