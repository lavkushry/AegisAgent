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
