use super::*;
use crate::agent::AuthorizeAgent;
use crate::outcome::DecisionBody;
use crate::test_runtime::MockRuntime;
use aegis_api::models::DecisionRecord;
use chrono::{Duration, Utc};

fn admitted(nonce: Option<&str>, request_id: Option<&str>) -> AdmittedAuthorize {
    let body = serde_json::json!({
        "request_id": request_id,
        "nonce": nonce,
        "agent": { "id": "a1", "environment": "dev" },
        "tool_call": {
            "tool": "Echo",
            "action": "Run",
            "parameters": {},
            "mutates_state": false
        },
        "context": {
            "source_trust": "trusted_internal_unsigned",
            "contains_sensitive_data": false
        }
    });
    let request: AuthorizeRequest = serde_json::from_value(body).expect("req");
    AdmittedAuthorize {
        request,
        agent: AuthorizeAgent::new("agent-1", "tenant-1", "low"),
        root_trust_level: "trusted_internal_unsigned".into(),
        dry_run: false,
        used_mtls: false,
    }
}

#[tokio::test]
async fn preflight_denies_tool_permission() {
    let rt = MockRuntime {
        tool_permitted: false,
        rate_ok: true,
        quota_ok: true,
        nonce_is_replay: false,
        idempotent: None,
        ..MockRuntime::default()
    };
    let err = preflight_authorize(&rt, admitted(None, None))
        .await
        .expect_err("deny");
    match err {
        PreflightTerminal::Outcome(o) => {
            assert_eq!(o.http_status, 403);
            match o.body {
                DecisionBody::PartialDeny { reason } => {
                    assert!(reason.contains("not permitted"));
                }
                _ => panic!("partial deny"),
            }
        }
        _ => panic!("outcome"),
    }
}

#[tokio::test]
async fn preflight_rejects_replay_nonce() {
    let rt = MockRuntime {
        tool_permitted: true,
        rate_ok: true,
        quota_ok: true,
        nonce_is_replay: true,
        idempotent: None,
        ..MockRuntime::default()
    };
    let err = preflight_authorize(&rt, admitted(Some("n1"), None))
        .await
        .expect_err("replay");
    match err {
        PreflightTerminal::Outcome(o) => {
            assert_eq!(o.http_status, 409);
        }
        _ => panic!("outcome"),
    }
}

#[tokio::test]
async fn preflight_rejects_stale_timestamp() {
    let rt = MockRuntime {
        tool_permitted: true,
        rate_ok: true,
        quota_ok: true,
        nonce_is_replay: false,
        idempotent: None,
        ..MockRuntime::default()
    };
    let mut a = admitted(Some("n1"), None);
    a.request.timestamp = Some(Utc::now() - Duration::seconds(600));
    let err = preflight_authorize(&rt, a).await.expect_err("stale");
    match err {
        PreflightTerminal::Outcome(o) => assert_eq!(o.http_status, 409),
        _ => panic!("outcome"),
    }
}

#[tokio::test]
async fn preflight_idempotent_replay() {
    let record = DecisionRecord {
        id: uuid::Uuid::nil().to_string(),
        tenant_id: "tenant-1".into(),
        agent_id: "agent-1".into(),
        user_id: None,
        run_id: None,
        trace_id: None,
        skill: "echo".into(),
        action: "run".into(),
        resource: None,
        input_json: "{}".into(),
        decision: "allow".into(),
        risk_score: Some(10),
        reason: Some("ok".into()),
        matched_policy_ids: None,
        request_id: Some("r1".into()),
        latency_ms: None,
        composite_risk_score: Some(10),
        root_trust_level: Some("trusted_internal_unsigned".into()),
        parent_run_id: None,
        created_at: Utc::now(),
    };
    let rt = MockRuntime {
        tool_permitted: true,
        rate_ok: true,
        quota_ok: true,
        nonce_is_replay: false,
        idempotent: Some(record),
        ..MockRuntime::default()
    };
    let err = preflight_authorize(&rt, admitted(None, Some("r1")))
        .await
        .expect_err("replay id");
    match err {
        PreflightTerminal::IdempotentReplay(r) => assert_eq!(r.decision, "allow"),
        PreflightTerminal::Outcome(_) => panic!("idempotent"),
    }
    // Heartbeat only on continue path
    assert_eq!(*rt.heartbeats.lock().expect("l"), 0);
}

#[tokio::test]
async fn preflight_rate_limit() {
    let rt = MockRuntime {
        tool_permitted: true,
        rate_ok: false,
        quota_ok: true,
        nonce_is_replay: false,
        idempotent: None,
        ..MockRuntime::default()
    };
    let err = preflight_authorize(&rt, admitted(None, None))
        .await
        .expect_err("rate");
    match err {
        PreflightTerminal::Outcome(o) => assert_eq!(o.http_status, 429),
        _ => panic!("outcome"),
    }
}

#[tokio::test]
async fn preflight_success_normalizes_and_heartbeats() {
    let rt = MockRuntime {
        tool_permitted: true,
        rate_ok: true,
        quota_ok: true,
        nonce_is_replay: false,
        idempotent: None,
        ..MockRuntime::default()
    };
    let got = preflight_authorize(&rt, admitted(None, None))
        .await
        .expect("ok");
    assert_eq!(got.normalized_tool, "echo");
    assert_eq!(got.normalized_action, "run");
    assert_eq!(*rt.heartbeats.lock().expect("l"), 1);
}
