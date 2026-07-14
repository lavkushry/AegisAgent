use super::*;
use crate::agent::AuthorizeAgent;
use crate::outcome::DecisionBody;
use crate::preflight::PreflightedAuthorize;
use crate::runtime::{AdmissionEffect, EnforcementStatus};
use crate::test_runtime::MockRuntime;
use std::time::Instant;

fn preflighted(status: &str) -> PreflightedAuthorize {
    let body = serde_json::json!({
        "agent": { "id": "a1", "environment": "dev" },
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
    });
    let mut agent = AuthorizeAgent::new("agent-1", "tenant-1", "low");
    agent.status = status.into();
    agent.agent_key = "my-agent".into();
    PreflightedAuthorize {
        request: serde_json::from_value(body).expect("req"),
        agent,
        root_trust_level: "trusted_internal_unsigned".into(),
        dry_run: false,
        used_mtls: false,
        normalized_tool: "echo".into(),
        normalized_action: "run".into(),
    }
}

#[tokio::test]
async fn guard_denies_frozen_agent() {
    let rt = MockRuntime {
        admission: AdmissionEffect::Disabled,
        enforcement: EnforcementStatus::Clear,
        ..MockRuntime::default()
    };
    let err = guard_authorize(&rt, preflighted("frozen"), Instant::now())
        .await
        .expect_err("frozen");
    assert!(matches!(err.body, DecisionBody::Decision(_)));
    assert_eq!(*rt.writes.lock().expect("l"), 1);
}

#[tokio::test]
async fn guard_denies_banned_agent_after_hash() {
    let rt = MockRuntime {
        admission: AdmissionEffect::Disabled,
        enforcement: EnforcementStatus::AgentBanned,
        ..MockRuntime::default()
    };
    let err = guard_authorize(&rt, preflighted("active"), Instant::now())
        .await
        .expect_err("banned");
    match err.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert!(resp.reason.contains("banned"));
        }
        _ => panic!("decision"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
}

#[tokio::test]
async fn guard_webhook_mutate_then_continue() {
    let rt = MockRuntime {
        admission: AdmissionEffect::Mutate(serde_json::json!({"x": 1})),
        enforcement: EnforcementStatus::Clear,
        ..MockRuntime::default()
    };
    let got = guard_authorize(&rt, preflighted("active"), Instant::now())
        .await
        .expect("ok");
    assert_eq!(got.action_hash, "deadbeef");
    assert_eq!(
        got.request.tool_call.parameters,
        serde_json::json!({"x": 1})
    );
    assert_eq!(*rt.writes.lock().expect("l"), 0);
}

#[tokio::test]
async fn guard_webhook_reject() {
    let rt = MockRuntime {
        admission: AdmissionEffect::Reject("blocked by admission".into()),
        enforcement: EnforcementStatus::Clear,
        ..MockRuntime::default()
    };
    let err = guard_authorize(&rt, preflighted("active"), Instant::now())
        .await
        .expect_err("reject");
    match err.body {
        DecisionBody::Decision(resp) => {
            assert!(resp.reason.contains("blocked by admission"));
            assert_eq!(resp.matched_policies, vec!["admission_webhook_reject"]);
        }
        _ => panic!("decision"),
    }
}

#[test]
fn mcp_server_key_extraction() {
    assert_eq!(mcp_server_key_from_tool("mcp:fs"), Some("fs"));
    assert_eq!(mcp_server_key_from_tool("mcp:"), None);
    assert_eq!(mcp_server_key_from_tool("echo"), None);
}
