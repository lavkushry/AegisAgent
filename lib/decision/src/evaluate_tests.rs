use super::*;
use crate::agent::AuthorizeAgent;
use crate::guard::GuardedAuthorize;
use crate::metadata::MetadataAuthorize;
use crate::outcome::{DecisionBody, DecisionFailureClass};
use crate::runtime::PolicyDecisionView;
use crate::test_runtime::MockRuntime;
use std::time::Instant;

fn meta_allow() -> MetadataAuthorize {
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
    MetadataAuthorize {
        guarded: GuardedAuthorize {
            request: serde_json::from_value(body).expect("req"),
            agent: AuthorizeAgent::new("agent-1", "tenant-1", "low"),
            root_trust_level: "trusted_internal_unsigned".into(),
            dry_run: false,
            used_mtls: false,
            normalized_tool: "echo".into(),
            normalized_action: "run".into(),
            action_hash: "h".into(),
        },
        risk_score: 10,
        risk_level: "low".into(),
        action_approval_required: false,
        action_default_decision: "policy".into(),
        is_tool_known: true,
        is_mcp_call: false,
        mcp_server_key: None,
    }
}

#[tokio::test]
async fn evaluate_allow_low_risk_writes() {
    let rt = MockRuntime {
        cedar: PolicyDecisionView {
            decision: "allow".into(),
            matched_policies: vec!["p1".into()],
            approver_group: None,
            reason: "ok".into(),
            redacted_fields: vec![],
        },
        audit_capacity: true,
        write_fail: false,
        ..MockRuntime::default()
    };
    let out =
        evaluate_authorize(&rt, meta_allow(), Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "allow");
            assert_eq!(resp.risk_score, 10);
        }
        _ => panic!("decision"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
}

#[tokio::test]
async fn evaluate_audit_capacity_fail_closed_high_risk() {
    let mut m = meta_allow();
    m.risk_level = "critical".into();
    m.risk_score = 95;
    let rt = MockRuntime {
        cedar: PolicyDecisionView {
            decision: "allow".into(),
            matched_policies: vec![],
            approver_group: None,
            reason: "ok".into(),
            redacted_fields: vec![],
        },
        audit_capacity: false,
        write_fail: false,
        ..MockRuntime::default()
    };
    let out = evaluate_authorize(&rt, m, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert!(resp.reason.contains("audit_writer_unavailable"));
        }
        _ => panic!("decision"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 0);
}

#[tokio::test]
async fn evaluate_write_fail_high_risk_denies() {
    let mut m = meta_allow();
    m.risk_level = "high".into();
    m.risk_score = 75;
    let rt = MockRuntime {
        cedar: PolicyDecisionView {
            decision: "allow".into(),
            matched_policies: vec!["p1".into()],
            approver_group: None,
            reason: "ok".into(),
            redacted_fields: vec![],
        },
        write_fail: true,
        ..MockRuntime::default()
    };
    let out = evaluate_authorize(&rt, m, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert!(
                resp.reason.contains("audit_writer_unavailable"),
                "reason={}",
                resp.reason
            );
        }
        other => panic!("expected deny decision, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 0);
}

#[tokio::test]
async fn evaluate_write_fail_low_risk_allows_without_audit() {
    // Low-risk allow degrades open when the audit writer is down (historical
    // contract): decision is still allow, but no durable write occurred.
    let rt = MockRuntime {
        cedar: PolicyDecisionView {
            decision: "allow".into(),
            matched_policies: vec!["p1".into()],
            approver_group: None,
            reason: "ok".into(),
            redacted_fields: vec![],
        },
        write_fail: true,
        ..MockRuntime::default()
    };
    let out =
        evaluate_authorize(&rt, meta_allow(), Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "allow");
            assert!(resp.receipt.is_none());
        }
        other => panic!("expected allow without audit, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 0);
}

fn meta_require_approval() -> MetadataAuthorize {
    let mut m = meta_allow();
    m.guarded.request.tool_call.mutates_state = true;
    m.risk_level = "medium".into();
    m.risk_score = 40;
    m
}

#[tokio::test]
async fn evaluate_require_approval_create_bad_request_preserves_class() {
    let rt = MockRuntime {
        cedar: PolicyDecisionView {
            decision: "require_approval".into(),
            matched_policies: vec!["needs_human".into()],
            approver_group: Some("sec".into()),
            reason: "human gate".into(),
            redacted_fields: vec![],
        },
        approval_bad_request: Some("callback URL rejected (SSRF policy)".into()),
        ..MockRuntime::default()
    };
    let out = evaluate_authorize(
        &rt,
        meta_require_approval(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    assert_eq!(out.http_status, 400);
    match out.body {
        DecisionBody::Failure(f) => {
            assert_eq!(f.class, DecisionFailureClass::BadRequest);
            assert!(f.message.contains("callback URL rejected"));
        }
        other => panic!("expected BadRequest Failure, got {other:?}"),
    }
    assert_eq!(*rt.approvals.lock().expect("l"), 0);
}

#[tokio::test]
async fn evaluate_require_approval_create_internal_fail_closed() {
    let rt = MockRuntime {
        cedar: PolicyDecisionView {
            decision: "require_approval".into(),
            matched_policies: vec!["needs_human".into()],
            approver_group: None,
            reason: "human gate".into(),
            redacted_fields: vec![],
        },
        approval_fail: true,
        ..MockRuntime::default()
    };
    let out = evaluate_authorize(
        &rt,
        meta_require_approval(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    assert_eq!(out.http_status, 500);
    match out.body {
        DecisionBody::Failure(f) => {
            assert_eq!(f.class, DecisionFailureClass::Internal);
        }
        other => panic!("expected Internal Failure, got {other:?}"),
    }
    assert_eq!(*rt.approvals.lock().expect("l"), 0);
}
