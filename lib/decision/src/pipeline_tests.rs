use super::*;
use crate::agent::AuthorizeAgent;
use crate::context::{AuthCredential, Transport};
use crate::outcome::DecisionBody;
use crate::runtime::{AdmissionEffect, EnforcementStatus, McpToolMeta, PolicyDecisionView};
use crate::test_runtime::MockRuntime;
use aegis_api::models::DecisionRecord;
use chrono::Utc;
use std::net::SocketAddr;
use std::time::Instant;

fn body_json() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
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
    }))
    .expect("json")
}

fn mcp_body_json(server: &str, action: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "agent": { "id": "a1", "environment": "dev" },
        "tool_call": {
            "tool": format!("mcp:{server}"),
            "action": action,
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

fn ctx() -> AuthorizeContext {
    AuthorizeContext::new(
        "tenant-1",
        SocketAddr::from(([10, 0, 0, 1], 4443)),
        Transport::Rest,
        AuthCredential::BearerToken("tok".into()),
    )
}

#[test]
fn response_from_record_maps_fields() {
    let record = DecisionRecord {
        id: Uuid::nil().to_string(),
        tenant_id: "t1".into(),
        agent_id: "a1".into(),
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
        matched_policy_ids: Some("p1,p2".into()),
        request_id: Some("r1".into()),
        latency_ms: None,
        composite_risk_score: Some(12),
        root_trust_level: Some("trusted_internal_unsigned".into()),
        parent_run_id: None,
        created_at: Utc::now(),
    };
    let resp = authorize_response_from_decision_record(record, None);
    assert_eq!(resp.decision, "allow");
    assert_eq!(resp.risk_score, 10);
    assert_eq!(resp.composite_risk_score, 12);
    assert_eq!(resp.matched_policies, vec!["p1", "p2"]);
    assert!(!resp.dry_run);
    assert!(resp.receipt.is_none());
}

#[tokio::test]
async fn pipeline_allow_writes_decision_and_heartbeats() {
    let rt = MockRuntime::default();
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "allow");
            assert_eq!(resp.reason, "ok");
        }
        other => panic!("expected decision, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
    assert_eq!(*rt.heartbeats.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_bad_token_unauthorized() {
    let rt = MockRuntime {
        agent: None,
        ..MockRuntime::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    assert_eq!(out.http_status, 401);
    assert!(matches!(out.body, DecisionBody::Failure(_)));
    assert_eq!(*rt.writes.lock().expect("l"), 0);
}

#[tokio::test]
async fn pipeline_idempotent_replay_skips_cedar_write() {
    let record = DecisionRecord {
        id: Uuid::nil().to_string(),
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
        reason: Some("cached".into()),
        matched_policy_ids: None,
        request_id: Some("req-1".into()),
        latency_ms: None,
        composite_risk_score: Some(10),
        root_trust_level: Some("trusted_internal_unsigned".into()),
        parent_run_id: None,
        created_at: Utc::now(),
    };
    let rt = MockRuntime {
        idempotent: Some(record),
        ..MockRuntime::default()
    };
    let mut body: serde_json::Value = serde_json::from_slice(&body_json()).expect("v");
    body["request_id"] = serde_json::json!("req-1");
    let raw = serde_json::to_vec(&body).expect("ser");
    let out =
        run_authorize_pipeline(&rt, &ctx(), &raw, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "allow");
            assert_eq!(resp.reason, "cached");
        }
        other => panic!("expected replay decision, got {other:?}"),
    }
    // Idempotent path must not re-write a decision row.
    assert_eq!(*rt.writes.lock().expect("l"), 0);
    assert_eq!(*rt.heartbeats.lock().expect("l"), 0);
}

#[tokio::test]
async fn pipeline_require_approval_creates_approval_info() {
    let rt = MockRuntime {
        cedar: PolicyDecisionView {
            decision: "require_approval".into(),
            matched_policies: vec!["needs_human".into()],
            approver_group: Some("sec".into()),
            reason: "human gate".into(),
            redacted_fields: vec![],
        },
        ..MockRuntime::default()
    };
    let mut body: serde_json::Value = serde_json::from_slice(&body_json()).expect("v");
    body["tool_call"]["mutates_state"] = serde_json::json!(true);
    let raw = serde_json::to_vec(&body).expect("ser");
    let out =
        run_authorize_pipeline(&rt, &ctx(), &raw, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "require_approval");
            assert!(resp.approval.is_some());
        }
        other => panic!("expected approval decision, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
    assert_eq!(*rt.approvals.lock().expect("l"), 1);
    // Mutating require_approval requires a durable receipt.
    assert_eq!(*rt.receipts.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_frozen_agent_denies_and_persists() {
    let mut agent = AuthorizeAgent::new("agent-1", "tenant-1", "low");
    agent.status = "frozen".into();
    let rt = MockRuntime {
        agent: Some(agent),
        ..MockRuntime::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert!(
                resp.reason.contains("frozen"),
                "reason should mention frozen: {}",
                resp.reason
            );
            assert_eq!(resp.matched_policies, vec!["agent_frozen".to_string()]);
            assert!(resp.approval.is_none());
            assert!(resp.receipt.is_none());
        }
        other => panic!("expected frozen deny decision, got {other:?}"),
    }
    // Early deny still records a decision row (fail-closed audit trail).
    assert_eq!(*rt.writes.lock().expect("l"), 1);
    // Heartbeat is touched during preflight before the frozen guard.
    assert_eq!(*rt.heartbeats.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_dry_run_allow_skips_receipt_and_side_effects() {
    let rt = MockRuntime::default();
    let mut body: serde_json::Value = serde_json::from_slice(&body_json()).expect("v");
    body["dry_run"] = serde_json::json!(true);
    body["request_id"] = serde_json::json!("dry-req-1");
    let raw = serde_json::to_vec(&body).expect("ser");
    let out =
        run_authorize_pipeline(&rt, &ctx(), &raw, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "allow");
            assert!(resp.dry_run, "response must echo dry_run");
            assert!(resp.receipt.is_none(), "dry-run must not emit receipts");
            assert!(resp.approval.is_none());
        }
        other => panic!("expected dry-run allow, got {other:?}"),
    }
    // Host port is still invoked for composite score (#1281 score-only path);
    // durable side effects (heartbeat, receipts, approvals) stay off.
    assert_eq!(*rt.writes.lock().expect("l"), 1);
    assert_eq!(*rt.heartbeats.lock().expect("l"), 0);
}

#[tokio::test]
async fn pipeline_dry_run_bypasses_idempotent_replay() {
    // A prior real decision exists for request_id, but dry-run must ignore it
    // and re-evaluate (idempotency is for durable requests only).
    let record = DecisionRecord {
        id: Uuid::nil().to_string(),
        tenant_id: "tenant-1".into(),
        agent_id: "agent-1".into(),
        user_id: None,
        run_id: None,
        trace_id: None,
        skill: "echo".into(),
        action: "run".into(),
        resource: None,
        input_json: "{}".into(),
        decision: "deny".into(),
        risk_score: Some(99),
        reason: Some("cached deny".into()),
        matched_policy_ids: None,
        request_id: Some("req-dry".into()),
        latency_ms: None,
        composite_risk_score: Some(99),
        root_trust_level: Some("trusted_internal_unsigned".into()),
        parent_run_id: None,
        created_at: Utc::now(),
    };
    let rt = MockRuntime {
        idempotent: Some(record),
        cedar: PolicyDecisionView {
            decision: "allow".into(),
            matched_policies: vec!["base_allow".into()],
            approver_group: None,
            reason: "fresh dry-run allow".into(),
            redacted_fields: vec![],
        },
        ..MockRuntime::default()
    };
    let mut body: serde_json::Value = serde_json::from_slice(&body_json()).expect("v");
    body["dry_run"] = serde_json::json!(true);
    body["request_id"] = serde_json::json!("req-dry");
    let raw = serde_json::to_vec(&body).expect("ser");
    let out =
        run_authorize_pipeline(&rt, &ctx(), &raw, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "allow");
            assert_eq!(resp.reason, "fresh dry-run allow");
            assert!(resp.dry_run);
        }
        other => panic!("expected fresh dry-run allow, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_cedar_deny_persists() {
    let rt = MockRuntime {
        cedar: PolicyDecisionView {
            decision: "deny".into(),
            matched_policies: vec!["forbid_tool".into()],
            approver_group: None,
            reason: "policy deny".into(),
            redacted_fields: vec![],
        },
        ..MockRuntime::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert_eq!(resp.reason, "policy deny");
            assert_eq!(resp.matched_policies, vec!["forbid_tool".to_string()]);
            assert!(resp.approval.is_none());
        }
        other => panic!("expected cedar deny, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
    assert_eq!(*rt.heartbeats.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_revoked_agent_denies() {
    let mut agent = AuthorizeAgent::new("agent-1", "tenant-1", "low");
    agent.status = "revoked".into();
    let rt = MockRuntime {
        agent: Some(agent),
        ..MockRuntime::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert!(resp.reason.contains("revoked"), "reason={}", resp.reason);
            assert_eq!(resp.matched_policies, vec!["agent_revoked".to_string()]);
        }
        other => panic!("expected revoked deny, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_admission_webhook_reject_denies() {
    let rt = MockRuntime {
        admission: AdmissionEffect::Reject("webhook blocked".into()),
        ..MockRuntime::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert_eq!(resp.reason, "webhook blocked");
            assert_eq!(
                resp.matched_policies,
                vec!["admission_webhook_reject".to_string()]
            );
        }
        other => panic!("expected webhook reject deny, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_tool_banned_denies() {
    let rt = MockRuntime {
        enforcement: EnforcementStatus::ToolBanned,
        ..MockRuntime::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert!(resp.reason.contains("banned") || resp.reason.contains("tool"));
            assert_eq!(resp.matched_policies, vec!["tool_banned".to_string()]);
        }
        other => panic!("expected tool ban deny, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_agent_banned_denies() {
    let rt = MockRuntime {
        enforcement: EnforcementStatus::AgentBanned,
        ..MockRuntime::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert!(resp.reason.contains("banned"), "reason={}", resp.reason);
            assert_eq!(resp.matched_policies, vec!["agent_banned".to_string()]);
        }
        other => panic!("expected ban deny, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
    assert_eq!(*rt.heartbeats.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_tool_not_permitted_partial_deny() {
    let rt = MockRuntime {
        tool_permitted: false,
        ..MockRuntime::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    assert_eq!(out.http_status, 403);
    match out.body {
        DecisionBody::PartialDeny { reason } => {
            assert!(reason.contains("not permitted"), "reason={reason}");
        }
        other => panic!("expected PartialDeny, got {other:?}"),
    }
    // Preflight partial deny does not write a full decision row.
    assert_eq!(*rt.writes.lock().expect("l"), 0);
    assert_eq!(*rt.heartbeats.lock().expect("l"), 0);
}

#[tokio::test]
async fn pipeline_mcp_server_not_permitted_partial_deny() {
    let rt = MockRuntime {
        mcp_server_permitted: false,
        ..MockRuntime::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &mcp_body_json("fs", "read_file"),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    assert_eq!(out.http_status, 403);
    match out.body {
        DecisionBody::PartialDeny { reason } => {
            assert!(reason.contains("MCP server"), "reason={reason}");
        }
        other => panic!("expected MCP permission PartialDeny, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 0);
}

#[tokio::test]
async fn pipeline_mcp_quarantined_server_denies() {
    let rt = MockRuntime {
        mcp_server_status: Some("quarantined".into()),
        mcp_tool: Some(McpToolMeta {
            risk: "medium".into(),
            approval_required: false,
            status: "approved".into(),
        }),
        ..MockRuntime::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &mcp_body_json("fs", "read_file"),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert!(
                resp.reason.contains("quarantined"),
                "reason={}",
                resp.reason
            );
            assert_eq!(
                resp.matched_policies,
                vec!["mcp_server_quarantined".to_string()]
            );
        }
        other => panic!("expected MCP quarantine deny, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_mcp_unapproved_tool_denies() {
    let rt = MockRuntime {
        mcp_server_status: Some("active".into()),
        mcp_tool: Some(McpToolMeta {
            risk: "high".into(),
            approval_required: false,
            status: "pending".into(),
        }),
        ..MockRuntime::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &mcp_body_json("github", "merge_pr"),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert!(
                resp.reason.contains("not approved"),
                "reason={}",
                resp.reason
            );
            assert_eq!(resp.matched_policies, vec!["mcp_tool_status".to_string()]);
        }
        other => panic!("expected MCP tool status deny, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_mcp_approved_tool_allows() {
    let rt = MockRuntime {
        mcp_server_status: Some("active".into()),
        mcp_tool: Some(McpToolMeta {
            risk: "low".into(),
            approval_required: false,
            status: "approved".into(),
        }),
        ..MockRuntime::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &mcp_body_json("fs", "read_file"),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "allow");
            assert_eq!(resp.reason, "ok");
        }
        other => panic!("expected MCP allow, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
    assert_eq!(*rt.heartbeats.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_rate_limit_returns_429() {
    let rt = MockRuntime {
        rate_ok: false,
        ..MockRuntime::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    assert_eq!(out.http_status, 429);
    match out.body {
        DecisionBody::Failure(f) => {
            assert!(f.message.contains("Rate limit"), "message={}", f.message);
        }
        other => panic!("expected rate-limit Failure, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 0);
}

#[tokio::test]
async fn pipeline_quota_exceeded_returns_429() {
    let rt = MockRuntime {
        quota_ok: false,
        ..MockRuntime::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    assert_eq!(out.http_status, 429);
    match out.body {
        DecisionBody::Failure(f) => {
            assert!(f.message.contains("quota"), "message={}", f.message);
        }
        other => panic!("expected quota Failure, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 0);
}

#[tokio::test]
async fn pipeline_audit_stream_full_fail_closed_for_mutating() {
    let rt = MockRuntime {
        audit_capacity: false,
        ..MockRuntime::default()
    };
    let mut body: serde_json::Value = serde_json::from_slice(&body_json()).expect("v");
    body["tool_call"]["mutates_state"] = serde_json::json!(true);
    let raw = serde_json::to_vec(&body).expect("ser");
    let out =
        run_authorize_pipeline(&rt, &ctx(), &raw, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert!(
                resp.reason.contains("audit_writer_unavailable")
                    || resp.reason.contains("Audit writer unavailable"),
                "reason={}",
                resp.reason
            );
            assert_eq!(
                resp.matched_policies,
                vec!["audit_writer_unavailable".to_string()]
            );
        }
        other => panic!("expected audit fail-closed deny, got {other:?}"),
    }
    // Fail-closed before durable write when the SOC stream is full.
    assert_eq!(*rt.writes.lock().expect("l"), 0);
    assert_eq!(*rt.receipts.lock().expect("l"), 0);
}

#[tokio::test]
async fn pipeline_mutating_allow_emits_durable_receipt() {
    let rt = MockRuntime::default();
    let mut body: serde_json::Value = serde_json::from_slice(&body_json()).expect("v");
    body["tool_call"]["mutates_state"] = serde_json::json!(true);
    let raw = serde_json::to_vec(&body).expect("ser");
    let out =
        run_authorize_pipeline(&rt, &ctx(), &raw, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "allow");
            assert!(
                resp.receipt.is_some(),
                "mutating allow must carry receipt identity"
            );
        }
        other => panic!("expected mutating allow, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
    assert_eq!(*rt.receipts.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_durable_receipt_failure_fail_closed() {
    // Protected decisions (mutating allow) must not report success if the
    // receipt store is unavailable — even after the decision row was written.
    let rt = MockRuntime {
        receipt_fail: true,
        ..MockRuntime::default()
    };
    let mut body: serde_json::Value = serde_json::from_slice(&body_json()).expect("v");
    body["tool_call"]["mutates_state"] = serde_json::json!(true);
    let raw = serde_json::to_vec(&body).expect("ser");
    let out =
        run_authorize_pipeline(&rt, &ctx(), &raw, Instant::now(), EvaluateConfig::default()).await;
    assert_eq!(out.http_status, 500);
    match out.body {
        DecisionBody::Failure(f) => {
            assert!(
                f.message.contains("durably record") || f.message.contains("evidence"),
                "message={}",
                f.message
            );
        }
        other => panic!("expected Failure when receipt store is down, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
    assert_eq!(*rt.receipts.lock().expect("l"), 0);
}

#[tokio::test]
async fn pipeline_require_approval_create_failure_fail_closed() {
    let rt = MockRuntime {
        cedar: PolicyDecisionView {
            decision: "require_approval".into(),
            matched_policies: vec!["needs_human".into()],
            approver_group: Some("sec".into()),
            reason: "human gate".into(),
            redacted_fields: vec![],
        },
        approval_fail: true,
        ..MockRuntime::default()
    };
    let mut body: serde_json::Value = serde_json::from_slice(&body_json()).expect("v");
    body["tool_call"]["mutates_state"] = serde_json::json!(true);
    let raw = serde_json::to_vec(&body).expect("ser");
    let out =
        run_authorize_pipeline(&rt, &ctx(), &raw, Instant::now(), EvaluateConfig::default()).await;
    assert_eq!(out.http_status, 500);
    match out.body {
        DecisionBody::Failure(_) => {}
        other => panic!("expected Failure when approval create fails, got {other:?}"),
    }
    // Decision may have been written before approval create; no approval row.
    assert_eq!(*rt.approvals.lock().expect("l"), 0);
}

#[tokio::test]
async fn pipeline_dry_run_require_approval_creates_no_approval_row() {
    let rt = MockRuntime {
        cedar: PolicyDecisionView {
            decision: "require_approval".into(),
            matched_policies: vec!["needs_human".into()],
            approver_group: Some("sec".into()),
            reason: "human gate".into(),
            redacted_fields: vec![],
        },
        ..MockRuntime::default()
    };
    let mut body: serde_json::Value = serde_json::from_slice(&body_json()).expect("v");
    body["dry_run"] = serde_json::json!(true);
    body["tool_call"]["mutates_state"] = serde_json::json!(true);
    let raw = serde_json::to_vec(&body).expect("ser");
    let out =
        run_authorize_pipeline(&rt, &ctx(), &raw, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "require_approval");
            assert!(resp.dry_run);
            assert!(
                resp.approval.is_none(),
                "dry-run must not create approval info"
            );
            assert!(resp.receipt.is_none());
        }
        other => panic!("expected dry-run require_approval, got {other:?}"),
    }
    assert_eq!(*rt.approvals.lock().expect("l"), 0);
    assert_eq!(*rt.receipts.lock().expect("l"), 0);
    // Score-only host write still invoked.
    assert_eq!(*rt.writes.lock().expect("l"), 1);
}
