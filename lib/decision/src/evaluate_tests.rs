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

#[tokio::test]
async fn evaluate_policies_load_failure_is_internal() {
    let rt = MockRuntime {
        policies_load_fail: true,
        ..MockRuntime::default()
    };
    let out =
        evaluate_authorize(&rt, meta_allow(), Instant::now(), EvaluateConfig::default()).await;
    assert_eq!(out.http_status, 500);
    match out.body {
        DecisionBody::Failure(f) => {
            assert!(f.message.contains("load tenant policies"));
        }
        other => panic!("expected Failure, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 0);
}

#[tokio::test]
async fn evaluate_cedar_engine_failure_is_internal() {
    let rt = MockRuntime {
        cedar_fail: true,
        ..MockRuntime::default()
    };
    let out =
        evaluate_authorize(&rt, meta_allow(), Instant::now(), EvaluateConfig::default()).await;
    assert_eq!(out.http_status, 500);
    match out.body {
        DecisionBody::Failure(f) => {
            assert!(f.message.contains("Policy engine"));
        }
        other => panic!("expected Failure, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 0);
}

#[tokio::test]
async fn evaluate_quarantine_decision_quarantines_agent() {
    let rt = MockRuntime {
        cedar: PolicyDecisionView {
            decision: "quarantine".into(),
            matched_policies: vec!["q1".into()],
            approver_group: None,
            reason: "suspicious pattern".into(),
            redacted_fields: vec![],
        },
        ..MockRuntime::default()
    };
    let out =
        evaluate_authorize(&rt, meta_allow(), Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "quarantine");
            // Non-allow requires durable receipt.
            assert!(resp.receipt.is_some());
        }
        other => panic!("expected quarantine decision, got {other:?}"),
    }
    assert_eq!(*rt.quarantines.lock().expect("l"), 1);
    assert_eq!(*rt.writes.lock().expect("l"), 1);
}

#[tokio::test]
async fn evaluate_deny_may_escalate_risk_tier() {
    let mut m = meta_allow();
    m.guarded.request.tool_call.mutates_state = false;
    let rt = MockRuntime {
        cedar: PolicyDecisionView {
            decision: "deny".into(),
            matched_policies: vec!["forbid".into()],
            approver_group: None,
            reason: "denied".into(),
            redacted_fields: vec![],
        },
        escalate_to: Some(("low".into(), "medium".into())),
        ..MockRuntime::default()
    };
    let out = evaluate_authorize(&rt, m, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => assert_eq!(resp.decision, "deny"),
        other => panic!("expected deny, got {other:?}"),
    }
    assert_eq!(*rt.escalations.lock().expect("l"), 1);
}

#[tokio::test]
async fn evaluate_untrusted_mutating_deny_records_provenance() {
    let mut m = meta_allow();
    m.guarded.request.tool_call.mutates_state = true;
    m.guarded.request.context.source_trust = "untrusted_external".into();
    let rt = MockRuntime {
        cedar: PolicyDecisionView {
            decision: "deny".into(),
            matched_policies: vec!["forbid".into()],
            approver_group: None,
            reason: "untrusted mutate".into(),
            redacted_fields: vec![],
        },
        ..MockRuntime::default()
    };
    let out = evaluate_authorize(&rt, m, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => assert_eq!(resp.decision, "deny"),
        other => panic!("expected deny, got {other:?}"),
    }
    assert_eq!(*rt.provenance_denials.lock().expect("l"), 1);
}

#[tokio::test]
async fn evaluate_force_approval_overrides_cedar_allow() {
    let mut m = meta_allow();
    m.guarded.agent.force_approval = true;
    let rt = MockRuntime {
        cedar: PolicyDecisionView {
            decision: "allow".into(),
            matched_policies: vec!["base_allow".into()],
            approver_group: None,
            reason: "ok".into(),
            redacted_fields: vec![],
        },
        ..MockRuntime::default()
    };
    let out = evaluate_authorize(&rt, m, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "require_approval");
            assert!(
                resp.matched_policies
                    .iter()
                    .any(|p| p == "soc_response_force_approval"),
                "policies={:?}",
                resp.matched_policies
            );
            assert!(resp.approval.is_some());
        }
        other => panic!("expected force_approval require_approval, got {other:?}"),
    }
    assert_eq!(*rt.approvals.lock().expect("l"), 1);
}

#[tokio::test]
async fn evaluate_action_approval_required_overrides_allow() {
    let mut m = meta_allow();
    m.action_approval_required = true;
    let rt = MockRuntime {
        cedar: PolicyDecisionView {
            decision: "allow".into(),
            matched_policies: vec!["base_allow".into()],
            approver_group: None,
            reason: "ok".into(),
            redacted_fields: vec![],
        },
        ..MockRuntime::default()
    };
    let out = evaluate_authorize(&rt, m, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "require_approval");
            assert!(resp
                .matched_policies
                .iter()
                .any(|p| p == "registered_action_approval_required"));
        }
        other => panic!("expected action approval override, got {other:?}"),
    }
}

#[tokio::test]
async fn evaluate_action_default_deny_overrides_allow() {
    let mut m = meta_allow();
    m.action_default_decision = "deny".into();
    let rt = MockRuntime {
        cedar: PolicyDecisionView {
            decision: "allow".into(),
            matched_policies: vec!["base_allow".into()],
            approver_group: None,
            reason: "ok".into(),
            redacted_fields: vec![],
        },
        ..MockRuntime::default()
    };
    let out = evaluate_authorize(&rt, m, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert!(resp
                .matched_policies
                .iter()
                .any(|p| p == "registered_action_default_deny"));
        }
        other => panic!("expected default deny override, got {other:?}"),
    }
}

#[tokio::test]
async fn evaluate_critical_risk_allow_requires_approval() {
    let mut m = meta_allow();
    m.risk_level = "critical".into();
    m.risk_score = 95;
    let rt = MockRuntime {
        cedar: PolicyDecisionView {
            decision: "allow".into(),
            matched_policies: vec!["base_allow".into()],
            approver_group: None,
            reason: "ok".into(),
            redacted_fields: vec![],
        },
        ..MockRuntime::default()
    };
    let out = evaluate_authorize(&rt, m, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "require_approval");
            assert!(resp
                .matched_policies
                .iter()
                .any(|p| p == "critical_risk_requires_approval"));
        }
        other => panic!("expected critical risk approval, got {other:?}"),
    }
}

#[tokio::test]
async fn evaluate_dry_run_quarantine_does_not_quarantine_agent() {
    let mut m = meta_allow();
    m.guarded.dry_run = true;
    let rt = MockRuntime {
        cedar: PolicyDecisionView {
            decision: "quarantine".into(),
            matched_policies: vec!["q1".into()],
            approver_group: None,
            reason: "suspicious".into(),
            redacted_fields: vec![],
        },
        ..MockRuntime::default()
    };
    let out = evaluate_authorize(&rt, m, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "quarantine");
            assert!(resp.dry_run);
            assert!(resp.receipt.is_none());
        }
        other => panic!("expected dry-run quarantine, got {other:?}"),
    }
    assert_eq!(*rt.quarantines.lock().expect("l"), 0);
    assert_eq!(*rt.heartbeats.lock().expect("l"), 0);
}

#[tokio::test]
async fn evaluate_redact_keeps_redacted_fields_others_clear() {
    let rt_redact = MockRuntime {
        cedar: PolicyDecisionView {
            decision: "redact".into(),
            matched_policies: vec!["r1".into()],
            approver_group: None,
            reason: "strip secrets".into(),
            redacted_fields: vec!["password".into(), "token".into()],
        },
        ..MockRuntime::default()
    };
    let out = evaluate_authorize(
        &rt_redact,
        meta_allow(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "redact");
            assert_eq!(
                resp.redacted_fields,
                vec!["password".to_string(), "token".to_string()]
            );
        }
        other => panic!("expected redact, got {other:?}"),
    }

    let rt_allow = MockRuntime {
        cedar: PolicyDecisionView {
            decision: "allow".into(),
            matched_policies: vec!["p1".into()],
            approver_group: None,
            reason: "ok".into(),
            redacted_fields: vec!["should_clear".into()],
        },
        ..MockRuntime::default()
    };
    let out = evaluate_authorize(
        &rt_allow,
        meta_allow(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "allow");
            assert!(
                resp.redacted_fields.is_empty(),
                "non-redact decisions must clear redacted_fields"
            );
        }
        other => panic!("expected allow, got {other:?}"),
    }
}
