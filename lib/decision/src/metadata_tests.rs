use super::*;
use crate::agent::AuthorizeAgent;
use crate::guard::GuardedAuthorize;
use crate::outcome::DecisionBody;
use crate::runtime::{McpToolMeta, RegisteredActionMeta};
use crate::test_runtime::MockRuntime;
use std::time::Instant;

fn guarded(tool: &str, action: &str) -> GuardedAuthorize {
    let body = serde_json::json!({
        "agent": { "id": "a1", "environment": "dev" },
        "tool_call": {
            "tool": tool,
            "action": action,
            "parameters": {},
            "mutates_state": false
        },
        "context": {
            "source_trust": "trusted_internal_unsigned",
            "contains_sensitive_data": false
        }
    });
    GuardedAuthorize {
        request: serde_json::from_value(body).expect("req"),
        agent: AuthorizeAgent::new("agent-1", "tenant-1", "low"),
        root_trust_level: "trusted_internal_unsigned".into(),
        dry_run: false,
        used_mtls: false,
        normalized_tool: tool.to_lowercase(),
        normalized_action: action.to_lowercase(),
        action_hash: "hash".into(),
    }
}

#[tokio::test]
async fn metadata_skill_action_sets_risk() {
    let rt = MockRuntime {
        skill: Some(RegisteredActionMeta {
            risk: "high".into(),
            mutates_state: true,
            approval_required: true,
            default_decision: "require_approval".into(),
        }),
        mcp_server_permitted: true,
        mcp_server_status: None,
        mcp_tool: None,
        ..MockRuntime::default()
    };
    let got = metadata_authorize(&rt, guarded("echo", "run"), Instant::now())
        .await
        .expect("ok");
    assert_eq!(got.risk_level, "high");
    assert_eq!(got.risk_score, 75);
    assert!(got.action_approval_required);
    assert!(!got.is_mcp_call);
    assert!(got.is_tool_known);
}

#[tokio::test]
async fn metadata_mcp_permission_denied() {
    let rt = MockRuntime {
        skill: None,
        mcp_server_permitted: false,
        mcp_server_status: Some("active".into()),
        mcp_tool: Some(McpToolMeta {
            risk: "low".into(),
            approval_required: false,
            status: "approved".into(),
        }),
        ..MockRuntime::default()
    };
    let err = metadata_authorize(&rt, guarded("mcp:fs", "read"), Instant::now())
        .await
        .expect_err("deny");
    assert_eq!(err.http_status, 403);
    match err.body {
        DecisionBody::PartialDeny { reason } => {
            assert!(reason.contains("MCP server"));
        }
        _ => panic!("partial deny"),
    }
}

#[tokio::test]
async fn metadata_mcp_quarantined_server() {
    let rt = MockRuntime {
        skill: None,
        mcp_server_permitted: true,
        mcp_server_status: Some("quarantined".into()),
        mcp_tool: None,
        ..MockRuntime::default()
    };
    let err = metadata_authorize(&rt, guarded("mcp:fs", "read"), Instant::now())
        .await
        .expect_err("quarantine");
    match err.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert!(resp.reason.contains("quarantined"));
        }
        _ => panic!("decision"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
}

#[tokio::test]
async fn metadata_mcp_unapproved_tool() {
    let rt = MockRuntime {
        skill: None,
        mcp_server_permitted: true,
        mcp_server_status: Some("active".into()),
        mcp_tool: Some(McpToolMeta {
            risk: "medium".into(),
            approval_required: false,
            status: "pending".into(),
        }),
        ..MockRuntime::default()
    };
    let err = metadata_authorize(&rt, guarded("mcp:fs", "read_file"), Instant::now())
        .await
        .expect_err("unapproved");
    match err.body {
        DecisionBody::Decision(resp) => {
            assert!(resp.reason.contains("not approved"));
        }
        _ => panic!("decision"),
    }
}

#[tokio::test]
async fn metadata_unknown_mcp_tool_critical() {
    let rt = MockRuntime {
        skill: None,
        mcp_server_permitted: true,
        mcp_server_status: Some("active".into()),
        mcp_tool: None,
        ..MockRuntime::default()
    };
    let got = metadata_authorize(&rt, guarded("mcp:fs", "unknown"), Instant::now())
        .await
        .expect("ok continue");
    assert!(!got.is_tool_known);
    assert_eq!(got.risk_level, "critical");
    assert_eq!(got.risk_score, 100);
}
