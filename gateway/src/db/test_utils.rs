// Shared test helpers for all db submodules.
// This module is declared with `#[cfg(test)] pub(crate) mod test_utils;` in mod.rs,
// so we don't wrap the contents in another module here.

use crate::models::*;
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

/// Serializes tests that mutate the process-wide
/// `AEGIS_SOC_INCIDENT_DEDUP_WINDOW_SECS` env var.
pub static DEDUP_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn setup_pool(test_name: &str) -> SqlitePool {
    std::fs::create_dir_all("target").unwrap();
    let db_url = format!(
        "sqlite://target/{}_{}.db",
        test_name,
        Uuid::new_v4().simple()
    );
    crate::db::init_db(&db_url).await.unwrap()
}

#[derive(Debug)]
pub struct MockDbError {
    pub code: &'static str,
}

impl std::fmt::Display for MockDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mock db error code {}", self.code)
    }
}

impl std::error::Error for MockDbError {}

impl sqlx::error::DatabaseError for MockDbError {
    fn message(&self) -> &str {
        "mock db error"
    }

    fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
        Some(self.code.into())
    }

    fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        self
    }

    fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
        self
    }

    fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
        self
    }

    fn kind(&self) -> sqlx::error::ErrorKind {
        sqlx::error::ErrorKind::Other
    }
}

pub fn busy_error() -> sqlx::Error {
    sqlx::Error::Database(Box::new(MockDbError { code: "5" }))
}

// ── SOC test helpers ─────────────────────────────────────────────────

pub fn make_alert(id: &str, tenant_id: &str) -> SocAlertRecord {
    SocAlertRecord {
        id: id.to_string(),
        tenant_id: tenant_id.to_string(),
        rule: "confused_deputy_block".to_string(),
        severity: "high".to_string(),
        agent_id: "agent_x".to_string(),
        source_event_id: format!("evt_{}", id),
        summary: "Test alert summary".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}

pub fn make_alert_with(
    id: &str,
    tenant_id: &str,
    severity: &str,
    agent_id: &str,
) -> SocAlertRecord {
    SocAlertRecord {
        id: id.to_string(),
        tenant_id: tenant_id.to_string(),
        rule: "test_rule".to_string(),
        severity: severity.to_string(),
        agent_id: agent_id.to_string(),
        source_event_id: format!("evt_{}", id),
        summary: format!("Alert {} summary", id),
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}

pub fn make_incident(id: &str, tenant_id: &str) -> SocIncidentRecord {
    SocIncidentRecord {
        id: id.to_string(),
        tenant_id: tenant_id.to_string(),
        kind: "deny_storm".to_string(),
        severity: "high".to_string(),
        agent_id: "agent_y".to_string(),
        summary: "Test incident summary".to_string(),
        source_event_ids: serde_json::json!(["evt_1", "evt_2"]).to_string(),
        opened_at: chrono::Utc::now().to_rfc3339(),
        status: "open".to_string(),
        closed_at: None,
    }
}

pub fn make_incident_with(
    id: &str,
    tenant_id: &str,
    severity: &str,
    agent_id: &str,
) -> SocIncidentRecord {
    SocIncidentRecord {
        id: id.to_string(),
        tenant_id: tenant_id.to_string(),
        kind: "deny_storm".to_string(),
        severity: severity.to_string(),
        agent_id: agent_id.to_string(),
        summary: format!("Incident {} summary", id),
        source_event_ids: serde_json::json!(["evt_a"]).to_string(),
        opened_at: chrono::Utc::now().to_rfc3339(),
        status: "open".to_string(),
        closed_at: None,
    }
}

// ── Evidence-graph test helpers ───────────────────────────────────────

pub fn graph_perf_decision(id: &str, tenant_id: &str) -> DecisionRecord {
    DecisionRecord {
        id: id.to_string(),
        tenant_id: tenant_id.to_string(),
        agent_id: "agent_graph_perf".to_string(),
        user_id: None,
        run_id: None,
        trace_id: None,
        skill: "github".to_string(),
        action: "merge_pull_request".to_string(),
        resource: None,
        input_json: "{}".to_string(),
        decision: "require_approval".to_string(),
        risk_score: Some(75),
        reason: None,
        matched_policy_ids: None,
        request_id: None,
        latency_ms: None,
        composite_risk_score: None,
        root_trust_level: None,
        parent_run_id: None,
        created_at: Utc::now(),
    }
}

pub fn graph_perf_approval(id: &str, tenant_id: &str, decision_id: &str) -> ApprovalRecord {
    ApprovalRecord {
        id: id.to_string(),
        tenant_id: tenant_id.to_string(),
        decision_id: decision_id.to_string(),
        status: "pending".to_string(),
        approver_group: None,
        approver_user_id: None,
        reason: None,
        original_skill_call: "{}".to_string(),
        original_call_hash: "sha256:deadbeef".to_string(),
        edited_skill_call: None,
        expires_at: None,
        decided_at: None,
        callback_url: None,
        callback_secret_hash: None,
        created_at: Utc::now(),
    }
}

pub fn graph_perf_receipt(id: &str, tenant_id: &str, decision_id: &str) -> ActionReceiptRecord {
    ActionReceiptRecord {
        id: id.to_string(),
        tenant_id: tenant_id.to_string(),
        decision_id: Some(decision_id.to_string()),
        ts: Utc::now().to_rfc3339(),
        agent_id: Some("agent_graph_perf".to_string()),
        user_id: None,
        run_id: None,
        trace_id: None,
        tool: Some("github".to_string()),
        action: Some("merge_pull_request".to_string()),
        resource: None,
        source_trust: "trusted_internal_signed".to_string(),
        decision: "require_approval".to_string(),
        approver: None,
        action_hash: Some("sha256:deadbeef".to_string()),
        prev_receipt_hash: String::new(),
        receipt_hash: format!("sha256:{id}"),
        canon_version: "aegis-jcs-1".to_string(),
        signature: None,
        signer_public_key: None,
        signer_key_id: None,
        created_at: Utc::now(),
    }
}

pub async fn insert_test_receipt(pool: &SqlitePool, r: &ActionReceiptRecord) {
    sqlx::query(
        "INSERT INTO action_receipts (id, tenant_id, decision_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash, canon_version, signature, signer_public_key)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&r.id)
    .bind(&r.tenant_id)
    .bind(&r.decision_id)
    .bind(&r.ts)
    .bind(&r.agent_id)
    .bind(&r.user_id)
    .bind(&r.run_id)
    .bind(&r.trace_id)
    .bind(&r.tool)
    .bind(&r.action)
    .bind(&r.resource)
    .bind(&r.source_trust)
    .bind(&r.decision)
    .bind(&r.approver)
    .bind(&r.action_hash)
    .bind(&r.prev_receipt_hash)
    .bind(&r.receipt_hash)
    .bind(&r.canon_version)
    .bind(&r.signature)
    .bind(&r.signer_public_key)
    .execute(pool)
    .await
    .unwrap();
}

pub fn make_audit_event(id: &str, tenant_id: &str) -> AuditEventRecord {
    AuditEventRecord {
        id: id.to_string(),
        tenant_id: tenant_id.to_string(),
        event_type: "decision".to_string(),
        agent_id: Some("agent_1".to_string()),
        user_id: None,
        run_id: None,
        trace_id: None,
        span_id: None,
        skill: None,
        action: Some("read".to_string()),
        resource: Some("repo".to_string()),
        event_json: "{}".to_string(),
        input_hash: None,
        output_hash: None,
        decision_id: None,
        approval_id: None,
        created_at: Utc::now(),
    }
}
