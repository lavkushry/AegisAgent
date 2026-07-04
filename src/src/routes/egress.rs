//! Phase 5.2 (`docs/AegisAgent_Phased_PR_Plan.md`, section 7): the egress
//! check API. Wires `aegis_egress::EgressPolicy` (Phase 5.1) to the
//! gateway's existing ban store (Phase 2.4) and quarantine store
//! (Phase 2.5) for a fast first-line check, then to the same
//! runtime-event + receipt machinery the core authorize pipeline uses
//! (`decision_requires_durable_receipt`) so a blocked egress attempt — or
//! an *allowed* high-risk one — is durably evidenced, not just decided.
//!
//! Like `aegis-egress` itself, this module never fetches tenant/run
//! egress rules on its own: the caller (the Phase 5.3 proxy binary)
//! supplies the applicable rules in the request body. Bans and
//! quarantine, by contrast, are looked up here directly — they are
//! tenant-global enforcement primitives the gateway already owns.

use std::net::IpAddr;
use std::sync::Arc;

use aegis_egress::{EgressDecision, EgressDestination, EgressPolicy, EgressRule};
use aegis_storage::traits::RuntimeEventListFilters;
use axum::{
    extract::{RawQuery, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::error;
use uuid::Uuid;

use crate::error::StatusError;
use crate::models::*;

use super::authorize_canon::CANON_VERSION;
use super::{paginated_response, parse_cursor, parse_pagination, AppState, TenantId};

fn default_risk_level() -> String {
    "low".to_string()
}

fn default_source_trust() -> String {
    "trusted_internal_unsigned".to_string()
}

/// Body for `POST /v1/egress/check`.
#[derive(Debug, Deserialize)]
pub struct EgressCheckRequest {
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub sandbox_id: Option<String>,
    /// A hostname or a raw IP literal.
    pub destination: String,
    #[serde(default)]
    pub tenant_rules: Vec<EgressRule>,
    #[serde(default)]
    pub run_rules: Vec<EgressRule>,
    #[serde(default)]
    pub deny_by_default: bool,
    /// `low` | `medium` | `high` | `critical` (default `low`) — mirrors the
    /// authorize pipeline's own risk level, so a high-risk *allowed* egress
    /// still gets a durable, verifiable receipt rather than only an event.
    #[serde(default = "default_risk_level")]
    pub risk_level: String,
    #[serde(default = "default_source_trust")]
    pub source_trust: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EgressCheckResponse {
    pub decision: String,
    pub reason: String,
    pub event_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ActionReceiptRecord>,
}

fn ban_target_type(destination: &str) -> &'static str {
    if destination.parse::<IpAddr>().is_ok() {
        "destination_ip"
    } else {
        "destination_domain"
    }
}

/// Any of a run/sandbox/agent already under active quarantine gets no
/// egress at all — quarantine freezes a target pending review, and a
/// still-running egress path would keep contaminating the evidence it's
/// meant to preserve.
async fn any_target_quarantined(
    storage: &dyn aegis_storage::traits::StorageBackend,
    tenant_id: &str,
    req: &EgressCheckRequest,
) -> Result<bool, aegis_common::errors::AegisError> {
    if let Some(run_id) = &req.run_id {
        if storage.is_quarantined(tenant_id, "run", run_id).await? {
            return Ok(true);
        }
    }
    if let Some(sandbox_id) = &req.sandbox_id {
        if storage
            .is_quarantined(tenant_id, "sandbox", sandbox_id)
            .await?
        {
            return Ok(true);
        }
    }
    if let Some(agent_id) = &req.agent_id {
        if storage.is_quarantined(tenant_id, "agent", agent_id).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// POST /v1/egress/check — fast ban/quarantine check, then a rule-based
/// decision via `aegis_egress::EgressPolicy`. Tenant-scoped. Always emits
/// a `runtime_events` row; also emits a durable, hash-chained receipt when
/// the decision is `deny`, or when it's `allow` but `risk_level` is
/// `high`/`critical` — the same "protected decision" rule
/// `decision_requires_durable_receipt` already applies to `POST
/// /v1/authorize`.
pub async fn check_egress(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(req): Json<EgressCheckRequest>,
) -> impl IntoResponse {
    let now = Utc::now();

    let banned = match state
        .storage
        .is_banned(
            &tenant_id,
            ban_target_type(&req.destination),
            &req.destination,
            now,
        )
        .await
    {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to check egress ban: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    let quarantined = if banned {
        false
    } else {
        match any_target_quarantined(state.storage.as_ref(), &tenant_id, &req).await {
            Ok(q) => q,
            Err(e) => {
                error!("Failed to check egress quarantine: {:?}", e);
                return StatusError::internal("Database error").into_response();
            }
        }
    };

    let (decision, reason) = if banned {
        (EgressDecision::Deny, "destination is banned".to_string())
    } else if quarantined {
        (
            EgressDecision::Deny,
            "run/sandbox/agent is quarantined".to_string(),
        )
    } else {
        let destination = match req.destination.parse::<IpAddr>() {
            Ok(ip) => EgressDestination::Ip(ip),
            Err(_) => EgressDestination::Domain(req.destination.clone()),
        };
        let policy = EgressPolicy::new(req.deny_by_default, &req.tenant_rules, &req.run_rules);
        match policy.check(&destination) {
            EgressDecision::Allow => (EgressDecision::Allow, "allowed by rule".to_string()),
            EgressDecision::Deny => (EgressDecision::Deny, "denied by rule".to_string()),
        }
    };
    let decision_str = match decision {
        EgressDecision::Allow => "allow",
        EgressDecision::Deny => "deny",
    };

    let needs_receipt =
        decision == EgressDecision::Deny || matches!(req.risk_level.as_str(), "high" | "critical");
    let receipt = if needs_receipt {
        let receipt_record = ActionReceiptRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.clone(),
            decision_id: None,
            ts: now.to_rfc3339(),
            agent_id: req.agent_id.clone(),
            user_id: None,
            run_id: req.run_id.clone(),
            trace_id: None,
            tool: Some("egress".to_string()),
            action: Some("egress_check".to_string()),
            resource: Some(req.destination.clone()),
            source_trust: req.source_trust.clone(),
            decision: decision_str.to_string(),
            approver: None,
            action_hash: None,
            prev_receipt_hash: String::new(),
            receipt_hash: String::new(),
            canon_version: CANON_VERSION.to_string(),
            signature: None,
            signer_public_key: None,
            signer_key_id: None,
            created_at: now,
        };
        match state
            .storage
            .append_action_receipt_atomic(&tenant_id, receipt_record)
            .await
        {
            Ok(r) => Some(r),
            Err(e) => {
                error!("Failed to write egress receipt: {:?}", e);
                None
            }
        }
    } else {
        None
    };

    let event_id = Uuid::new_v4().to_string();
    let event = RuntimeEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.clone(),
        event_id: event_id.clone(),
        event_type: if decision == EgressDecision::Deny {
            "egress_blocked"
        } else {
            "egress_allowed"
        }
        .to_string(),
        severity: Some(
            if decision == EgressDecision::Deny {
                "high"
            } else {
                "low"
            }
            .to_string(),
        ),
        agent_id: req.agent_id.clone(),
        run_id: req.run_id.clone(),
        sandbox_id: req.sandbox_id.clone(),
        trace_id: None,
        parent_event_id: None,
        source_component: "egress".to_string(),
        source_trust: Some(req.source_trust.clone()),
        decision: Some(decision_str.to_string()),
        reason: Some(reason.clone()),
        action_hash: None,
        prompt_hash: None,
        request_hash: None,
        response_hash: None,
        receipt_id: receipt.as_ref().map(|r| r.id.clone()),
        receipt_hash: receipt.as_ref().map(|r| r.receipt_hash.clone()),
        prev_receipt_hash: None,
        canonical_version: None,
        redaction_status: None,
        schema_version: 1,
        observed_at: now,
        received_at: now,
    };
    if let Err(e) = state.storage.insert_runtime_event(&event).await {
        error!("Failed to insert egress runtime event: {:?}", e);
    }

    (
        StatusCode::OK,
        Json(EgressCheckResponse {
            decision: decision_str.to_string(),
            reason,
            event_id,
            receipt,
        }),
    )
        .into_response()
}

/// GET /v1/egress/events — the tenant's egress check timeline
/// (`egress_allowed` / `egress_blocked`), newest activity cursor-paginated
/// the same way as every other `runtime_events`-backed listing.
pub async fn list_egress_events(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let (limit, _offset) = parse_pagination(raw_query.as_deref());
    let cursor = match parse_cursor(raw_query.as_deref()) {
        Ok(c) => c,
        Err(resp) => return *resp,
    };
    let filters = RuntimeEventListFilters {
        source_component: Some("egress"),
        ..Default::default()
    };
    match state
        .storage
        .query_runtime_events(&tenant_id, limit, cursor, filters)
        .await
    {
        Ok((rows, next_cursor)) => paginated_response(&rows, next_cursor),
        Err(e) => {
            error!("Failed to list egress events: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// Body for `POST /v1/egress/block`.
#[derive(Debug, Deserialize)]
pub struct BlockEgressRequest {
    pub destination: String,
    pub actor: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// POST /v1/egress/block — ban a specific domain or IP literal outright,
/// bypassing rule evaluation entirely on every later `check_egress` call.
/// A thin, egress-flavored wrapper over the existing Phase 2.4 ban store
/// (`target_type` is inferred from whether `destination` parses as an IP).
/// Tenant-scoped.
pub async fn block_egress(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(req): Json<BlockEgressRequest>,
) -> impl IntoResponse {
    let now = Utc::now();
    let record = AgentBanRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id,
        target_type: ban_target_type(&req.destination).to_string(),
        target_value: req.destination,
        scope: "tenant".to_string(),
        reason: req.reason,
        actor: req.actor,
        status: "active".to_string(),
        created_at: now,
        expires_at: req.expires_at,
        revoked_at: None,
        revoked_by: None,
    };
    match state.storage.insert_ban(&record).await {
        Ok(()) => (StatusCode::CREATED, Json(record)).into_response(),
        Err(e) => {
            error!("Failed to block egress destination: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// Body for `POST /v1/egress/unblock`.
#[derive(Debug, Deserialize)]
pub struct UnblockEgressRequest {
    /// The `id` returned by the original `POST /v1/egress/block` call —
    /// explicit rather than re-specifying the destination string, so
    /// unblocking never has to guess which of several overlapping bans on
    /// the same value the caller means.
    pub ban_id: String,
    pub revoked_by: String,
}

/// POST /v1/egress/unblock — revoke a ban created via `POST
/// /v1/egress/block`. Tenant-scoped; idempotent on an already-revoked ban;
/// 404 if the ban doesn't exist for this tenant.
pub async fn unblock_egress(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(req): Json<UnblockEgressRequest>,
) -> impl IntoResponse {
    let existing = match state.storage.get_ban(&tenant_id, &req.ban_id).await {
        Ok(Some(b)) => b,
        Ok(None) => return StatusError::not_found("ban not found").into_response(),
        Err(e) => {
            error!("Failed to fetch ban for unblock: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };
    if existing.status == "revoked" {
        return (StatusCode::OK, Json(existing)).into_response();
    }

    let now = Utc::now();
    match state
        .storage
        .revoke_ban(&tenant_id, &req.ban_id, &req.revoked_by, now)
        .await
    {
        Ok(_) => match state.storage.get_ban(&tenant_id, &req.ban_id).await {
            Ok(Some(r)) => (StatusCode::OK, Json(r)).into_response(),
            Ok(None) => StatusError::not_found("ban not found").into_response(),
            Err(e) => {
                error!("Failed to re-fetch ban after unblock: {:?}", e);
                StatusError::internal("Database error").into_response()
            }
        },
        Err(e) => {
            error!("Failed to unblock egress destination: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_helpers::{register_tenant_helper, setup_state};
    use axum::body::to_bytes;

    fn check_request(destination: &str) -> EgressCheckRequest {
        EgressCheckRequest {
            agent_id: None,
            run_id: None,
            sandbox_id: None,
            destination: destination.to_string(),
            tenant_rules: Vec::new(),
            run_rules: Vec::new(),
            deny_by_default: true,
            risk_level: "low".to_string(),
            source_trust: default_source_trust(),
        }
    }

    async fn body_of<T: serde::de::DeserializeOwned>(response: axum::response::Response) -> T {
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn an_unknown_destination_is_blocked_by_deny_by_default() {
        let (state, tenant_id, _agent_token) = setup_state("egress_unknown_block").await;

        let response = check_egress(
            State(state.clone()),
            TenantId(tenant_id),
            Json(check_request("unknown-destination.example")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body: EgressCheckResponse = body_of(response).await;
        assert_eq!(body.decision, "deny");
        // A denied egress is always a protected decision — it must carry a
        // durable, hash-chained receipt, not just an event.
        assert!(body.receipt.is_some());
        assert_eq!(body.receipt.unwrap().decision, "deny");
    }

    #[tokio::test]
    async fn a_high_risk_allowed_egress_still_gets_a_receipt() {
        let (state, tenant_id, _agent_token) = setup_state("egress_high_risk_allow").await;

        let mut req = check_request("api.example.com");
        req.tenant_rules = vec![EgressRule::allow_domain_suffix("api.example.com")];
        req.risk_level = "high".to_string();

        let response = check_egress(State(state.clone()), TenantId(tenant_id), Json(req))
            .await
            .into_response();
        let body: EgressCheckResponse = body_of(response).await;
        assert_eq!(body.decision, "allow");
        assert!(
            body.receipt.is_some(),
            "a high-risk allowed egress must still be durably evidenced"
        );
    }

    #[tokio::test]
    async fn a_low_risk_allowed_egress_does_not_need_a_receipt() {
        let (state, tenant_id, _agent_token) = setup_state("egress_low_risk_allow").await;

        let mut req = check_request("api.example.com");
        req.tenant_rules = vec![EgressRule::allow_domain_suffix("api.example.com")];

        let response = check_egress(State(state.clone()), TenantId(tenant_id), Json(req))
            .await
            .into_response();
        let body: EgressCheckResponse = body_of(response).await;
        assert_eq!(body.decision, "allow");
        assert!(body.receipt.is_none());
    }

    #[tokio::test]
    async fn a_banned_destination_is_denied_even_if_a_rule_would_allow_it() {
        let (state, tenant_id, _agent_token) = setup_state("egress_ban_overrides_rule").await;

        let _ = block_egress(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(BlockEgressRequest {
                destination: "evil.example.com".to_string(),
                actor: "operator@example.com".to_string(),
                reason: Some("known C2 domain".to_string()),
                expires_at: None,
            }),
        )
        .await
        .into_response();

        let mut req = check_request("evil.example.com");
        req.deny_by_default = false;
        req.tenant_rules = vec![EgressRule::allow_domain_suffix("evil.example.com")];

        let response = check_egress(State(state.clone()), TenantId(tenant_id), Json(req))
            .await
            .into_response();
        let body: EgressCheckResponse = body_of(response).await;
        assert_eq!(body.decision, "deny");
        assert_eq!(body.reason, "destination is banned");
    }

    #[tokio::test]
    async fn unblocking_a_destination_lets_it_pass_the_rule_check_again() {
        let (state, tenant_id, _agent_token) = setup_state("egress_unblock_roundtrip").await;

        let block_response = block_egress(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(BlockEgressRequest {
                destination: "temp-block.example.com".to_string(),
                actor: "operator@example.com".to_string(),
                reason: None,
                expires_at: None,
            }),
        )
        .await
        .into_response();
        let ban: AgentBanRecord = body_of(block_response).await;

        let mut req = check_request("temp-block.example.com");
        req.deny_by_default = false;
        let response = check_egress(State(state.clone()), TenantId(tenant_id.clone()), Json(req))
            .await
            .into_response();
        let body: EgressCheckResponse = body_of(response).await;
        assert_eq!(body.decision, "deny");

        let unblock_response = unblock_egress(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(UnblockEgressRequest {
                ban_id: ban.id,
                revoked_by: "operator@example.com".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(unblock_response.status(), StatusCode::OK);

        let mut req = check_request("temp-block.example.com");
        req.deny_by_default = false;
        let response = check_egress(State(state.clone()), TenantId(tenant_id), Json(req))
            .await
            .into_response();
        let body: EgressCheckResponse = body_of(response).await;
        assert_eq!(
            body.decision, "allow",
            "an unblocked destination with no other deny rule must be allowed again"
        );
    }

    #[tokio::test]
    async fn unblocking_an_unknown_ban_id_is_a_404() {
        let (state, tenant_id, _agent_token) = setup_state("egress_unblock_unknown").await;

        let response = unblock_egress(
            State(state.clone()),
            TenantId(tenant_id),
            Json(UnblockEgressRequest {
                ban_id: "does-not-exist".to_string(),
                revoked_by: "operator@example.com".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_quarantined_run_gets_no_egress_at_all() {
        let (state, tenant_id, _agent_token) = setup_state("egress_quarantined_run").await;

        state
            .storage
            .insert_quarantine(&QuarantineRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.clone(),
                target_type: "run".to_string(),
                target_value: "run-under-review".to_string(),
                reason: Some("suspicious behavior".to_string()),
                actor: "detector".to_string(),
                status: "active".to_string(),
                incident_id: None,
                created_at: Utc::now(),
                released_at: None,
                released_by: None,
            })
            .await
            .unwrap();

        let mut req = check_request("api.example.com");
        req.run_id = Some("run-under-review".to_string());
        req.deny_by_default = false;
        req.tenant_rules = vec![EgressRule::allow_domain_suffix("api.example.com")];

        let response = check_egress(State(state.clone()), TenantId(tenant_id), Json(req))
            .await
            .into_response();
        let body: EgressCheckResponse = body_of(response).await;
        assert_eq!(body.decision, "deny");
        assert_eq!(body.reason, "run/sandbox/agent is quarantined");
    }

    #[tokio::test]
    async fn egress_checks_are_tenant_isolated() {
        let (state, tenant_id, _agent_token) = setup_state("egress_tenant_isolation_a").await;
        let other_tenant_id = "tenant_egress_other".to_string();
        register_tenant_helper(
            state.storage.as_ref(),
            &other_tenant_id,
            "Other",
            "developer",
        )
        .await;

        // Tenant A bans a destination.
        let _ = block_egress(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(BlockEgressRequest {
                destination: "shared-name.example.com".to_string(),
                actor: "operator@example.com".to_string(),
                reason: None,
                expires_at: None,
            }),
        )
        .await
        .into_response();

        // Tenant B checks the SAME destination string — tenant A's ban must
        // not leak across the tenant boundary.
        let mut req = check_request("shared-name.example.com");
        req.deny_by_default = false;
        req.tenant_rules = vec![EgressRule::allow_domain_suffix("shared-name.example.com")];
        let response = check_egress(
            State(state.clone()),
            TenantId(other_tenant_id.clone()),
            Json(req),
        )
        .await
        .into_response();
        let body: EgressCheckResponse = body_of(response).await;
        assert_eq!(
            body.decision, "allow",
            "tenant B must not see tenant A's ban on the same destination string"
        );

        // Tenant B's events list must not contain tenant A's blocked-egress event.
        let events_response = list_egress_events(
            State(state.clone()),
            TenantId(other_tenant_id),
            RawQuery(None),
        )
        .await
        .into_response();
        let events: Vec<RuntimeEventRecord> = body_of(events_response).await;
        assert!(events.iter().all(|e| e.event_type != "egress_blocked"));
    }

    #[tokio::test]
    async fn list_egress_events_returns_inserted_events_for_the_tenant() {
        let (state, tenant_id, _agent_token) = setup_state("egress_list_events").await;

        let _ = check_egress(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(check_request("unlisted.example")),
        )
        .await
        .into_response();

        let response =
            list_egress_events(State(state.clone()), TenantId(tenant_id), RawQuery(None))
                .await
                .into_response();
        let events: Vec<RuntimeEventRecord> = body_of(response).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "egress_blocked");
        assert_eq!(events[0].source_component, "egress");
    }
}
