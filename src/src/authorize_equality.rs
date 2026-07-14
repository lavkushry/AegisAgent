//! Phase C equality corpus for authorize path parity.
//!
//! Compares the REST **HeaderMap** entry (`authorize_action_impl`) with the
//! typed **AuthorizeContext** entry (`authorize` / gRPC-style) over the same
//! requests. Both paths call `run_authorize_pipeline`; the corpus guards
//! adapter-level parity (headers vs context), not a deleted feature flag.

use super::{
    authorize, build_service_headers, error_reason_to_tonic_code, AuthCredential, AuthorizeContext,
    AuthorizedBody, AuthorizedOutcome, Transport,
};
use crate::error::ErrorReason;
use crate::models::{AuthorizeRequest, AuthorizeResponse, RegisterToolAction, RegisterToolRequest};
use crate::routes::test_helpers::{
    agent_headers, mcp_authorize_request, setup_state, test_conn_info,
};
use crate::routes::{register_tool, TenantId};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use std::sync::Arc;
use tonic::Code;

// ── Phase C: equality corpus ─────────────────────────────────────────
// Drive the REST HeaderMap path and the typed AuthorizeContext entry with the
// same requests and assert equal decision class, risk, error class, and
// approval shape. decision_id / approval_id / expires_at differ by design
// (fresh UUIDs and clocks) and are excluded from the fingerprint.

/// Snapshot of authorize response fields that must match across paths.
#[derive(Debug, PartialEq, Eq)]
struct DecisionFingerprint {
    http_status: u16,
    body_kind: &'static str,
    decision: Option<String>,
    risk_score: Option<i32>,
    risk_level: Option<String>,
    reason: Option<String>,
    matched_policies: Option<Vec<String>>,
    root_trust_level: Option<String>,
    dry_run: Option<bool>,
    has_approval: bool,
    approver_group: Option<String>,
    has_action_hash: bool,
    error_reason: Option<String>,
    error_message: Option<String>,
}

fn fingerprint_decision(res: &AuthorizeResponse, status: StatusCode) -> DecisionFingerprint {
    // Cedar match order / primary-reason selection can be non-deterministic
    // when multiple annotations fire; sort policies and drop free-text
    // reason so the corpus compares the security-relevant outcome.
    let mut policies = res.matched_policies.clone();
    policies.sort();
    let reason = if policies.len() > 1 {
        None
    } else {
        Some(res.reason.clone())
    };
    DecisionFingerprint {
        http_status: status.as_u16(),
        body_kind: "ok",
        decision: Some(res.decision.clone()),
        risk_score: Some(res.risk_score),
        risk_level: Some(res.risk_level.clone()),
        reason,
        matched_policies: Some(policies),
        root_trust_level: Some(res.root_trust_level.clone()),
        dry_run: Some(res.dry_run),
        has_approval: res.approval.is_some(),
        approver_group: res.approval.as_ref().and_then(|a| a.approver_group.clone()),
        has_action_hash: res
            .approval
            .as_ref()
            .map(|a| !a.action_hash.is_empty())
            .unwrap_or(false),
        error_reason: None,
        error_message: None,
    }
}

fn fingerprint_outcome(outcome: &AuthorizedOutcome) -> DecisionFingerprint {
    match &outcome.body {
        AuthorizedBody::Decision(res) => fingerprint_decision(res, outcome.status),
        AuthorizedBody::Status(err) => DecisionFingerprint {
            http_status: outcome.status.as_u16(),
            body_kind: "status_error",
            decision: None,
            risk_score: None,
            risk_level: None,
            reason: None,
            matched_policies: None,
            root_trust_level: None,
            dry_run: None,
            has_approval: false,
            approver_group: None,
            has_action_hash: false,
            error_reason: Some(format!("{:?}", err.reason)),
            error_message: Some(err.message.clone()),
        },
        AuthorizedBody::Json(v) => DecisionFingerprint {
            http_status: outcome.status.as_u16(),
            body_kind: "other",
            decision: v
                .get("decision")
                .and_then(|d| d.as_str())
                .map(str::to_string),
            risk_score: v
                .get("risk_score")
                .and_then(|x| x.as_i64())
                .map(|x| x as i32),
            risk_level: v
                .get("risk_level")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            reason: v.get("reason").and_then(|x| x.as_str()).map(str::to_string),
            matched_policies: None,
            root_trust_level: None,
            dry_run: None,
            has_approval: false,
            approver_group: None,
            has_action_hash: false,
            error_reason: None,
            error_message: None,
        },
    }
}

async fn run_rest_headers(
    state: Arc<crate::routes::AppState>,
    tenant_id: &str,
    agent_token: &str,
    request: &AuthorizeRequest,
    client_addr: std::net::SocketAddr,
) -> DecisionFingerprint {
    let headers = agent_headers(agent_token, tenant_id);
    let body = Bytes::from(serde_json::to_vec(request).expect("serialize"));
    let outcome = crate::routes::authorize_action_impl(state, headers, body, client_addr).await;
    fingerprint_outcome(&outcome)
}

async fn run_typed_context(
    state: Arc<crate::routes::AppState>,
    tenant_id: &str,
    agent_token: &str,
    request: &AuthorizeRequest,
    client_addr: std::net::SocketAddr,
) -> DecisionFingerprint {
    let ctx = AuthorizeContext::new(
        tenant_id,
        client_addr,
        Transport::Grpc,
        AuthCredential::BearerToken(agent_token.to_string()),
    );
    let outcome = authorize(state, ctx, request).await;
    fingerprint_outcome(&outcome)
}

async fn register_ship(state: &Arc<crate::routes::AppState>, tenant_id: &str) {
    let req = RegisterToolRequest {
        skill_key: "deployer".to_string(),
        name: "Deployer".to_string(),
        r#type: "static".to_string(),
        auth_type: None,
        owner_team: None,
        default_risk: None,
        actions: vec![RegisterToolAction {
            action_key: "ship".to_string(),
            description: None,
            risk: "low".to_string(),
            mutates_state: false,
            data_access: None,
            approval_required: false,
            default_decision: "policy".to_string(),
        }],
    };
    let resp = register_tool(
        State(state.clone()),
        TenantId(tenant_id.to_string()),
        Json(req),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
}

async fn equality_on_fresh_states(
    label: &str,
    setup_prefix: &str,
    mut build: impl FnMut() -> AuthorizeRequest,
    prepare: impl Fn(
        Arc<crate::routes::AppState>,
        String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
) {
    let peer = std::net::SocketAddr::from(([198, 51, 100, 10], 9000));

    let (state_a, tenant_a, token_a) = setup_state(&format!("{setup_prefix}_rest")).await;
    prepare(state_a.clone(), tenant_a.clone()).await;
    let rest_headers = run_rest_headers(state_a, &tenant_a, &token_a, &build(), peer).await;

    let (state_b, tenant_b, token_b) = setup_state(&format!("{setup_prefix}_ctx")).await;
    prepare(state_b.clone(), tenant_b.clone()).await;
    let typed_context = run_typed_context(state_b, &tenant_b, &token_b, &build(), peer).await;

    assert_eq!(
        rest_headers, typed_context,
        "equality corpus mismatch for `{label}`:\n  rest_headers={rest_headers:?}\n  typed_context={typed_context:?}"
    );
}

#[tokio::test]
async fn equality_allow_read_only() {
    equality_on_fresh_states(
        "allow_read_only",
        "eq_allow",
        || {
            let mut r = mcp_authorize_request("deployer", "ship");
            r.tool_call.mutates_state = false;
            r.context.source_trust = "trusted_internal_signed".to_string();
            r
        },
        |state, tenant| {
            Box::pin(async move {
                register_ship(&state, &tenant).await;
            })
        },
    )
    .await;
}

#[tokio::test]
async fn equality_deny_untrusted_mutation() {
    equality_on_fresh_states(
        "deny_untrusted_mutation",
        "eq_deny_untrusted",
        || {
            let mut r = mcp_authorize_request("deployer", "ship");
            r.tool_call.mutates_state = true;
            r.context.source_trust = "untrusted_external".to_string();
            r
        },
        |state, tenant| {
            Box::pin(async move {
                register_ship(&state, &tenant).await;
            })
        },
    )
    .await;
}

#[tokio::test]
async fn equality_require_approval_customer_context() {
    equality_on_fresh_states(
        "require_approval",
        "eq_req_approval",
        || {
            let mut r = mcp_authorize_request("deployer", "ship");
            r.tool_call.mutates_state = true;
            r.context.source_trust = "semi_trusted_customer".to_string();
            r
        },
        |state, tenant| {
            Box::pin(async move {
                register_ship(&state, &tenant).await;
            })
        },
    )
    .await;
}

#[tokio::test]
async fn equality_dry_run_allow() {
    equality_on_fresh_states(
        "dry_run_allow",
        "eq_dry_run",
        || {
            let mut r = mcp_authorize_request("deployer", "ship");
            r.tool_call.mutates_state = false;
            r.context.source_trust = "trusted_internal_signed".to_string();
            r.dry_run = Some(true);
            r
        },
        |state, tenant| {
            Box::pin(async move {
                register_ship(&state, &tenant).await;
            })
        },
    )
    .await;
}

#[tokio::test]
async fn equality_frozen_agent_deny() {
    equality_on_fresh_states(
        "frozen_agent",
        "eq_frozen",
        || mcp_authorize_request("filesystem", "read_file"),
        |state, tenant| {
            Box::pin(async move {
                let agents = state
                    .storage
                    .list_agents(&tenant, 10, 0, None)
                    .await
                    .expect("list agents");
                for a in agents {
                    state
                        .storage
                        .set_agent_status(&tenant, &a.id, "frozen")
                        .await
                        .expect("freeze");
                }
            })
        },
    )
    .await;
}

#[tokio::test]
async fn equality_bad_token_unauthorized() {
    let peer = std::net::SocketAddr::from(([198, 51, 100, 20], 9001));
    let (state, tenant_id, _good_token) = setup_state("eq_bad_token").await;
    let request = mcp_authorize_request("filesystem", "read_file");

    let rest_headers = run_rest_headers(
        state.clone(),
        &tenant_id,
        "not-a-real-token",
        &request,
        peer,
    )
    .await;
    let typed_context =
        run_typed_context(state, &tenant_id, "not-a-real-token", &request, peer).await;
    assert_eq!(
        rest_headers, typed_context,
        "bad token must match across paths"
    );
    assert_eq!(rest_headers.http_status, 401);
    assert_eq!(rest_headers.body_kind, "status_error");
    assert_eq!(rest_headers.error_reason.as_deref(), Some("Unauthorized"));
    assert_eq!(
        error_reason_to_tonic_code(ErrorReason::Unauthorized),
        Code::Unauthenticated
    );
}

#[tokio::test]
async fn equality_missing_tenant_is_client_error_on_both_paths() {
    let peer = test_conn_info();
    let (state, _tenant, token) = setup_state("eq_missing_tenant").await;
    let request = mcp_authorize_request("filesystem", "read_file");

    let mut headers = agent_headers(&token, "ignored");
    headers.remove("X-Aegis-Tenant-ID");
    let body = Bytes::from(serde_json::to_vec(&request).unwrap());
    let rest_outcome =
        crate::routes::authorize_action_impl(state.clone(), headers, body, peer).await;
    let rest_headers = fingerprint_outcome(&rest_outcome);

    let ctx = AuthorizeContext::new(
        "",
        peer,
        Transport::Grpc,
        AuthCredential::BearerToken(token),
    );
    let typed_context = match build_service_headers(&ctx) {
        Ok(h) => {
            let body = Bytes::from(serde_json::to_vec(&request).unwrap());
            let outcome = crate::routes::authorize_action_impl(state, h, body, peer).await;
            fingerprint_outcome(&outcome)
        }
        Err(e) => fingerprint_outcome(&AuthorizedOutcome::status_error(e)),
    };

    assert!(
        (400..500).contains(&rest_headers.http_status),
        "REST missing tenant must be client error, got {rest_headers:?}"
    );
    assert!(
        (400..500).contains(&typed_context.http_status),
        "typed empty tenant must be client error, got {typed_context:?}"
    );
}

#[tokio::test]
async fn equality_replay_nonce_conflict_on_both_paths() {
    for (label, use_ctx) in [("rest_headers", false), ("typed_context", true)] {
        let (state, tenant_id, token) = setup_state(&format!("eq_replay_{label}")).await;
        register_ship(&state, &tenant_id).await;
        let peer = std::net::SocketAddr::from(([203, 0, 113, 80], 7000));
        let mut request = mcp_authorize_request("deployer", "ship");
        request.tool_call.mutates_state = false;
        request.context.source_trust = "trusted_internal_signed".to_string();
        request.nonce = Some(format!("nonce-{label}"));
        request.timestamp = Some(chrono::Utc::now());

        let first = if use_ctx {
            run_typed_context(state.clone(), &tenant_id, &token, &request, peer).await
        } else {
            run_rest_headers(state.clone(), &tenant_id, &token, &request, peer).await
        };
        assert_eq!(first.decision.as_deref(), Some("allow"), "{label} first");

        let second = if use_ctx {
            run_typed_context(state, &tenant_id, &token, &request, peer).await
        } else {
            run_rest_headers(state, &tenant_id, &token, &request, peer).await
        };
        assert_eq!(
            second.http_status, 409,
            "{label} replay must conflict: {second:?}"
        );
        assert_eq!(second.body_kind, "status_error");
        assert_eq!(second.error_reason.as_deref(), Some("Conflict"));
    }
    assert_eq!(
        error_reason_to_tonic_code(ErrorReason::Conflict),
        Code::Aborted
    );
}

#[tokio::test]
async fn equality_require_approval_persists_matching_action_hash() {
    let peer = std::net::SocketAddr::from(([198, 51, 100, 30], 9002));
    let build = || {
        let mut r = mcp_authorize_request("deployer", "ship");
        r.tool_call.mutates_state = true;
        r.context.source_trust = "semi_trusted_customer".to_string();
        r
    };

    let (state_a, tenant_a, token_a) = setup_state("eq_approval_hash_rest").await;
    register_ship(&state_a, &tenant_a).await;
    let rest_headers = run_rest_headers(state_a.clone(), &tenant_a, &token_a, &build(), peer).await;
    assert!(
        rest_headers.has_approval && rest_headers.has_action_hash,
        "{rest_headers:?}"
    );

    let (state_b, tenant_b, token_b) = setup_state("eq_approval_hash_ctx").await;
    register_ship(&state_b, &tenant_b).await;
    let typed_context =
        run_typed_context(state_b.clone(), &tenant_b, &token_b, &build(), peer).await;
    assert!(
        typed_context.has_approval && typed_context.has_action_hash,
        "{typed_context:?}"
    );

    assert_eq!(rest_headers.decision, typed_context.decision);
    assert_eq!(rest_headers.approver_group, typed_context.approver_group);
    assert_eq!(rest_headers.risk_score, typed_context.risk_score);

    for (state, tenant) in [(state_a, tenant_a), (state_b, tenant_b)] {
        let approvals = state
            .storage
            .list_pending_approvals(&tenant, 10, 0)
            .await
            .expect("list pending approvals");
        assert_eq!(approvals.len(), 1, "one pending approval row");
        assert_eq!(approvals[0].original_call_hash.len(), 64);
    }
}
