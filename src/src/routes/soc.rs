#![allow(unused_imports)]
use crate::error::StatusError;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    Json,
};
use chrono::{DateTime, Duration, Utc};
use futures_util::stream::{self, Stream};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{error, info, warn};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use crate::db;
use crate::events::{AseEvent, EventSink};
use crate::mcp_inspect;
use crate::metrics::{is_untrusted_provenance, SecurityMetrics};
use crate::models::*;
use crate::policy::PolicyEngine;
use crate::sign;
use aegis_common::errors::AegisError;
use aegis_storage::traits::{DecisionListFilters, StorageBackend, TimeBucket};

use super::*;

/// Poll interval for `GET /v1/alerts|incidents?watch=true` (#1146)'s
/// forward-watch background tasks. SSE watch mode is explicitly a simpler
/// REST alternative to the lower-latency `/v1/ws/events` WebSocket stream
/// (which broadcasts in real time off the live SOC event pipeline) — a short
/// DB-poll interval is an acceptable, much lower-risk tradeoff than wiring a
/// new broadcast channel into `events::drain`'s detection/correlation path.
const SOC_WATCH_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Adapts an `mpsc::Receiver` into a `Stream` for [`Sse::new`], without
/// pulling in `tokio-stream` as a new dependency (`futures_util` is already
/// a direct dependency).
fn receiver_into_stream<T>(
    rx: tokio::sync::mpsc::Receiver<T>,
) -> impl Stream<Item = Result<T, Infallible>> {
    stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (Ok(item), rx))
    })
}

// Get Investigation Run Timeline
pub async fn get_timeline(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(run_id): Path<String>,
) -> impl IntoResponse {
    match state
        .storage
        .get_audit_events_by_run(&tenant_id, &run_id)
        .await
    {
        Ok(events) => (StatusCode::OK, Json(events)).into_response(),
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/audit/events — list audit events for the authenticated tenant.
///
/// Query params:
///   `decision_id` — optional equality filter (#1301).
///   `cursor` (#1142) — see [`list_decisions`]'s doc comment. This endpoint
///   has no `limit`/`offset` — it has always returned (up to) the 100 most
///   recent matching events; `cursor` only adds the ability to page past
///   that first 100.
///   `q` (#1450) — optional full-text keyword search (FTS5, prefix-matching)
///   over `event_type`/`skill`/`action`/`resource`/`agent_id`.
pub async fn get_audit_events(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let decision_id = parse_filter(raw_query.as_deref(), "decision_id");
    let cursor = match parse_cursor(raw_query.as_deref()) {
        Ok(c) => c,
        Err(resp) => return *resp,
    };
    let q = parse_filter(raw_query.as_deref(), "q").and_then(|raw| sanitize_fts5_query(&raw));
    match state
        .storage
        .get_audit_events(&tenant_id, decision_id.as_deref(), cursor, q.as_deref())
        .await
    {
        Ok((events, next_cursor)) => paginated_response(&events, next_cursor),
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/decisions — list decisions for the authenticated tenant.
///
/// Query params:
///   `limit` (default 50, max 200), `offset` (default 0).
///   `cursor` (#1142) — opaque keyset-pagination token from a previous
///   page's `X-Next-Cursor` response header; takes priority over `offset`
///   when both are supplied.
///   `agent_id` — optional equality filter.
///   `decision` — optional equality filter.
///   `q` (#1450) — optional full-text keyword search (FTS5, prefix-matching)
///   over `skill`/`action`/`resource`/`reason`/`decision`/`agent_id`.
///   `source_trust`/`skill` — optional equality filters.
///   `from`/`to` — optional RFC3339 time bounds on `created_at` (inclusive).
///
/// Parse an RFC3339 timestamp into the DB's `created_at` string format
/// (`%F %T%.6f`, space-separated) so range comparisons sort correctly — the
/// same formatting `list_decisions_in_range` (#1283) relies on. Invalid input
/// is dropped (no filter) rather than erroring, since the time range is a UI
/// convenience, not a security control.
fn to_db_timestamp(raw: &str) -> Option<String> {
    chrono::DateTime::parse_from_rfc3339(raw).ok().map(|dt| {
        dt.with_timezone(&chrono::Utc)
            .format("%F %T%.6f")
            .to_string()
    })
}

pub async fn list_decisions(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let (limit, _offset) = parse_pagination(raw_query.as_deref());
    let cursor = match parse_cursor(raw_query.as_deref()) {
        Ok(c) => c,
        Err(resp) => return *resp,
    };
    let agent_id = parse_filter(raw_query.as_deref(), "agent_id");
    let decision = parse_filter(raw_query.as_deref(), "decision");
    let source_trust = parse_filter(raw_query.as_deref(), "source_trust");
    let skill = parse_filter(raw_query.as_deref(), "skill");
    let from = parse_filter(raw_query.as_deref(), "from").and_then(|raw| to_db_timestamp(&raw));
    let to = parse_filter(raw_query.as_deref(), "to").and_then(|raw| to_db_timestamp(&raw));
    let q = parse_filter(raw_query.as_deref(), "q").and_then(|raw| sanitize_fts5_query(&raw));

    match state
        .storage
        .list_decisions(
            &tenant_id,
            limit,
            cursor,
            DecisionListFilters {
                agent_id: agent_id.as_deref(),
                decision: decision.as_deref(),
                q: q.as_deref(),
                source_trust: source_trust.as_deref(),
                skill: skill.as_deref(),
                from: from.as_deref(),
                to: to.as_deref(),
            },
        )
        .await
    {
        Ok((decisions, next_cursor)) => paginated_response(&decisions, next_cursor),
        Err(e) => {
            error!("Failed to list decisions: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/decisions/timeseries — decision counts bucketed over time for the
/// authenticated tenant. Accepts the same filters as `/v1/decisions`
/// (`agent_id`/`decision`/`source_trust`/`skill`/`from`/`to`) plus `interval`
/// (`minute`|`hour`|`day`, default `hour`). Returns `[{ bucket, count }]`.
pub async fn decision_timeseries(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let agent_id = parse_filter(raw_query.as_deref(), "agent_id");
    let decision = parse_filter(raw_query.as_deref(), "decision");
    let source_trust = parse_filter(raw_query.as_deref(), "source_trust");
    let skill = parse_filter(raw_query.as_deref(), "skill");
    let from = parse_filter(raw_query.as_deref(), "from").and_then(|raw| to_db_timestamp(&raw));
    let to = parse_filter(raw_query.as_deref(), "to").and_then(|raw| to_db_timestamp(&raw));
    let bucket = TimeBucket::parse(
        parse_filter(raw_query.as_deref(), "interval")
            .as_deref()
            .unwrap_or("hour"),
    );

    match state
        .storage
        .count_decisions_over_time(
            &tenant_id,
            bucket,
            DecisionListFilters {
                agent_id: agent_id.as_deref(),
                decision: decision.as_deref(),
                source_trust: source_trust.as_deref(),
                skill: skill.as_deref(),
                from: from.as_deref(),
                to: to.as_deref(),
                ..Default::default()
            },
        )
        .await
    {
        Ok(buckets) => {
            let points: Vec<_> = buckets
                .into_iter()
                .map(|(bucket, count)| serde_json::json!({ "bucket": bucket, "count": count }))
                .collect();
            (StatusCode::OK, Json(points)).into_response()
        }
        Err(e) => {
            error!("Failed to count decisions over time: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// POST /v1/soc/query — structured, tenant-scoped query API for the SOC console
/// (PR5). Accepts a validated entity + filter allowlist + aggregation; never raw
/// SQL. Backed entirely by existing parameterized, tenant-scoped storage
/// methods. This slice supports the `decision` entity; the entity allowlist is
/// the extension point for `alert`/`incident`/`receipt`/… (each must map only to
/// parameterized, tenant-scoped queries).
pub async fn soc_query(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(req): Json<SocQueryRequest>,
) -> impl IntoResponse {
    // Entity allowlist — fail closed on anything unknown.
    if req.entity != "decision" {
        return StatusError::bad_request(format!(
            "unsupported entity '{}' (supported: decision)",
            req.entity
        ))
        .into_response();
    }

    let from = req.filters.from.as_deref().and_then(to_db_timestamp);
    let to = req.filters.to.as_deref().and_then(to_db_timestamp);
    let q = req.filters.q.as_deref().and_then(sanitize_fts5_query);
    let filters = DecisionListFilters {
        agent_id: req.filters.agent_id.as_deref(),
        decision: req.filters.decision.as_deref(),
        q: q.as_deref(),
        source_trust: req.filters.source_trust.as_deref(),
        skill: req.filters.skill.as_deref(),
        from: from.as_deref(),
        to: to.as_deref(),
    };

    match req.aggregate.as_deref().unwrap_or("none") {
        "none" => {
            let limit = req.limit.unwrap_or(50).clamp(1, 200);
            match state
                .storage
                .list_decisions(&tenant_id, limit, req.cursor, filters)
                .await
            {
                Ok((rows, next_cursor)) => paginated_response(&rows, next_cursor),
                Err(e) => {
                    error!("soc_query list failed: {:?}", e);
                    StatusError::internal("Database error").into_response()
                }
            }
        }
        "count" => match state.storage.count_decisions_by_outcome(&tenant_id).await {
            Ok((total, allow, deny, require_approval)) => (
                StatusCode::OK,
                Json(json!({
                    "entity": "decision",
                    "aggregate": "count",
                    "total": total,
                    "by_decision": {
                        "allow": allow,
                        "deny": deny,
                        "require_approval": require_approval,
                    },
                })),
            )
                .into_response(),
            Err(e) => {
                error!("soc_query count failed: {:?}", e);
                StatusError::internal("Database error").into_response()
            }
        },
        "count_over_time" => {
            let bucket = TimeBucket::parse(req.interval.as_deref().unwrap_or("hour"));
            match state
                .storage
                .count_decisions_over_time(&tenant_id, bucket, filters)
                .await
            {
                Ok(buckets) => {
                    let points: Vec<_> = buckets
                        .into_iter()
                        .map(|(bucket, count)| json!({ "bucket": bucket, "count": count }))
                        .collect();
                    (
                        StatusCode::OK,
                        Json(json!({
                            "entity": "decision",
                            "aggregate": "count_over_time",
                            "points": points,
                        })),
                    )
                        .into_response()
                }
                Err(e) => {
                    error!("soc_query count_over_time failed: {:?}", e);
                    StatusError::internal("Database error").into_response()
                }
            }
        }
        other => StatusError::bad_request(format!(
            "unsupported aggregate '{other}' (supported: none, count, count_over_time)"
        ))
        .into_response(),
    }
}

/// GET /v1/decisions/:id — get a single decision detail for the authenticated tenant.
pub async fn get_decision(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.storage.get_decision_by_id(&tenant_id, &id).await {
        Ok(Some(decision)) => (StatusCode::OK, Json(decision)).into_response(),
        Ok(None) => StatusError::not_found("Decision not found").into_response(),
        Err(e) => {
            error!("Failed to get decision: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub(crate) fn default_detection_rule_enabled() -> bool {
    true
}

/// TASK-0088 (#934): create or update (upsert by `rule_key`) a tenant-managed
/// detection rule. First step toward SOC-003 (#1186) — `condition` and
/// `summary_template` hold a YAML rule body that will eventually be loaded
/// by `detect.rs` to replace the hardcoded Rust detection functions.
pub async fn upsert_detection_rule(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(payload): Json<UpsertDetectionRuleRequest>,
) -> impl IntoResponse {
    match state
        .storage
        .upsert_detection_rule(
            &tenant_id,
            &payload.rule_key,
            &payload.name,
            &payload.severity,
            &payload.condition,
            &payload.summary_template,
            payload.enabled,
        )
        .await
    {
        Ok(record) => (StatusCode::CREATED, Json(record)).into_response(),
        Err(e) => {
            error!("Failed to upsert detection rule: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// TASK-0088 (#934): list this tenant's detection rules.
pub async fn list_detection_rules(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
) -> impl IntoResponse {
    match state.storage.list_detection_rules(&tenant_id).await {
        Ok(rules) => (StatusCode::OK, Json(rules)).into_response(),
        Err(e) => {
            error!("Failed to list detection rules: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// One entry in the `GET /v1/soc/rules` effective-rule list: a [`rule_dsl::YamlRule`]
/// annotated with whether it's a built-in default or a tenant-managed custom rule.
#[derive(Debug, serde::Serialize)]
pub struct EffectiveDetectionRule {
    #[serde(flatten)]
    pub rule: crate::rule_dsl::YamlRule,
    /// `"default"` (embedded, applies to every tenant) or `"custom"`
    /// (tenant-managed, from the `detection_rules` table).
    pub source: &'static str,
}

/// #1282: the embedded defaults (`rule_dsl::default_rules()`) plus this
/// tenant's enabled custom rules from `detection_rules`. Mirrors exactly
/// what `events::drain` evaluates for this tenant's events. Rows whose
/// `condition` fails to parse/validate are skipped (same as `drain`).
/// Shared by `get_soc_rules` (#1282) and `backtest_soc_rule` (#1283).
pub(crate) async fn effective_detection_rules(
    storage: &dyn StorageBackend,
    tenant_id: &str,
) -> Result<Vec<EffectiveDetectionRule>, AegisError> {
    let mut rules: Vec<EffectiveDetectionRule> = crate::rule_dsl::default_rules()
        .into_iter()
        .map(|rule| EffectiveDetectionRule {
            rule,
            source: "default",
        })
        .collect();

    let records = storage.list_detection_rules(tenant_id).await?;
    for record in records.into_iter().filter(|r| r.enabled) {
        if let Ok(rule) = crate::rule_dsl::yaml_rule_from_condition(
            &record.rule_key,
            &record.name,
            &record.severity,
            &record.condition,
            &record.summary_template,
        ) {
            rules.push(EffectiveDetectionRule {
                rule,
                source: "custom",
            });
        }
    }

    Ok(rules)
}

/// #1282: list the *effective* detection rules for this tenant. SOC rule
/// listing is advisory, never gates `/v1/authorize` (Law 1).
pub async fn get_soc_rules(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
) -> impl IntoResponse {
    match effective_detection_rules(state.storage.as_ref(), &tenant_id).await {
        Ok(rules) => (StatusCode::OK, Json(rules)).into_response(),
        Err(e) => {
            error!("Failed to list detection rules: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// #1283: optional `[from, to]` window for `backtest_soc_rule`. Both
/// default to the trailing 7 days when omitted.
#[derive(Debug, serde::Deserialize)]
pub struct BacktestRuleRequest {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}

/// #1283: backtest one detection rule (default or tenant-custom, looked up
/// by `rule_key`) against this tenant's historical `decisions` over
/// `[from, to]` (default: trailing 7 days). Read-only and pure in-memory
/// evaluation — never writes a `soc_alerts`/`soc_incidents` row, so a
/// backtest can never affect the live SOC pipeline (Law 1: advisory only).
pub async fn backtest_soc_rule(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(rule_key): Path<String>,
    body: Option<Json<BacktestRuleRequest>>,
) -> impl IntoResponse {
    let to = body.as_ref().and_then(|b| b.to).unwrap_or_else(Utc::now);
    let from = body
        .as_ref()
        .and_then(|b| b.from)
        .unwrap_or_else(|| to - Duration::days(7));

    let rules = match effective_detection_rules(state.storage.as_ref(), &tenant_id).await {
        Ok(rules) => rules,
        Err(e) => {
            error!("Failed to list detection rules: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    let Some(effective_rule) = rules.into_iter().find(|r| r.rule.rule_key == rule_key) else {
        return StatusError::not_found(format!("No effective rule with rule_key '{rule_key}'"))
            .into_response();
    };

    let decisions = match state
        .storage
        .list_decisions_in_range(&tenant_id, from, to)
        .await
    {
        Ok(decisions) => decisions,
        Err(e) => {
            error!("Failed to list decisions for backtest: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    let result = crate::backtest::run_backtest(
        &effective_rule.rule,
        effective_rule.source,
        &tenant_id,
        &decisions,
        from,
        to,
    );

    (StatusCode::OK, Json(result)).into_response()
}

/// #1282: create or update a tenant-managed custom detection rule, validating
/// the YAML `condition`/`severity` via [`crate::rule_dsl`] before persisting.
/// Returns `400` with a descriptive message for an invalid rule (never `500`)
/// — mirrors the [`UpsertDetectionRuleRequest`]/[`upsert_detection_rule`]
/// shape but rejects rules that `events::drain` would have to skip.
pub async fn create_soc_rule(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(payload): Json<UpsertDetectionRuleRequest>,
) -> impl IntoResponse {
    if let Err(e) = crate::rule_dsl::yaml_rule_from_condition(
        &payload.rule_key,
        &payload.name,
        &payload.severity,
        &payload.condition,
        &payload.summary_template,
    ) {
        return StatusError::bad_request(format!("Invalid detection rule: {e}")).into_response();
    }

    match state
        .storage
        .upsert_detection_rule(
            &tenant_id,
            &payload.rule_key,
            &payload.name,
            &payload.severity,
            &payload.condition,
            &payload.summary_template,
            payload.enabled,
        )
        .await
    {
        Ok(record) => (StatusCode::CREATED, Json(record)).into_response(),
        Err(e) => {
            error!("Failed to upsert detection rule: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// #1282: `POST /v1/soc/rules/reload`. Documented no-op: `events::drain`
/// already loads each tenant's enabled custom rules fresh from
/// `detection_rules` on every event (Law 3 — out-of-band, never cached), so
/// there is no cache to invalidate. Kept as a `200` confirmation endpoint for
/// API compatibility with rule-management tooling.
pub async fn reload_soc_rules(TenantId(_tenant_id): TenantId) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "message": "Detection rules are loaded fresh on every event; no reload needed"
        })),
    )
}

/// TASK-0088 (#934): delete a tenant's detection rule.
pub async fn delete_detection_rule(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.storage.delete_detection_rule(&tenant_id, &id).await {
        Ok(true) => (
            StatusCode::OK,
            Json(json!({"message": "Detection rule successfully deleted"})),
        )
            .into_response(),
        Ok(false) => StatusError::not_found("Detection rule not found").into_response(),
        Err(e) => {
            error!("Failed to delete detection rule: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/alerts — list SOC detection alerts for the authenticated tenant.
///
/// Query params:
///   `limit` (default 50, max 200), `offset` (default 0).
///   `cursor` (#1142) — see [`list_decisions`]'s doc comment.
///   `severity` — optional equality filter (e.g. `?severity=high`).
///   `agent_id`  — optional equality filter (e.g. `?agent_id=abc`).
/// Returns a JSON array of [`SocAlertRecord`]s ordered newest-first.
/// Every result row is tenant-scoped via parameterized SQL — never leaks
/// another tenant's data.
pub async fn list_alerts(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let (limit, _offset) = parse_pagination(raw_query.as_deref());
    let cursor = match parse_cursor(raw_query.as_deref()) {
        Ok(c) => c,
        Err(resp) => return *resp,
    };
    let severity = parse_filter(raw_query.as_deref(), "severity");
    let agent_id = parse_filter(raw_query.as_deref(), "agent_id");

    // #1146: `?watch=true` switches to an SSE stream of newly created alerts
    // instead of a JSON page. Pagination/cursor params are ignored in watch
    // mode (matching Kubernetes `?watch=true` semantics — no historical
    // backfill; combine with a plain `GET /v1/alerts` call for that).
    if parse_filter(raw_query.as_deref(), "watch").as_deref() == Some("true") {
        return Sse::new(alerts_watch_stream(
            Arc::clone(&state.storage),
            tenant_id,
            severity,
            agent_id,
        ))
        .keep_alive(KeepAlive::default())
        .into_response();
    }

    match state
        .storage
        .list_soc_alerts(
            &tenant_id,
            agent_id.as_deref(),
            severity.as_deref(),
            limit,
            cursor,
        )
        .await
    {
        Ok((alerts, next_cursor)) => paginated_response(&alerts, next_cursor),
        Err(e) => {
            error!("Failed to list SOC alerts: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// Backing stream for `GET /v1/alerts?watch=true` (#1146): polls
/// [`db::list_soc_alerts_since`] every `SOC_WATCH_POLL_INTERVAL` and emits one
/// SSE `Event` per new alert, oldest-first. Runs as a detached background
/// task feeding an mpsc channel — the task exits as soon as the SSE
/// connection drops and the receiver is dropped (the next `tx.send` fails).
/// `Sse::keep_alive` (applied by the caller) handles the heartbeat-ping
/// acceptance criterion independently of this polling loop.
fn alerts_watch_stream(
    storage: Arc<dyn StorageBackend>,
    tenant_id: String,
    severity: Option<String>,
    agent_id: Option<String>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Event>(32);
    tokio::spawn(async move {
        let mut since_rowid = match storage.max_soc_alert_rowid(&tenant_id).await {
            Ok(rowid) => rowid,
            Err(e) => {
                error!("alerts watch: failed to establish starting rowid: {:?}", e);
                return;
            }
        };
        let mut interval = tokio::time::interval(SOC_WATCH_POLL_INTERVAL);
        loop {
            interval.tick().await;
            let new_alerts = match storage
                .list_soc_alerts_since(
                    &tenant_id,
                    since_rowid,
                    severity.as_deref(),
                    agent_id.as_deref(),
                )
                .await
            {
                Ok(alerts) => alerts,
                Err(e) => {
                    error!("alerts watch: poll failed: {:?}", e);
                    continue;
                }
            };
            for (alert, rowid) in new_alerts {
                since_rowid = since_rowid.max(rowid);
                let Ok(data) = serde_json::to_string(&alert) else {
                    continue;
                };
                if tx
                    .send(Event::default().event("alert").data(data))
                    .await
                    .is_err()
                {
                    return; // receiver dropped — client disconnected
                }
            }
        }
    });
    receiver_into_stream(rx)
}

/// GET /v1/incidents — list SOC correlation incidents for the authenticated tenant.
///
/// Query params:
///   `limit` (default 50, max 200), `offset` (default 0).
///   `cursor` (#1142) — see [`list_decisions`]'s doc comment.
///   `status`   — optional filter: `"open"` or `"closed"` (omit for all).
///   `severity` — optional equality filter (e.g. `?severity=high`).
///   `agent_id` — optional equality filter (e.g. `?agent_id=abc`).
/// Returns a JSON array of [`SocIncidentRecord`]s ordered newest-first.
/// Every result row is tenant-scoped via parameterized SQL — never leaks
/// another tenant's data.
pub async fn list_incidents(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let (limit, _offset) = parse_pagination(raw_query.as_deref());
    let cursor = match parse_cursor(raw_query.as_deref()) {
        Ok(c) => c,
        Err(resp) => return *resp,
    };
    let status_filter = parse_filter(raw_query.as_deref(), "status");
    let severity = parse_filter(raw_query.as_deref(), "severity");
    let agent_id = parse_filter(raw_query.as_deref(), "agent_id");
    let kind = parse_filter(raw_query.as_deref(), "kind");

    // #1146: `?watch=true` switches to an SSE stream of newly created
    // incidents instead of a JSON page — see `alerts_watch_stream`'s doc
    // comment for the design rationale (poll-based, not wired into the live
    // SOC broadcast pipeline).
    if parse_filter(raw_query.as_deref(), "watch").as_deref() == Some("true") {
        return Sse::new(incidents_watch_stream(
            Arc::clone(&state.storage),
            tenant_id,
            status_filter,
            severity,
            agent_id,
            kind,
        ))
        .keep_alive(KeepAlive::default())
        .into_response();
    }

    match state
        .storage
        .list_soc_incidents(
            &tenant_id,
            agent_id.as_deref(),
            severity.as_deref(),
            status_filter.as_deref(),
            kind.as_deref(),
            limit,
            cursor,
        )
        .await
    {
        Ok((incidents, next_cursor)) => paginated_response(&incidents, next_cursor),
        Err(e) => {
            error!("Failed to list SOC incidents: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// Backing stream for `GET /v1/incidents?watch=true` (#1146) — see
/// [`alerts_watch_stream`]'s doc comment for the shared design rationale.
#[allow(clippy::too_many_arguments)]
fn incidents_watch_stream(
    storage: Arc<dyn StorageBackend>,
    tenant_id: String,
    status_filter: Option<String>,
    severity: Option<String>,
    agent_id: Option<String>,
    kind: Option<String>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Event>(32);
    tokio::spawn(async move {
        let mut since_rowid = match storage.max_soc_incident_rowid(&tenant_id).await {
            Ok(rowid) => rowid,
            Err(e) => {
                error!(
                    "incidents watch: failed to establish starting rowid: {:?}",
                    e
                );
                return;
            }
        };
        let mut interval = tokio::time::interval(SOC_WATCH_POLL_INTERVAL);
        loop {
            interval.tick().await;
            let new_incidents = match storage
                .list_soc_incidents_since(
                    &tenant_id,
                    since_rowid,
                    status_filter.as_deref(),
                    severity.as_deref(),
                    agent_id.as_deref(),
                    kind.as_deref(),
                )
                .await
            {
                Ok(incidents) => incidents,
                Err(e) => {
                    error!("incidents watch: poll failed: {:?}", e);
                    continue;
                }
            };
            for (incident, rowid) in new_incidents {
                since_rowid = since_rowid.max(rowid);
                let Ok(data) = serde_json::to_string(&incident) else {
                    continue;
                };
                if tx
                    .send(Event::default().event("incident").data(data))
                    .await
                    .is_err()
                {
                    return; // receiver dropped — client disconnected
                }
            }
        }
    });
    receiver_into_stream(rx)
}

// ── SOC query layer: incident detail + aggregate summary ─────────────────────

/// `GET /v1/incidents/:id` — single-incident detail, tenant-scoped.
///
/// Returns the full [`SocIncidentRecord`] for the given `id` when it belongs to
/// the authenticated tenant, or HTTP 404 when the `id` is unknown **or** belongs
/// to a different tenant (CWE-284: no information leakage across tenants).
/// Both DB binds (`tenant_id`, `incident_id`) are parameterized — no SQL
/// concatenation (CWE-89).
pub async fn get_incident(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(incident_id): Path<String>,
) -> impl IntoResponse {
    match state
        .storage
        .get_incident_by_id(&tenant_id, &incident_id)
        .await
    {
        Ok(Some(incident)) => (StatusCode::OK, Json(incident)).into_response(),
        Ok(None) => StatusError::not_found("Incident not found").into_response(),
        Err(e) => {
            error!("Failed to fetch SOC incident {}: {:?}", incident_id, e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// `GET /v1/soc/summary` — tenant-scoped SOC aggregate counts.
///
/// Returns `{ alerts_total, alerts_high, incidents_total, incidents_open,
/// incidents_closed }` derived from five parameterized COUNT queries, all
/// binding `tenant_id` (CWE-284).  `alerts_high` counts alerts with
/// `severity = 'high'`; open/closed split on the incident `status` column.
/// No SQL concatenation occurs (CWE-89).
pub async fn soc_summary(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
) -> impl IntoResponse {
    match state.storage.get_soc_summary(&tenant_id).await {
        Ok(summary) => (StatusCode::OK, Json(summary)).into_response(),
        Err(e) => {
            error!("Failed to compute SOC summary: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// Query parameters for `GET /soc/semantic-search` (#1451).
#[derive(Debug, serde::Deserialize)]
pub struct SemanticSearchParams {
    pub query: String,
    pub limit: Option<usize>,
}

/// GET /soc/semantic-search — search for semantically similar audit logs in Qdrant (multi-tenant isolated).
pub async fn semantic_search(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    axum::extract::Query(params): axum::extract::Query<SemanticSearchParams>,
) -> impl IntoResponse {
    if params.query.trim().is_empty() {
        return StatusError::bad_request("Query parameter cannot be empty").into_response();
    }

    let exporter = match &state.qdrant_exporter {
        Some(exp) => exp,
        None => {
            return StatusError::not_implemented(
                "Qdrant semantic search is not configured on this gateway",
            )
            .into_response();
        }
    };

    let limit = params.limit.unwrap_or(10);

    match exporter
        .search_similar_events(&tenant_id, &params.query, limit)
        .await
    {
        Ok(results) => (StatusCode::OK, Json(results)).into_response(),
        Err(e) => {
            error!("Semantic search failed: {:?}", e);
            StatusError::internal(format!("Semantic search error: {}", e)).into_response()
        }
    }
}

// ── SOC Phase 6: Incident lifecycle ──────────────────────────────────────────

/// `POST /v1/incidents/:id/close` — close an open SOC incident.
///
/// Transitions the incident from `"open"` to `"closed"`, stamps `closed_at`,
/// and writes an `"incident_closed"` audit event. Tenant-scoped: 404 if the
/// incident does not exist for this tenant. Idempotent on a second call: a
/// 200 response is returned with `"already_closed": true` so callers can
/// distinguish the first close from a repeat without erroring.
///
/// # Security invariants
/// * Two parameterized binds on every DB call (`tenant_id` + `id`).
/// * No payload fields in the audit event — only the incident id and new status.
/// * `close_soc_incident` uses `AND status != 'closed'` to make the UPDATE
///   idempotent at the DB level; concurrent closes are safe.
pub async fn close_incident(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(incident_id): Path<String>,
) -> impl IntoResponse {
    // First verify the incident exists for this tenant (provides a meaningful 404
    // rather than a silent no-op when the id is simply wrong or belongs to another
    // tenant — CWE-284 isolation).
    let incident = match state
        .storage
        .get_incident_by_id(&tenant_id, &incident_id)
        .await
    {
        Ok(Some(inc)) => inc,
        Ok(None) => {
            return StatusError::not_found("Incident not found").into_response();
        }
        Err(e) => {
            error!("Failed to fetch incident for close: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    // If already closed, return a clear idempotent response (200 with a flag).
    if incident.status == "closed" {
        return (
            StatusCode::OK,
            Json(json!({
                "incident_id": incident.id,
                "status": "closed",
                "closed_at": incident.closed_at,
                "already_closed": true,
            })),
        )
            .into_response();
    }

    // Atomically flip status → 'closed' and stamp closed_at.
    let did_close = match state
        .storage
        .close_soc_incident(&tenant_id, &incident_id)
        .await
    {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to close incident {}: {:?}", incident_id, e);
            return StatusError::internal("Database error").into_response();
        }
    };

    if !did_close {
        // Race: incident was closed between the get and the update. Treat as
        // idempotent — re-fetch to return the correct closed_at.
        return match state
            .storage
            .get_incident_by_id(&tenant_id, &incident_id)
            .await
        {
            Ok(Some(inc)) => (
                StatusCode::OK,
                Json(json!({
                    "incident_id": inc.id,
                    "status": "closed",
                    "closed_at": inc.closed_at,
                    "already_closed": true,
                })),
            )
                .into_response(),
            _ => StatusError::internal("Database error").into_response(),
        };
    }

    // Re-fetch to pick up the DB-stamped `closed_at` timestamp.
    let closed_at = match state
        .storage
        .get_incident_by_id(&tenant_id, &incident_id)
        .await
    {
        Ok(Some(inc)) => inc.closed_at,
        Ok(None) => None,
        Err(e) => {
            error!("Failed to re-fetch incident after close: {:?}", e);
            None
        }
    };

    // SOC-005 (#1158): mean-time-to-resolve — the real gap between this
    // incident's open and close timestamps. Unparseable timestamps or a
    // negative duration (clock skew) are skipped silently.
    if let Some(closed_at_str) = closed_at.as_deref() {
        if let (Ok(opened), Ok(closed)) = (
            DateTime::parse_from_rfc3339(&incident.opened_at),
            DateTime::parse_from_rfc3339(closed_at_str),
        ) {
            let resolution_time = closed
                .with_timezone(&Utc)
                .signed_duration_since(opened.with_timezone(&Utc));
            if let Ok(resolution_time) = resolution_time.to_std() {
                state.metrics.observe_mttr(resolution_time);
            }
        }
    }

    // Write audit event (hashes / ids only — no payloads, no raw evidence).
    let audit = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.clone(),
        event_type: "incident_closed".to_string(),
        agent_id: None,
        user_id: None,
        run_id: None,
        trace_id: None,
        span_id: None,
        skill: None,
        action: None,
        resource: Some(incident_id.clone()),
        event_json: serde_json::to_string(&json!({
            "incident_id": incident_id,
            "new_status": "closed",
        }))
        .unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        decision_id: None,
        approval_id: None,
        created_at: Utc::now(),
    };
    let _ = state.storage.insert_audit_event(&audit).await;

    info!(incident_id = %incident_id, "SOC incident closed");

    (
        StatusCode::OK,
        Json(json!({
            "incident_id": incident_id,
            "status": "closed",
            "closed_at": closed_at,
            "already_closed": false,
        })),
    )
        .into_response()
}

// ── SOC Phase 6: RCA Narrator ────────────────────────────────────────────────

/// GET /v1/incidents/:id/narrate — on-demand RCA narrative for a closed incident.
///
/// # LAW-2 compliance
/// * On-demand only — never called from the authorize / drain hot paths.
/// * Tenant-scoped db fetch (two parameterized binds: tenant_id + id).
/// * 404 if the incident does not exist **or** belongs to a different tenant.
/// * The [`crate::narrate`] module builds the narrative from structured,
///   already-redacted fields only — never raw evidence or live telemetry.
/// * The narrator is constructed inside the handler (no AppState mutation).
pub async fn narrate_incident(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(incident_id): Path<String>,
) -> impl IntoResponse {
    let incident = match state
        .storage
        .get_incident_by_id(&tenant_id, &incident_id)
        .await
    {
        Ok(Some(inc)) => inc,
        Ok(None) => {
            return StatusError::not_found("Incident not found").into_response();
        }
        Err(e) => {
            error!("Failed to fetch incident for narration: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    // Construct narrator from env — hermetic template by default, optional Claude.
    // Never touches AppState; no network call in the default path.
    let narrator = crate::narrate::from_env();
    let narrative = narrator.narrate(&incident);

    info!(incident_id = %incident_id, "RCA narrative generated");

    (
        StatusCode::OK,
        Json(json!({
            "incident_id": incident.id,
            "narrative": narrative,
        })),
    )
        .into_response()
}

/// `GET /v1/incidents/:id/evidence-pack` — per-incident compliance evidence
/// export (SOC-006, #1189). Bundles the incident, the alerts and decisions
/// that contributed to it, the receipts/audit events tied to those
/// decisions, and an RCA narrative into a downloadable ZIP — a focused,
/// single-incident counterpart to the tenant-wide
/// `GET /v1/compliance/evidence-pack` (#1298).
///
/// Linkage: `soc_incidents.source_event_ids` and `soc_alerts.source_event_id`
/// are both populated from the same `AseEvent.event_id`, and
/// `audit_events.id` is that same event_id at emission time — so alerts and
/// decisions are resolved by exact `IN (...)` match, not a heuristic (the
/// same linkage `GET /v1/graph/incident/:incident_id` (#1272) already uses).
///
/// 404 if the incident doesn't exist for this tenant. Tenant-scoped
/// throughout — every query binds `tenant_id` (CWE-284).
pub async fn get_incident_evidence_pack(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(incident_id): Path<String>,
) -> impl IntoResponse {
    let incident = match state
        .storage
        .get_incident_by_id(&tenant_id, &incident_id)
        .await
    {
        Ok(Some(inc)) => inc,
        Ok(None) => {
            return StatusError::not_found("Incident not found").into_response();
        }
        Err(e) => {
            error!("Failed to fetch incident for evidence pack: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    let event_ids: Vec<String> =
        serde_json::from_str(&incident.source_event_ids).unwrap_or_default();

    let alerts = match state
        .storage
        .list_soc_alerts_by_source_event_ids(&tenant_id, &event_ids)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to load alerts for evidence pack: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    // Resolve event_ids -> decision_ids (#1272's established linkage),
    // de-duplicated, preserving the order encountered.
    let mut decision_ids: Vec<String> = Vec::new();
    for event_id in &event_ids {
        if let Ok(Some(decision_id)) = state
            .storage
            .get_audit_event_decision_id(&tenant_id, event_id)
            .await
        {
            if !decision_ids.contains(&decision_id) {
                decision_ids.push(decision_id);
            }
        }
    }

    let receipts = match state
        .storage
        .list_action_receipts_by_decision_ids(&tenant_id, &decision_ids)
        .await
    {
        Ok(map) => map.into_values().collect::<Vec<_>>(),
        Err(e) => {
            error!("Failed to load receipts for evidence pack: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    let audit_events = match state
        .storage
        .list_audit_events_by_decision_ids(&tenant_id, &decision_ids)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to load audit events for evidence pack: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    // Same hermetic-by-default narrator as `narrate_incident` — no network
    // call unless AEGIS_NARRATOR=claude is explicitly configured.
    let narrator = crate::narrate::from_env();
    let rca_narrative = narrator.narrate(&incident);

    let zip_bytes = match build_incident_evidence_pack_zip(
        &incident,
        &alerts,
        &receipts,
        &audit_events,
        &rca_narrative,
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to build incident evidence pack zip: {:?}", e);
            return StatusError::internal("Failed to build evidence pack").into_response();
        }
    };

    info!(incident_id = %incident_id, "incident evidence pack generated");

    let filename = format!(
        "evidence-pack-incident-{incident_id}-{}.zip",
        Utc::now().timestamp()
    );
    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/zip".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        zip_bytes,
    )
        .into_response()
}

/// Serialize one incident's evidence bundle into an in-memory ZIP archive
/// (#1189). Bounded by a single incident's linked data (typically a handful
/// of alerts/decisions), unlike the tenant-wide, potentially unbounded
/// `build_evidence_pack_zip` (#1298) — in-memory construction is the same
/// established pattern, not a new streaming-writer dependency, since the
/// per-incident data volume doesn't justify one.
fn build_incident_evidence_pack_zip(
    incident: &SocIncidentRecord,
    alerts: &[SocAlertRecord],
    receipts: &[ActionReceiptRecord],
    audit_events: &[AuditEventRecord],
    rca_narrative: &str,
) -> Result<Vec<u8>, std::io::Error> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        writer.start_file("incident.json", options)?;
        let incident_bytes = serde_json::to_vec_pretty(incident)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::io::Write::write_all(&mut writer, &incident_bytes)?;

        writer.start_file("alerts.json", options)?;
        let alerts_bytes = serde_json::to_vec_pretty(alerts)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::io::Write::write_all(&mut writer, &alerts_bytes)?;

        writer.start_file("receipts.json", options)?;
        let receipts_bytes = serde_json::to_vec_pretty(receipts)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::io::Write::write_all(&mut writer, &receipts_bytes)?;

        writer.start_file("audit_events.json", options)?;
        let audit_events_bytes = serde_json::to_vec_pretty(audit_events)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::io::Write::write_all(&mut writer, &audit_events_bytes)?;

        writer.start_file("rca_narrative.md", options)?;
        std::io::Write::write_all(&mut writer, rca_narrative.as_bytes())?;

        writer.finish()?;
    }
    Ok(cursor.into_inner())
}

pub async fn ws_events(
    State(state): State<Arc<AppState>>,
    ws: WebSocketUpgrade,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant_id = if let Some(token) = params.get("token").or_else(|| params.get("jwt")) {
        if let Some(tid) = validate_jwt(token) {
            tid
        } else if std::env::var("AEGIS_JWT_REQUIRED")
            .map(|v| v == "true")
            .unwrap_or(false)
        {
            return StatusError::unauthorized("Invalid or expired JWT token").into_response();
        } else if token.starts_with("tenant_") {
            token.to_string()
        } else {
            return StatusError::unauthorized(
                "Invalid token. Query token must start with 'tenant_' when JWT is not required",
            )
            .into_response();
        }
    } else {
        let auth_header = headers.get("Authorization").and_then(|h| h.to_str().ok());
        if let Some(auth) = auth_header {
            if let Some(token) = auth.strip_prefix("Bearer ") {
                if let Some(tid) = validate_jwt(token) {
                    tid
                } else if std::env::var("AEGIS_JWT_REQUIRED")
                    .map(|v| v == "true")
                    .unwrap_or(false)
                {
                    return StatusError::unauthorized("Invalid or expired JWT token")
                        .into_response();
                } else if token.starts_with("tenant_") {
                    token.to_string()
                } else {
                    return StatusError::unauthorized("Invalid token. Bearer token must start with 'tenant_' when JWT is not required")
                        .into_response();
                }
            } else {
                return StatusError::unauthorized("Invalid Authorization format").into_response();
            }
        } else {
            return StatusError::unauthorized(
                "Missing authentication. A valid token or JWT must be provided.",
            )
            .into_response();
        }
    };

    ws.on_upgrade(move |socket| handle_socket(socket, state, tenant_id))
}

pub(crate) async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>, tenant_id: String) {
    let mut rx = state.events.subscribe();

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(ev) => {
                        if ev.tenant_id == tenant_id {
                            if let Ok(msg) = serde_json::to_string(&ev) {
                                if socket.send(Message::Text(msg)).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        // #1305: a slow consumer fell behind the SOC broadcast
                        // channel and the oldest buffered events were dropped
                        // (tokio's broadcast channel evicts the oldest entries
                        // on overflow and advances this receiver's cursor to
                        // the new oldest message — no further action needed
                        // for recovery). Tell the client how many events it
                        // missed so it can resync/alert rather than silently
                        // missing security events.
                        let notice = json!({"type": "events_dropped", "count": n});
                        if let Ok(msg) = serde_json::to_string(&notice) {
                            if socket.send(Message::Text(msg)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => {
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::*;
    use crate::db;
    use crate::events;
    use crate::metrics::SecurityMetrics;
    use crate::models::*;
    use crate::policy::PolicyEngine;
    use crate::routes::test_helpers::*;
    use axum::body::{to_bytes, Bytes};
    use axum::extract::{FromRequestParts, Path, Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::Json;
    use chrono::{DateTime, Duration, Utc};
    use serde_json::{json, Value};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use uuid::Uuid;
    /// list_alerts returns an empty array when no alerts exist, not an error.
    #[tokio::test]
    async fn list_alerts_empty_when_no_alerts() {
        let (state, tenant_id, _agent_token) = setup_state("alerts_empty").await;

        let response = list_alerts(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().is_empty());
    }

    /// list_incidents returns an empty array when no incidents exist.
    #[tokio::test]
    async fn list_incidents_empty_when_no_incidents() {
        let (state, tenant_id, _agent_token) = setup_state("incidents_empty").await;

        let response = list_incidents(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().is_empty());
    }

    /// Inserting a SOC alert directly into the DB then calling list_alerts via the
    /// route returns that alert scoped to the correct tenant.
    #[tokio::test]
    async fn list_alerts_returns_tenant_scoped_alerts() {
        let (state, tenant_id, _agent_token) = setup_state("alerts_tenant_route").await;

        // Directly seed an alert for the tenant.
        let alert = crate::models::SocAlertRecord {
            id: "route_alert_1".to_string(),
            tenant_id: tenant_id.clone(),
            rule: "confused_deputy_block".to_string(),
            severity: "high".to_string(),
            agent_id: "agent_route".to_string(),
            source_event_id: "evt_route_1".to_string(),
            summary: "Route test alert".to_string(),
            created_at: "2026-06-06T10:00:00Z".to_string(),
        };
        state.storage.insert_soc_alert(&alert).await.unwrap();

        let response = list_alerts(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"], "route_alert_1");
        assert_eq!(arr[0]["rule"], "confused_deputy_block");
        assert_eq!(arr[0]["severity"], "high");
        assert_eq!(arr[0]["tenant_id"], tenant_id.as_str());
    }

    /// Inserting a SOC incident directly then calling list_incidents via the route
    /// returns it tenant-scoped.
    #[tokio::test]
    async fn list_incidents_returns_tenant_scoped_incidents() {
        let (state, tenant_id, _agent_token) = setup_state("incidents_tenant_route").await;

        let source_ids = serde_json::to_string(&vec!["evt_1", "evt_2"]).unwrap();
        let incident = crate::models::SocIncidentRecord {
            id: "route_inc_1".to_string(),
            tenant_id: tenant_id.clone(),
            kind: "deny_storm".to_string(),
            severity: "high".to_string(),
            agent_id: "agent_route".to_string(),
            summary: "Route test incident".to_string(),
            source_event_ids: source_ids.clone(),
            opened_at: "2026-06-06T10:00:00Z".to_string(),
            status: "open".to_string(),
            closed_at: None,
        };
        state.storage.insert_soc_incident(&incident).await.unwrap();

        let response = list_incidents(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"], "route_inc_1");
        assert_eq!(arr[0]["kind"], "deny_storm");
        assert_eq!(arr[0]["tenant_id"], tenant_id.as_str());
    }

    /// #1145: `GET /v1/incidents?kind=...` field filtering.
    #[tokio::test]
    async fn list_incidents_route_filters_by_kind() {
        let (state, tenant_id, _agent_token) = setup_state("incidents_kind_filter_route").await;

        insert_test_incident(
            state.storage.get_pool(),
            &tenant_id,
            "inc_deny_storm",
            "deny_storm",
        )
        .await;
        insert_test_incident(
            state.storage.get_pool(),
            &tenant_id,
            "inc_policy_drift",
            "policy_drift",
        )
        .await;

        let response = list_incidents(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(Some("kind=policy_drift".to_string())),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"], "inc_policy_drift");
    }

    /// #1146: `GET /v1/alerts?watch=true` returns an SSE stream that pushes
    /// newly created alerts (and only those created *after* the watch
    /// connects — no historical backfill).
    #[tokio::test]
    async fn list_alerts_watch_mode_streams_new_alerts_as_sse() {
        use futures_util::StreamExt;

        let (state, tenant_id, _agent_token) = setup_state("alerts_watch_sse").await;

        let response = list_alerts(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(Some("watch=true".to_string())),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "text/event-stream"
        );

        let mut body_stream = response.into_body().into_data_stream();

        // Give the watch task a moment to establish its starting rowid
        // before inserting the alert it should pick up.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let alert = SocAlertRecord {
            id: "watch_alert_1".to_string(),
            tenant_id: tenant_id.clone(),
            rule: "test_rule".to_string(),
            severity: "high".to_string(),
            agent_id: "agent_watch".to_string(),
            source_event_id: "evt_watch_1".to_string(),
            summary: "Watch test alert".to_string(),
            created_at: Utc::now().to_rfc3339(),
        };
        state.storage.insert_soc_alert(&alert).await.unwrap();

        let chunk = tokio::time::timeout(std::time::Duration::from_secs(5), body_stream.next())
            .await
            .expect("SSE event must arrive within 5s")
            .expect("stream must not end")
            .expect("chunk must not be an error");
        let text = String::from_utf8(chunk.to_vec()).unwrap();
        assert!(text.contains("event:alert") || text.contains("event: alert"));
        assert!(text.contains("watch_alert_1"));
    }

    /// #1146: `GET /v1/incidents?watch=true` mirrors the alerts watch test
    /// above, including respecting the existing `kind` filter (#1145).
    #[tokio::test]
    async fn list_incidents_watch_mode_streams_new_incidents_as_sse() {
        use futures_util::StreamExt;

        let (state, tenant_id, _agent_token) = setup_state("incidents_watch_sse").await;

        let response = list_incidents(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(Some("watch=true&kind=policy_drift".to_string())),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "text/event-stream"
        );

        let mut body_stream = response.into_body().into_data_stream();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // Non-matching kind first — must not be streamed.
        insert_test_incident(
            state.storage.get_pool(),
            &tenant_id,
            "inc_deny_storm",
            "deny_storm",
        )
        .await;
        // Matching kind — must be streamed.
        insert_test_incident(
            state.storage.get_pool(),
            &tenant_id,
            "inc_policy_drift",
            "policy_drift",
        )
        .await;

        let chunk = tokio::time::timeout(std::time::Duration::from_secs(5), body_stream.next())
            .await
            .expect("SSE event must arrive within 5s")
            .expect("stream must not end")
            .expect("chunk must not be an error");
        let text = String::from_utf8(chunk.to_vec()).unwrap();
        assert!(text.contains("event:incident") || text.contains("event: incident"));
        assert!(text.contains("inc_policy_drift"));
        assert!(!text.contains("inc_deny_storm"));
    }

    /// Helper: insert a bare-minimum incident row for a tenant (no agent required).
    async fn insert_test_incident(
        pool: &db::DbPool,
        tenant_id: &str,
        incident_id: &str,
        kind: &str,
    ) {
        let record = SocIncidentRecord {
            id: incident_id.to_string(),
            tenant_id: tenant_id.to_string(),
            kind: kind.to_string(),
            severity: "high".to_string(),
            agent_id: "agent-test".to_string(),
            summary: "Test incident for narration".to_string(),
            source_event_ids: serde_json::json!(["evt_a", "evt_b"]).to_string(),
            opened_at: "2026-06-06T12:00:00Z".to_string(),
            status: "open".to_string(),
            closed_at: None,
        };
        db::insert_soc_incident(pool, &record).await.unwrap();
    }

    #[tokio::test]
    async fn narrate_incident_returns_narrative_for_own_incident() {
        let (state, tenant_id, _agent_token) = setup_state("narrate_own").await;

        insert_test_incident(
            state.storage.get_pool(),
            &tenant_id,
            "inc_narrate_1",
            "deny_storm",
        )
        .await;

        // Call the handler directly — same pattern used by all other route tests.
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", tenant_id).parse().unwrap(),
        );

        let response = narrate_incident(
            State(state),
            TenantId(tenant_id.clone()),
            Path("inc_narrate_1".to_string()),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(json["incident_id"], "inc_narrate_1");
        let narrative = json["narrative"].as_str().unwrap();
        // Default template must include the incident kind.
        assert!(
            narrative.contains("deny_storm"),
            "narrative must contain kind"
        );
    }

    #[tokio::test]
    async fn narrate_incident_returns_404_for_other_tenants_incident() {
        let (state, tenant_id, _agent_token) = setup_state("narrate_isolation").await;

        // Register a second tenant and insert the incident under it.
        let other_tenant = "tenant_other_narrator";
        register_tenant_helper(state.storage.as_ref(), other_tenant, "Other", "developer").await;
        insert_test_incident(
            state.storage.get_pool(),
            other_tenant,
            "inc_other",
            "deny_storm",
        )
        .await;

        // Authenticate as our tenant and try to fetch the other tenant's incident.
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", tenant_id).parse().unwrap(),
        );

        let response = narrate_incident(
            State(state),
            TenantId(tenant_id.clone()),
            Path("inc_other".to_string()),
        )
        .await
        .into_response();

        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "must not expose another tenant's incident"
        );
    }

    // ── get_incident_evidence_pack route tests (#1189) ─────────────────────────

    fn zip_entry_names(bytes: &[u8]) -> std::collections::HashSet<String> {
        let reader = std::io::Cursor::new(bytes);
        let archive = zip::ZipArchive::new(reader).unwrap();
        archive.file_names().map(|s| s.to_string()).collect()
    }

    fn zip_entry_string(bytes: &[u8], name: &str) -> String {
        let reader = std::io::Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(reader).unwrap();
        let mut file = archive.by_name(name).unwrap();
        let mut out = String::new();
        std::io::Read::read_to_string(&mut file, &mut out).unwrap();
        out
    }

    /// Seeds a full incident evidence chain — agent, decision, audit event,
    /// alert (linked via `source_event_id`), receipt (linked via
    /// `decision_id`), and the incident itself (linked via
    /// `source_event_ids`) — mirroring the linkage `get_graph_for_incident`
    /// (#1272) already relies on.
    async fn seed_incident_evidence_chain(
        state: &Arc<AppState>,
        tenant_id: &str,
        incident_id: &str,
    ) {
        let agent_id = format!("{incident_id}_agent");
        let agent = AgentRecord {
            id: agent_id.clone(),
            tenant_id: tenant_id.to_string(),
            agent_key: format!("{agent_id}-key"),
            agent_token: format!("{agent_id}-token"),
            name: "Evidence Pack Agent".to_string(),
            owner_team: None,
            owner_email: None,
            environment: "production".to_string(),
            framework: None,
            model_provider: None,
            model_name: None,
            purpose: None,
            risk_tier: "medium".to_string(),
            status: "active".to_string(),
            last_seen_at: None,
            frozen_reason: None,
            force_approval: false,
            quarantined_at: None,
            signing_key: None,
            allowed_environments: None,
            mtls_cn: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        state.storage.insert_agent(&agent).await.unwrap();

        let decision_id = format!("{incident_id}_decision");
        let decision = DecisionRecord {
            id: decision_id.clone(),
            tenant_id: tenant_id.to_string(),
            agent_id: agent_id.clone(),
            user_id: None,
            run_id: None,
            trace_id: None,
            skill: "github".to_string(),
            action: "merge_pull_request".to_string(),
            resource: Some("payments#1".to_string()),
            input_json: "{}".to_string(),
            decision: "deny".to_string(),
            risk_score: Some(80),
            reason: Some("test reason".to_string()),
            matched_policy_ids: None,
            request_id: None,
            latency_ms: Some(5),
            composite_risk_score: Some(50),
            root_trust_level: None,
            parent_run_id: None,
            created_at: Utc::now(),
        };
        state.storage.insert_decision(&decision).await.unwrap();

        let event_id = format!("{incident_id}_event");
        let audit_event = AuditEventRecord {
            id: event_id.clone(),
            tenant_id: tenant_id.to_string(),
            event_type: "decision".to_string(),
            agent_id: Some(agent_id.clone()),
            user_id: None,
            run_id: None,
            trace_id: None,
            span_id: None,
            skill: Some("github".to_string()),
            action: Some("merge_pull_request".to_string()),
            resource: Some("payments#1".to_string()),
            event_json: "{}".to_string(),
            input_hash: None,
            output_hash: None,
            decision_id: Some(decision_id.clone()),
            approval_id: None,
            created_at: Utc::now(),
        };
        state
            .storage
            .insert_audit_event(&audit_event)
            .await
            .unwrap();

        let alert = SocAlertRecord {
            id: format!("{incident_id}_alert"),
            tenant_id: tenant_id.to_string(),
            rule: "confused_deputy_block".to_string(),
            severity: "high".to_string(),
            agent_id: agent_id.clone(),
            source_event_id: event_id.clone(),
            summary: "Evidence pack test alert".to_string(),
            created_at: Utc::now().to_rfc3339(),
        };
        state.storage.insert_soc_alert(&alert).await.unwrap();

        let prev_hash = state
            .storage
            .get_latest_action_receipt(tenant_id)
            .await
            .unwrap()
            .map(|r| r.receipt_hash)
            .unwrap_or_default();
        let mut receipt = ActionReceiptRecord {
            id: format!("{incident_id}_receipt"),
            tenant_id: tenant_id.to_string(),
            decision_id: Some(decision_id.clone()),
            ts: Utc::now().to_rfc3339(),
            agent_id: Some(agent_id.clone()),
            user_id: None,
            run_id: None,
            trace_id: None,
            tool: Some("github".to_string()),
            action: Some("merge_pull_request".to_string()),
            resource: Some("payments#1".to_string()),
            source_trust: "trusted_internal_signed".to_string(),
            decision: "deny".to_string(),
            approver: None,
            action_hash: Some("aaaa".to_string()),
            prev_receipt_hash: prev_hash,
            receipt_hash: String::new(),
            canon_version: "aegis-jcs-1".to_string(),
            signature: None,
            signer_public_key: None,
            signer_key_id: None,
            created_at: Utc::now(),
        };
        receipt.receipt_hash = db::compute_receipt_hash(&receipt);
        state.storage.insert_action_receipt(&receipt).await.unwrap();

        let incident = SocIncidentRecord {
            id: incident_id.to_string(),
            tenant_id: tenant_id.to_string(),
            kind: "deny_storm".to_string(),
            severity: "high".to_string(),
            agent_id: agent_id.clone(),
            summary: "Evidence pack test incident".to_string(),
            source_event_ids: serde_json::to_string(&vec![event_id.clone()]).unwrap(),
            opened_at: "2026-06-06T10:00:00Z".to_string(),
            status: "open".to_string(),
            closed_at: None,
        };
        state.storage.insert_soc_incident(&incident).await.unwrap();
    }

    /// SOC-006 (#1189): `GET /v1/incidents/:id/evidence-pack` bundles the
    /// incident, its linked alerts/receipts/audit events, and an RCA
    /// narrative into a downloadable ZIP with all five expected entries.
    #[tokio::test]
    async fn get_incident_evidence_pack_returns_zip_with_expected_entries() {
        let (state, tenant_id, _agent_token) = setup_state("evidence_pack_own").await;
        seed_incident_evidence_chain(&state, &tenant_id, "inc_evidence_1").await;

        let response = get_incident_evidence_pack(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("inc_evidence_1".to_string()),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/zip"
        );

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let entries = zip_entry_names(&body);
        for expected in [
            "incident.json",
            "alerts.json",
            "receipts.json",
            "audit_events.json",
            "rca_narrative.md",
        ] {
            assert!(
                entries.contains(expected),
                "missing zip entry: {expected} (have {entries:?})"
            );
        }

        let incident: serde_json::Value =
            serde_json::from_str(&zip_entry_string(&body, "incident.json")).unwrap();
        assert_eq!(incident["id"], "inc_evidence_1");

        let alerts: serde_json::Value =
            serde_json::from_str(&zip_entry_string(&body, "alerts.json")).unwrap();
        assert_eq!(alerts.as_array().unwrap().len(), 1);
        assert_eq!(alerts[0]["id"], "inc_evidence_1_alert");

        let receipts: serde_json::Value =
            serde_json::from_str(&zip_entry_string(&body, "receipts.json")).unwrap();
        assert_eq!(receipts.as_array().unwrap().len(), 1);
        assert_eq!(receipts[0]["id"], "inc_evidence_1_receipt");

        let audit_events: serde_json::Value =
            serde_json::from_str(&zip_entry_string(&body, "audit_events.json")).unwrap();
        assert_eq!(audit_events.as_array().unwrap().len(), 1);
        assert_eq!(audit_events[0]["id"], "inc_evidence_1_event");

        let narrative = zip_entry_string(&body, "rca_narrative.md");
        assert!(narrative.contains("deny_storm"));
    }

    /// 404 for an incident that doesn't exist (or belongs to another
    /// tenant) — never leaks cross-tenant evidence.
    #[tokio::test]
    async fn get_incident_evidence_pack_returns_404_for_unknown_or_cross_tenant_incident() {
        let (state, tenant_id, _agent_token) = setup_state("evidence_pack_404").await;

        let other_tenant = "tenant_other_evidence_pack";
        register_tenant_helper(state.storage.as_ref(), other_tenant, "Other", "developer").await;
        seed_incident_evidence_chain(&state, other_tenant, "inc_other_evidence").await;

        let missing = get_incident_evidence_pack(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("inc_does_not_exist".to_string()),
        )
        .await
        .into_response();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        let cross_tenant = get_incident_evidence_pack(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("inc_other_evidence".to_string()),
        )
        .await
        .into_response();
        assert_eq!(
            cross_tenant.status(),
            StatusCode::NOT_FOUND,
            "must not expose another tenant's incident evidence"
        );
    }

    // ── close_incident route tests ────────────────────────────────────────────

    /// `POST /v1/incidents/:id/close` returns 200 with `status: "closed"` and a
    /// non-null `closed_at` for a persisted open incident owned by the tenant.
    #[tokio::test]
    async fn close_incident_returns_closed_for_own_incident() {
        let (state, tenant_id, _) = setup_state("close_own").await;
        insert_test_incident(
            state.storage.get_pool(),
            &tenant_id,
            "inc_close_route_1",
            "deny_storm",
        )
        .await;

        let (status, json) = do_close(state, &tenant_id, "inc_close_route_1").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "closed");
        assert_eq!(json["incident_id"], "inc_close_route_1");
        assert!(
            !json["closed_at"].is_null(),
            "closed_at must be set after close"
        );
        assert_eq!(json["already_closed"], false);
    }

    /// `POST /v1/incidents/:id/close` returns 404 when the incident id belongs
    /// to a different tenant — tenant-isolation (CWE-284).
    #[tokio::test]
    async fn close_incident_returns_404_for_other_tenants_incident() {
        let (state, tenant_id, _) = setup_state("close_iso").await;

        let other_tenant = "tenant_other_close_iso";
        register_tenant_helper(state.storage.as_ref(), other_tenant, "Other", "developer").await;
        insert_test_incident(
            state.storage.get_pool(),
            other_tenant,
            "inc_other_close",
            "deny_storm",
        )
        .await;

        let (status, json) = do_close(state, &tenant_id, "inc_other_close").await;

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "must not expose another tenant's incident"
        );
        assert!(json["message"].as_str().is_some());
    }

    /// A second `POST /v1/incidents/:id/close` is idempotent — returns 200 with
    /// `already_closed: true` and the original `closed_at` unchanged.
    #[tokio::test]
    async fn close_incident_is_idempotent() {
        let (state, tenant_id, _) = setup_state("close_idempotent_route").await;
        insert_test_incident(
            state.storage.get_pool(),
            &tenant_id,
            "inc_idem_route",
            "replay_attempt",
        )
        .await;

        let (s1, j1) = do_close(state.clone(), &tenant_id, "inc_idem_route").await;
        assert_eq!(s1, StatusCode::OK);
        assert_eq!(j1["already_closed"], false);
        let first_closed_at = j1["closed_at"].as_str().unwrap().to_string();

        let (s2, j2) = do_close(state, &tenant_id, "inc_idem_route").await;
        assert_eq!(s2, StatusCode::OK, "second close must still be 200");
        assert_eq!(j2["already_closed"], true);
        assert_eq!(
            j2["closed_at"].as_str().unwrap(),
            first_closed_at,
            "closed_at must not change on second close"
        );
    }

    /// #1158 (SOC-005): closing an incident records a mean-time-to-resolve
    /// sample (the real gap between `opened_at` and `closed_at`), not a
    /// derived/zero value.
    #[tokio::test]
    async fn close_incident_records_mttr_sample() {
        let (state, tenant_id, _) = setup_state("close_mttr").await;
        insert_test_incident(
            state.storage.get_pool(),
            &tenant_id,
            "inc_mttr_1",
            "deny_storm",
        )
        .await;

        assert_eq!(state.metrics.soc_mttr.average_seconds(), 0.0);

        let (status, _) = do_close(state.clone(), &tenant_id, "inc_mttr_1").await;
        assert_eq!(status, StatusCode::OK);

        // insert_test_incident hardcodes opened_at far in the past, so the
        // resolution time (now - opened_at) must be a large positive value.
        assert!(state.metrics.soc_mttr.average_seconds() > 0.0);
    }

    // ── SOC query layer: get_incident + soc_summary route tests ──────────────

    /// GET /v1/incidents/:id returns 200 with the incident body for the owning tenant.
    #[tokio::test]
    async fn get_incident_returns_200_for_own_incident() {
        let (state, tenant_id, _) = setup_state("get_inc_own").await;
        insert_test_incident(
            state.storage.get_pool(),
            &tenant_id,
            "inc_get_own",
            "deny_storm",
        )
        .await;

        let (status, json) = do_get_incident(state, &tenant_id, "inc_get_own").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["id"], "inc_get_own");
        assert_eq!(json["kind"], "deny_storm");
        assert_eq!(json["tenant_id"], tenant_id.as_str());
    }

    /// GET /v1/incidents/:id returns 404 for an unknown id.
    #[tokio::test]
    async fn get_incident_returns_404_for_unknown_id() {
        let (state, tenant_id, _) = setup_state("get_inc_missing").await;

        let (status, json) = do_get_incident(state, &tenant_id, "does_not_exist").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(json["message"].as_str().is_some());
    }

    /// GET /v1/incidents/:id returns 404 when the incident belongs to a different
    /// tenant — cross-tenant isolation (CWE-284).
    #[tokio::test]
    async fn get_incident_returns_404_cross_tenant() {
        let (state, tenant_id_a, _) = setup_state("get_inc_cross_tenant").await;
        // Register a second tenant and insert an incident under it.
        let tenant_id_b = format!("tenant_b_{}", uuid::Uuid::new_v4().simple());
        register_tenant_helper(
            state.storage.as_ref(),
            &tenant_id_b,
            "Tenant B",
            "developer",
        )
        .await;
        db::insert_soc_incident(
            state.storage.get_pool(),
            &SocIncidentRecord {
                id: "inc_other_tenant".to_string(),
                tenant_id: tenant_id_b.clone(),
                kind: "deny_storm".to_string(),
                severity: "high".to_string(),
                agent_id: "agent-b".to_string(),
                summary: "B's incident".to_string(),
                source_event_ids: serde_json::json!(["e1"]).to_string(),
                opened_at: "2026-06-06T12:00:00Z".to_string(),
                status: "open".to_string(),
                closed_at: None,
            },
        )
        .await
        .unwrap();

        // tenant_a must get 404, not tenant_b's data.
        let (status, _) = do_get_incident(state, &tenant_id_a, "inc_other_tenant").await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "cross-tenant incident must return 404"
        );
    }

    /// GET /v1/alerts?severity=high only returns high-severity alerts (route-level).
    #[tokio::test]
    async fn list_alerts_severity_filter_via_route() {
        let (state, tenant_id, _) = setup_state("alerts_sev_route").await;

        // Insert 1 high + 1 low alert.
        db::insert_soc_alert(
            state.storage.get_pool(),
            &SocAlertRecord {
                id: "ra_high".to_string(),
                tenant_id: tenant_id.clone(),
                rule: "r1".to_string(),
                severity: "high".to_string(),
                agent_id: "ag1".to_string(),
                source_event_id: "evt1".to_string(),
                summary: "High alert".to_string(),
                created_at: "2026-06-06T10:00:00Z".to_string(),
            },
        )
        .await
        .unwrap();
        db::insert_soc_alert(
            state.storage.get_pool(),
            &SocAlertRecord {
                id: "ra_low".to_string(),
                tenant_id: tenant_id.clone(),
                rule: "r2".to_string(),
                severity: "low".to_string(),
                agent_id: "ag1".to_string(),
                source_event_id: "evt2".to_string(),
                summary: "Low alert".to_string(),
                created_at: "2026-06-06T10:01:00Z".to_string(),
            },
        )
        .await
        .unwrap();

        let response = list_alerts(
            State(state),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(Some("severity=high".to_string())),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let arr: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = arr.as_array().unwrap();
        assert_eq!(arr.len(), 1, "only 1 high-severity alert");
        assert_eq!(arr[0]["id"], "ra_high");
        assert_eq!(arr[0]["severity"], "high");
    }

    /// GET /v1/soc/summary returns correct aggregate counts for the tenant.
    #[tokio::test]
    async fn soc_summary_returns_correct_counts() {
        let (state, tenant_id, _) = setup_state("soc_summary_route").await;

        // Seed: 2 alerts (1 high, 1 medium), 2 incidents (1 open, 1 closed).
        db::insert_soc_alert(
            state.storage.get_pool(),
            &SocAlertRecord {
                id: "ss_a1".to_string(),
                tenant_id: tenant_id.clone(),
                rule: "r1".to_string(),
                severity: "high".to_string(),
                agent_id: "ag1".to_string(),
                source_event_id: "evt1".to_string(),
                summary: "High".to_string(),
                created_at: "2026-06-06T10:00:00Z".to_string(),
            },
        )
        .await
        .unwrap();
        db::insert_soc_alert(
            state.storage.get_pool(),
            &SocAlertRecord {
                id: "ss_a2".to_string(),
                tenant_id: tenant_id.clone(),
                rule: "r2".to_string(),
                severity: "medium".to_string(),
                agent_id: "ag1".to_string(),
                source_event_id: "evt2".to_string(),
                summary: "Medium".to_string(),
                created_at: "2026-06-06T10:01:00Z".to_string(),
            },
        )
        .await
        .unwrap();
        insert_test_incident(state.storage.get_pool(), &tenant_id, "ss_i1", "deny_storm").await;
        insert_test_incident(state.storage.get_pool(), &tenant_id, "ss_i2", "exfil").await;
        state
            .storage
            .close_soc_incident(&tenant_id, "ss_i2")
            .await
            .unwrap();

        let response = soc_summary(State(state), TenantId(tenant_id.clone()))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["alerts_total"], 2);
        assert_eq!(json["alerts_high"], 1);
        assert_eq!(json["incidents_total"], 2);
        assert_eq!(json["incidents_open"], 1);
        assert_eq!(json["incidents_closed"], 1);
    }

    /// GET /v1/soc/summary for a tenant with no data returns all-zero counts.
    #[tokio::test]
    async fn soc_summary_returns_zeros_when_empty() {
        let (state, tenant_id, _) = setup_state("soc_summary_empty").await;

        let response = soc_summary(State(state), TenantId(tenant_id.clone()))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["alerts_total"], 0);
        assert_eq!(json["alerts_high"], 0);
        assert_eq!(json["incidents_total"], 0);
        assert_eq!(json["incidents_open"], 0);
        assert_eq!(json["incidents_closed"], 0);
    }

    // --- MCP tool-manifest drift (SOC `mcp_manifest_drift`) ---

    /// TASK-0088 (#934): CRUD lifecycle for tenant-managed detection rules.
    /// First step toward SOC-003 (#1186)'s YAML-driven detection DSL.
    #[tokio::test]
    async fn test_detection_rule_crud_route() {
        let (state, tenant_id, _) = setup_state("detection_rule_crud").await;

        // 1. List (initially empty)
        let response = list_detection_rules(State(state.clone()), TenantId(tenant_id.clone()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().is_empty());

        // 2. Upsert (create)
        let payload = UpsertDetectionRuleRequest {
            rule_key: "confused_deputy_block".to_string(),
            name: "Confused deputy block".to_string(),
            severity: "high".to_string(),
            condition: "decision == 'deny' && reason contains 'confused_deputy'".to_string(),
            summary_template: "Confused-deputy action blocked for {{agent_id}}".to_string(),
            enabled: true,
        };
        let response_create = upsert_detection_rule(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload),
        )
        .await
        .into_response();
        assert_eq!(response_create.status(), StatusCode::CREATED);
        let body_create = to_bytes(response_create.into_body(), usize::MAX)
            .await
            .unwrap();
        let record: DetectionRuleRecord = serde_json::from_slice(&body_create).unwrap();
        assert_eq!(record.rule_key, "confused_deputy_block");
        assert_eq!(record.severity, "high");
        assert!(record.enabled);

        // 3. List (should contain 1 rule)
        let response_list = list_detection_rules(State(state.clone()), TenantId(tenant_id.clone()))
            .await
            .into_response();
        assert_eq!(response_list.status(), StatusCode::OK);
        let body_list = to_bytes(response_list.into_body(), usize::MAX)
            .await
            .unwrap();
        let rules: Vec<DetectionRuleRecord> = serde_json::from_slice(&body_list).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, record.id);

        // 4. Upsert again with same rule_key (update severity + disable)
        let payload_update = UpsertDetectionRuleRequest {
            rule_key: "confused_deputy_block".to_string(),
            name: "Confused deputy block".to_string(),
            severity: "critical".to_string(),
            condition: "decision == 'deny' && reason contains 'confused_deputy'".to_string(),
            summary_template: "Confused-deputy action blocked for {{agent_id}}".to_string(),
            enabled: false,
        };
        let response_update = upsert_detection_rule(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload_update),
        )
        .await
        .into_response();
        assert_eq!(response_update.status(), StatusCode::CREATED);
        let body_update = to_bytes(response_update.into_body(), usize::MAX)
            .await
            .unwrap();
        let record_update: DetectionRuleRecord = serde_json::from_slice(&body_update).unwrap();
        assert_eq!(record_update.id, record.id);
        assert_eq!(record_update.severity, "critical");
        assert!(!record_update.enabled);

        // List should still contain exactly 1 rule (upsert, not duplicate)
        let response_list2 =
            list_detection_rules(State(state.clone()), TenantId(tenant_id.clone()))
                .await
                .into_response();
        let body_list2 = to_bytes(response_list2.into_body(), usize::MAX)
            .await
            .unwrap();
        let rules2: Vec<DetectionRuleRecord> = serde_json::from_slice(&body_list2).unwrap();
        assert_eq!(rules2.len(), 1);

        // 5. Delete
        let response_delete = delete_detection_rule(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(record.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_delete.status(), StatusCode::OK);

        // 6. Delete again (should return 404)
        let response_delete_404 = delete_detection_rule(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(record.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_delete_404.status(), StatusCode::NOT_FOUND);

        // 7. List (empty again)
        let response_list3 = list_detection_rules(State(state), TenantId(tenant_id))
            .await
            .into_response();
        let body_list3 = to_bytes(response_list3.into_body(), usize::MAX)
            .await
            .unwrap();
        let rules3: Vec<DetectionRuleRecord> = serde_json::from_slice(&body_list3).unwrap();
        assert!(rules3.is_empty());
    }

    /// #1282: `GET /v1/soc/rules` returns the embedded default rule set when a
    /// tenant has no custom rules, each tagged `source: "default"`.
    #[tokio::test]
    async fn test_soc_rules_lists_defaults_with_no_custom_rules() {
        let (state, tenant_id, _) = setup_state("soc_rules_defaults").await;

        let response = get_soc_rules(State(state), TenantId(tenant_id))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rules: Vec<Value> = serde_json::from_slice(&body).unwrap();

        assert_eq!(rules.len(), crate::rule_dsl::default_rules().len());
        assert!(rules.iter().all(|r| r["source"] == "default"));
        assert!(rules
            .iter()
            .any(|r| r["rule_key"] == "confused_deputy_block"));
    }

    /// #1282: `POST /v1/soc/rules` validates the YAML condition DSL — a rule
    /// with an unknown condition key is rejected with `400`, never `500`, and
    /// is never persisted.
    #[tokio::test]
    async fn test_create_soc_rule_rejects_invalid_condition() {
        let (state, tenant_id, _) = setup_state("soc_rules_invalid").await;

        let payload = UpsertDetectionRuleRequest {
            rule_key: "bad_rule".to_string(),
            name: "bad_rule".to_string(),
            severity: "high".to_string(),
            condition: "not_a_real_field: true\n".to_string(),
            summary_template: "should not be created".to_string(),
            enabled: true,
        };
        let response = create_soc_rule(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response_list = list_detection_rules(State(state), TenantId(tenant_id))
            .await
            .into_response();
        let body_list = to_bytes(response_list.into_body(), usize::MAX)
            .await
            .unwrap();
        let rules: Vec<DetectionRuleRecord> = serde_json::from_slice(&body_list).unwrap();
        assert!(rules.is_empty());
    }

    /// #1282: `POST /v1/soc/rules` accepts a valid custom rule, and
    /// `GET /v1/soc/rules` then returns it alongside the defaults, tagged
    /// `source: "custom"`. Tenant isolation: a second tenant's effective
    /// rules contain only the defaults.
    #[tokio::test]
    async fn test_create_soc_rule_then_appears_in_effective_rules() {
        let (state, tenant_id, _) = setup_state("soc_rules_custom").await;

        let payload = UpsertDetectionRuleRequest {
            rule_key: "custom_github_force_push".to_string(),
            name: "custom_github_force_push".to_string(),
            severity: "medium".to_string(),
            condition: "tool: github\naction: force_push\n".to_string(),
            summary_template: "Custom rule: {tool}.{action} ({decision})".to_string(),
            enabled: true,
        };
        let response = create_soc_rule(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);

        let response_rules = get_soc_rules(State(state), TenantId(tenant_id))
            .await
            .into_response();
        assert_eq!(response_rules.status(), StatusCode::OK);
        let body = to_bytes(response_rules.into_body(), usize::MAX)
            .await
            .unwrap();
        let rules: Vec<Value> = serde_json::from_slice(&body).unwrap();

        let custom = rules
            .iter()
            .find(|r| r["rule_key"] == "custom_github_force_push")
            .expect("custom rule should be present");
        assert_eq!(custom["source"], "custom");
        assert_eq!(rules.len(), crate::rule_dsl::default_rules().len() + 1);
    }

    /// #1282: `POST /v1/soc/rules/reload` is a documented no-op `200` (rules
    /// are always loaded fresh per event — there is no cache to invalidate).
    #[tokio::test]
    async fn test_reload_soc_rules_is_a_noop_confirmation() {
        let (_state, tenant_id, _) = setup_state("soc_rules_reload").await;

        let response = reload_soc_rules(TenantId(tenant_id)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// #1169: a real WebSocket client connects to `/v1/ws/events`, receives
    /// `authorize_decision` events emitted for its own tenant within 100ms,
    /// and never receives events emitted for a different tenant.
    #[tokio::test]
    async fn ws_events_stream_is_tenant_scoped() {
        use axum::routing::get;
        use axum::Router;
        use futures_util::StreamExt;
        use tokio_tungstenite::connect_async;
        use tokio_tungstenite::tungstenite::Message as WsMessage;

        let (state, _tenant_id, _agent_token) = setup_state("ws_events_stream").await;

        let app = Router::new()
            .route("/v1/ws/events", get(ws_events))
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("ws://{addr}/v1/ws/events?token=tenant_a");
        let (mut ws_stream, _resp) = connect_async(url).await.unwrap();

        // Give the server a moment to register the subscription before emitting.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        fn make_event(tenant_id: &str, event_id: &str) -> AseEvent {
            AseEvent {
                event_id: event_id.to_string(),
                occurred_at: Utc::now().to_rfc3339(),
                tenant_id: tenant_id.to_string(),
                kind: "authorize_decision".to_string(),
                agent_id: "agent_ws_test".to_string(),
                decision: "allow".to_string(),
                tool: "github".to_string(),
                action: "read_file".to_string(),
                resource: None,
                risk_score: 10,
                reason: "policy_allow".to_string(),
                run_id: None,
                trace_id: None,
                matched_policies: vec![],
                redacted_fields: vec![],
                schema_version: 1,
                evidence: None,
            }
        }

        // Event for a different tenant must NOT be delivered to tenant_a's socket.
        state
            .events
            .emit(make_event("tenant_b", "evt_other_tenant"));
        // Event for tenant_a must be delivered within 100ms.
        state.events.emit(make_event("tenant_a", "evt_own_tenant"));

        let msg = tokio::time::timeout(std::time::Duration::from_millis(100), ws_stream.next())
            .await
            .expect("event must arrive within 100ms")
            .expect("stream must not close")
            .expect("message must not be an error");

        let text = match msg {
            WsMessage::Text(t) => t,
            other => panic!("expected text message, got {other:?}"),
        };
        let received: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(received["event_id"], "evt_own_tenant");
        assert_eq!(received["tenant_id"], "tenant_a");

        let _ = ws_stream.close(None).await;
    }

    /// #1305: a slow WebSocket consumer that falls behind the SOC broadcast
    /// channel receives an `events_dropped` notification (with a `count` of
    /// how many events it missed) instead of silently losing events, and the
    /// connection remains healthy afterward (subsequent events still arrive).
    #[tokio::test]
    async fn ws_events_lagged_consumer_gets_drop_notice() {
        use axum::routing::get;
        use axum::Router;
        use futures_util::StreamExt;
        use tokio_tungstenite::connect_async;
        use tokio_tungstenite::tungstenite::Message as WsMessage;

        // Tiny capacity so a handful of events emitted back-to-back overflow
        // the broadcast channel before the WS handler's `rx.recv()` drains
        // them, making the lag deterministic without 1000+ events.
        const CAPACITY: usize = 2;
        let (state, _tenant_id, _agent_token, events_rx) =
            setup_state_with_events_capacity("ws_events_lagged", CAPACITY).await;
        tokio::spawn(events::drain(
            events_rx,
            state.storage.get_pool().clone(),
            state.metrics.clone(),
            None,
        ));

        let app = Router::new()
            .route("/v1/ws/events", get(ws_events))
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("ws://{addr}/v1/ws/events?token=tenant_a");
        let (mut ws_stream, _resp) = connect_async(url).await.unwrap();

        fn make_event(tenant_id: &str, event_id: &str) -> AseEvent {
            AseEvent {
                event_id: event_id.to_string(),
                occurred_at: Utc::now().to_rfc3339(),
                tenant_id: tenant_id.to_string(),
                kind: "authorize_decision".to_string(),
                agent_id: "agent_ws_test".to_string(),
                decision: "allow".to_string(),
                tool: "github".to_string(),
                action: "read_file".to_string(),
                resource: None,
                risk_score: 10,
                reason: "policy_allow".to_string(),
                run_id: None,
                trace_id: None,
                matched_policies: vec![],
                redacted_fields: vec![],
                schema_version: 1,
                evidence: None,
            }
        }

        // Give the server a moment to register the subscription before
        // emitting, then flood the broadcast channel with more events than
        // its capacity *before* the handler's select loop gets a chance to
        // drain them, forcing a `RecvError::Lagged`.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        for i in 0..(CAPACITY * 5) {
            state
                .events
                .emit(make_event("tenant_a", &format!("evt_{i}")));
        }

        // Drain messages until we see the `events_dropped` notice (or time
        // out). Subsequent events for tenant_a should still arrive normally
        // afterward, proving the connection survived the lag.
        let mut saw_drop_notice = false;
        let mut saw_event_after_drop = false;
        for _ in 0..(CAPACITY * 5 + 2) {
            let msg =
                tokio::time::timeout(std::time::Duration::from_millis(200), ws_stream.next()).await;
            let msg = match msg {
                Ok(Some(Ok(m))) => m,
                _ => break,
            };
            let text = match msg {
                WsMessage::Text(t) => t,
                other => panic!("expected text message, got {other:?}"),
            };
            let received: serde_json::Value = serde_json::from_str(&text).unwrap();
            if received["type"] == "events_dropped" {
                saw_drop_notice = true;
                assert!(
                    received["count"].as_u64().unwrap() > 0,
                    "events_dropped count must be > 0"
                );
            } else if saw_drop_notice && received["tenant_id"] == "tenant_a" {
                saw_event_after_drop = true;
            }
        }

        assert!(
            saw_drop_notice,
            "slow consumer must receive an events_dropped notification"
        );
        assert!(
            saw_event_after_drop,
            "connection must remain healthy and deliver events after the drop notice"
        );

        let _ = ws_stream.close(None).await;
    }

    #[tokio::test]
    async fn test_semantic_search_not_implemented() {
        let (state, tenant_id, _agent_token) = setup_state("semantic_search_ni").await;

        let response = semantic_search(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::Query(SemanticSearchParams {
                query: "malicious activity".to_string(),
                limit: None,
            }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["message"],
            "Qdrant semantic search is not configured on this gateway"
        );
    }

    #[tokio::test]
    async fn test_semantic_search_bad_request_empty_query() {
        let (state, tenant_id, _agent_token) = setup_state("semantic_search_br").await;

        let response = semantic_search(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::Query(SemanticSearchParams {
                query: "   ".to_string(),
                limit: None,
            }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "Query parameter cannot be empty");
    }

    // ── PR5: /v1/soc/query structured query API ──────────────────────────────

    async fn seed_one_decision(state: &Arc<AppState>, tenant_id: &str, agent_token: &str) {
        let request = mcp_authorize_request("filesystem", "read_file");
        let _ = call_authorize(state.clone(), tenant_id, agent_token, request).await;
    }

    #[tokio::test]
    async fn soc_query_decision_list_count_and_timeseries() {
        let (state, tenant_id, agent_token) = setup_state("soc_query_decision").await;
        seed_one_decision(&state, &tenant_id, &agent_token).await;

        // aggregate=none → paginated rows.
        let resp = soc_query(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(SocQueryRequest {
                entity: "decision".to_string(),
                filters: SocQueryFilters::default(),
                aggregate: None,
                interval: None,
                limit: Some(10),
                cursor: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        // paginated_response returns the rows array (envelope shape reused).
        assert!(json.is_array() || json.get("data").is_some());

        // aggregate=count → totals.
        let resp = soc_query(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(SocQueryRequest {
                entity: "decision".to_string(),
                filters: SocQueryFilters::default(),
                aggregate: Some("count".to_string()),
                interval: None,
                limit: None,
                cursor: None,
            }),
        )
        .await
        .into_response();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(json["total"].as_i64().unwrap() >= 1);
        assert!(json["by_decision"]["allow"].as_i64().unwrap() >= 1);

        // aggregate=count_over_time → points array.
        let resp = soc_query(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(SocQueryRequest {
                entity: "decision".to_string(),
                filters: SocQueryFilters::default(),
                aggregate: Some("count_over_time".to_string()),
                interval: Some("day".to_string()),
                limit: None,
                cursor: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(json["points"].is_array());
    }

    #[tokio::test]
    async fn soc_query_rejects_unknown_entity_and_aggregate() {
        let (state, tenant_id, _) = setup_state("soc_query_reject").await;

        let resp = soc_query(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(SocQueryRequest {
                entity: "secrets".to_string(),
                filters: SocQueryFilters::default(),
                aggregate: None,
                interval: None,
                limit: None,
                cursor: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = soc_query(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(SocQueryRequest {
                entity: "decision".to_string(),
                filters: SocQueryFilters::default(),
                aggregate: Some("drop_table".to_string()),
                interval: None,
                limit: None,
                cursor: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn soc_query_is_tenant_scoped() {
        let (state, tenant_id, agent_token) = setup_state("soc_query_tenant").await;
        seed_one_decision(&state, &tenant_id, &agent_token).await;

        // A different tenant must see zero of tenant A's decisions.
        let resp = soc_query(
            State(state.clone()),
            TenantId("tenant_other".to_string()),
            Json(SocQueryRequest {
                entity: "decision".to_string(),
                filters: SocQueryFilters::default(),
                aggregate: Some("count".to_string()),
                interval: None,
                limit: None,
                cursor: None,
            }),
        )
        .await
        .into_response();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["total"].as_i64(),
            Some(0),
            "soc_query must be tenant-scoped — no cross-tenant decisions"
        );
    }
}
