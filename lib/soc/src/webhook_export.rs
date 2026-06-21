//! #1285 — configurable webhook export (generic SIEM).
//!
//! Adds real delivery on top of the TASK-0092 (#938) CRUD scaffold
//! (`webhook_subscriptions` table, `/v1/webhook_subscriptions` routes):
//! that scaffold registered subscriptions but never delivered anything to
//! them. This module is called from the same out-of-band drain loop
//! (`events::drain`, design law 3 — never touches the inline `/v1/authorize`
//! budget) at the same three high-signal trigger points `notify.rs` already
//! uses: every `deny`/`require_approval` decision, and every HIGH-severity
//! alert/incident.
//!
//! ## Redaction invariant
//!
//! [`WebhookExportPayload`] carries identifiers, decision, severity, and a
//! human-readable summary only — no secrets, no tokens, no raw action
//! payloads, mirroring `notify::NotifyMessage`.
//!
//! ## Delivery
//!
//! Each matching subscription gets its own fire-and-forget Tokio task: up to
//! 3 attempts with exponential backoff (0ms, 500ms, 1s) and a 5-second
//! per-attempt timeout. The payload is signed with `delivery_secret` (a
//! server-generated, per-subscription HMAC key distinct from the legacy
//! operator-supplied `secret`/`secret_hash` pair) via `X-Aegis-Signature:
//! sha256=<hmac-hex>`. `db::record_webhook_delivery_result` updates the
//! subscription's `delivery_status` (`healthy` -> `degraded` -> `dead`)
//! after the attempt sequence completes.

use crate::notify::hmac_sha256;
use aegis_api::models::WebhookSubscriptionRecord;
use sqlx::SqlitePool;
use tracing::warn;

/// A redacted, serializable envelope for one delivered event — identifiers
/// and a summary only, no secrets or raw payloads (mirrors `NotifyMessage`).
#[derive(Debug, Clone)]
pub struct WebhookExportPayload {
    pub event_id: String,
    /// `"authorize_decision"` | `"alert"` | `"incident"`.
    pub kind: String,
    /// `"deny"` | `"require_approval"` | `"alert"` | `"incident"` — also the
    /// value matched against a subscription's `event_types` filter.
    pub event_type: String,
    /// `"high"` | `"info"`.
    pub severity: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub summary: String,
    pub occurred_at: String,
}

/// `"high"` outranks `"info"`. Unrecognized severities rank as `"info"`
/// (fail least-permissive: an unrecognized value never bypasses a `"high"`
/// minimum filter).
fn severity_rank(s: &str) -> u8 {
    if s == "high" {
        2
    } else {
        1
    }
}

/// Whether an event of `event_severity` clears a subscription's
/// `min_severity` floor.
pub fn passes_severity_filter(min_severity: &str, event_severity: &str) -> bool {
    severity_rank(event_severity) >= severity_rank(min_severity)
}

/// Build the default JSON delivery body.
pub fn json_body(payload: &WebhookExportPayload) -> serde_json::Value {
    serde_json::json!({
        "event_id": payload.event_id,
        "kind": payload.kind,
        "event_type": payload.event_type,
        "severity": payload.severity,
        "tenant_id": payload.tenant_id,
        "agent_id": payload.agent_id,
        "summary": payload.summary,
        "occurred_at": payload.occurred_at,
    })
}

/// Build a minimal, valid CEF (Common Event Format) delivery body:
/// `CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension`.
/// CEF severity is numeric 0-10; `"high"` maps to 10, everything else to 3.
pub fn cef_body(payload: &WebhookExportPayload) -> String {
    let cef_severity = if payload.severity == "high" { 10 } else { 3 };
    format!(
        "CEF:0|AegisAgent|Gateway|1|{}|{}|{}|tenantId={} agentId={} msg={}",
        payload.event_type,
        payload.kind,
        cef_severity,
        payload.tenant_id,
        payload.agent_id,
        // CEF extension values must not contain '|' or newlines; the
        // summary is operator/policy-authored text, not raw user input, but
        // sanitize defensively anyway.
        payload.summary.replace(['|', '\n', '\r'], " "),
    )
}

/// Render `payload` per `subscription.format` and return `(content_type, body_bytes)`.
fn render_body(
    subscription: &WebhookSubscriptionRecord,
    payload: &WebhookExportPayload,
) -> (&'static str, Vec<u8>) {
    if subscription.format == "cef" {
        ("text/plain", cef_body(payload).into_bytes())
    } else {
        (
            "application/json",
            serde_json::to_vec(&json_body(payload)).unwrap_or_default(),
        )
    }
}

/// Look up this tenant's subscriptions matching `payload.event_type`, filter
/// by severity, and spawn one fire-and-forget delivery task per match. Never
/// blocks the caller (the SOC drain loop) and never panics — Law 3.
pub async fn dispatch(pool: &SqlitePool, client: &reqwest::Client, payload: &WebhookExportPayload) {
    let subscriptions = match aegis_storage::db::list_matching_webhook_subscriptions(
        pool,
        &payload.tenant_id,
        &payload.event_type,
    )
    .await
    {
        Ok(subs) => subs,
        Err(e) => {
            warn!("#1285: failed to list webhook subscriptions: {:?}", e);
            return;
        }
    };

    for subscription in subscriptions {
        if !passes_severity_filter(&subscription.min_severity, &payload.severity) {
            continue;
        }
        let pool = pool.clone();
        let client = client.clone();
        let payload = payload.clone();
        tokio::spawn(async move {
            deliver_with_retry(&pool, &client, &subscription, &payload).await;
        });
    }
}

/// Up to 3 attempts with exponential backoff (0ms, 500ms, 1s), a 5-second
/// per-attempt timeout, and an HMAC-SHA256 signature (using the
/// subscription's server-generated `delivery_secret`) on `X-Aegis-Signature`.
/// Records the final outcome via `db::record_webhook_delivery_result`.
async fn deliver_with_retry(
    pool: &SqlitePool,
    client: &reqwest::Client,
    subscription: &WebhookSubscriptionRecord,
    payload: &WebhookExportPayload,
) {
    let (content_type, body) = render_body(subscription, payload);
    let signature = subscription
        .delivery_secret
        .as_deref()
        .map(|secret| format!("sha256={}", hmac_sha256(secret.as_bytes(), &body)));

    const MAX_ATTEMPTS: u32 = 3;
    let mut success = false;

    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            let backoff_ms = 500u64 * (1 << (attempt - 1));
            tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
        }

        let mut req = client
            .post(&subscription.url)
            .header("Content-Type", content_type)
            .body(body.clone());
        if let Some(sig) = signature.as_ref() {
            req = req.header("X-Aegis-Signature", sig.clone());
        }

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), req.send()).await;
        match result {
            Ok(Ok(resp)) if resp.status().is_success() => {
                success = true;
                break;
            }
            Ok(Ok(resp)) => {
                warn!(
                    url = %subscription.url,
                    status = %resp.status(),
                    attempt,
                    "#1285: webhook export delivery returned non-2xx"
                );
            }
            Ok(Err(err)) => {
                warn!(url = %subscription.url, attempt, error = %err, "#1285: webhook export delivery failed");
            }
            Err(_elapsed) => {
                warn!(url = %subscription.url, attempt, "#1285: webhook export delivery timed out after 5s");
            }
        }
    }

    if let Err(e) = aegis_storage::db::record_webhook_delivery_result(
        pool,
        &subscription.tenant_id,
        &subscription.id,
        success,
    )
    .await
    {
        warn!("#1285: failed to record webhook delivery result: {:?}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_payload(event_type: &str, severity: &str) -> WebhookExportPayload {
        WebhookExportPayload {
            event_id: "evt_1".to_string(),
            kind: "authorize_decision".to_string(),
            event_type: event_type.to_string(),
            severity: severity.to_string(),
            tenant_id: "tenant_1".to_string(),
            agent_id: "agent_1".to_string(),
            summary: "decision=deny tool=github action=merge".to_string(),
            occurred_at: "2026-06-17T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn passes_severity_filter_high_event_passes_any_minimum() {
        assert!(passes_severity_filter("info", "high"));
        assert!(passes_severity_filter("high", "high"));
    }

    #[test]
    fn passes_severity_filter_info_event_blocked_by_high_minimum() {
        assert!(!passes_severity_filter("high", "info"));
    }

    #[test]
    fn passes_severity_filter_info_event_passes_info_minimum() {
        assert!(passes_severity_filter("info", "info"));
    }

    #[test]
    fn json_body_includes_all_redacted_fields_and_no_secrets() {
        let payload = make_payload("deny", "high");
        let body = json_body(&payload);
        assert_eq!(body["event_id"], "evt_1");
        assert_eq!(body["event_type"], "deny");
        assert_eq!(body["severity"], "high");
        assert_eq!(body["tenant_id"], "tenant_1");
        assert_eq!(body["agent_id"], "agent_1");
        assert_eq!(body["summary"], payload.summary);
        // Exactly the redacted fields above — nothing else leaks.
        assert_eq!(body.as_object().unwrap().len(), 8);
    }

    #[test]
    fn cef_body_is_well_formed_and_maps_severity() {
        let high = cef_body(&make_payload("deny", "high"));
        assert!(high.starts_with("CEF:0|AegisAgent|Gateway|1|deny|authorize_decision|10|"));
        assert!(high.contains("tenantId=tenant_1"));
        assert!(high.contains("agentId=agent_1"));

        let info = cef_body(&make_payload("alert", "info"));
        assert!(info.starts_with("CEF:0|AegisAgent|Gateway|1|alert|authorize_decision|3|"));
    }

    #[test]
    fn cef_body_strips_pipe_and_newline_from_summary() {
        let mut payload = make_payload("deny", "high");
        payload.summary = "line1\nline2|injected".to_string();
        let body = cef_body(&payload);
        assert!(!body.contains('\n'));
        // Exactly the format's own 7 header-delimiting pipes — none leaked
        // in from the (sanitized) summary.
        assert_eq!(body.matches('|').count(), 7);
        assert!(body.contains("line1 line2 injected"));
    }

    // ── dispatch: end-to-end delivery against a real local server ──────────

    async fn setup_pool_with_subscription(
        url: &str,
        min_severity: &str,
        format: &str,
    ) -> (
        sqlx::SqlitePool,
        aegis_api::models::WebhookSubscriptionRecord,
    ) {
        let pool = aegis_storage::db::init_db("sqlite::memory:").await.unwrap();
        aegis_storage::db::register_tenant(&pool, "tenant_1", "Tenant One", "developer")
            .await
            .unwrap();
        let record = aegis_storage::db::insert_webhook_subscription(
            &pool,
            "tenant_1",
            url,
            None,
            "deny,require_approval,alert,incident",
            "whsec_test_secret",
            min_severity,
            format,
        )
        .await
        .unwrap();
        (pool, record)
    }

    #[tokio::test]
    async fn dispatch_delivers_signed_json_payload_and_records_success() {
        use axum::{routing::post, Router};
        use std::sync::Arc;
        use tokio::sync::Mutex;

        type Received = Option<(Option<String>, serde_json::Value)>;
        let received: Arc<Mutex<Received>> = Arc::new(Mutex::new(None));
        let received_clone = received.clone();

        let app = Router::new().route(
            "/hook",
            post(
                move |headers: axum::http::HeaderMap,
                      axum::Json(body): axum::Json<serde_json::Value>| {
                    let received_clone = received_clone.clone();
                    async move {
                        let sig = headers
                            .get("X-Aegis-Signature")
                            .map(|v| v.to_str().unwrap_or("").to_string());
                        *received_clone.lock().await = Some((sig, body));
                        "ok"
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("http://{addr}/hook");
        let (pool, subscription) = setup_pool_with_subscription(&url, "info", "json").await;

        let client = reqwest::Client::new();
        dispatch(&pool, &client, &make_payload("deny", "high")).await;

        let mut delivered = None;
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if let Some(v) = received.lock().await.clone() {
                delivered = Some(v);
                break;
            }
        }
        let (sig_opt, body) = delivered.expect("webhook was not delivered in time");

        let expected_sig = format!(
            "sha256={}",
            hmac_sha256(b"whsec_test_secret", &serde_json::to_vec(&body).unwrap())
        );
        assert_eq!(sig_opt, Some(expected_sig));
        assert_eq!(body["event_type"], "deny");

        let updated =
            aegis_storage::db::get_webhook_subscription(&pool, "tenant_1", &subscription.id)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(updated.delivery_status, "healthy");
        assert_eq!(updated.consecutive_failures, 0);
        assert!(updated.last_success_at.is_some());
    }

    #[tokio::test]
    async fn dispatch_skips_subscription_below_severity_threshold() {
        use axum::{routing::post, Router};
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let hit_count = Arc::new(Mutex::new(0u32));
        let hit_count_clone = hit_count.clone();
        let app = Router::new().route(
            "/hook",
            post(move || {
                let hit_count_clone = hit_count_clone.clone();
                async move {
                    *hit_count_clone.lock().await += 1;
                    "ok"
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("http://{addr}/hook");
        // Subscription requires "high"; the dispatched event is "info".
        let (pool, _subscription) = setup_pool_with_subscription(&url, "high", "json").await;

        let client = reqwest::Client::new();
        dispatch(&pool, &client, &make_payload("alert", "info")).await;

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            *hit_count.lock().await,
            0,
            "info event must not reach a high-only subscription"
        );
    }

    #[tokio::test]
    async fn dispatch_records_failure_after_unreachable_endpoint() {
        // Port 0 never accepts connections once dropped; using an unbound
        // local port keeps this fast and avoids any real network access.
        let url = "http://127.0.0.1:1/unreachable".to_string();
        let (pool, subscription) = setup_pool_with_subscription(&url, "info", "json").await;

        let client = reqwest::Client::new();
        dispatch(&pool, &client, &make_payload("deny", "high")).await;

        // 3 attempts with 0ms/500ms/1s backoff between them — give it generous headroom.
        tokio::time::sleep(std::time::Duration::from_millis(3000)).await;

        let updated =
            aegis_storage::db::get_webhook_subscription(&pool, "tenant_1", &subscription.id)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(updated.consecutive_failures, 1);
        assert_eq!(updated.delivery_status, "healthy");
        assert!(updated.last_delivery_at.is_some());
        assert!(updated.last_success_at.is_none());
    }
}
