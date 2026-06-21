//! #1286 — Splunk HTTP Event Collector (HEC) export.
//!
//! A single, globally-configured Splunk destination (via env vars, not a
//! per-tenant DB-backed subscription like `webhook_export.rs`'s
//! `webhook_subscriptions`) that receives every tenant's decisions, alerts,
//! and incidents — the SIEM-forwarding use case is inherently ops-wide, not
//! per-tenant. Driven by a periodic batch job (`jobs::run_splunk_export_job`)
//! that polls `db::list_decisions_since`/`list_soc_alerts_since`/
//! `list_soc_incidents_since` per tenant (each still tenant-scoped at the
//! query level — the job just loops over every tenant via
//! `db::list_all_tenant_ids`, it never bypasses tenant filtering), batches
//! the results into one HTTP POST per tick, and only advances each tenant's
//! cursor after a successful dispatch (a failed POST retries the same
//! window next tick — no data loss, just delay).
//!
//! ## Redaction invariant
//!
//! [`decision_to_hec_event`] forwards structured decision metadata only —
//! never `input_json` (the original tool-call payload). Forwarding raw
//! payloads to a third-party SIEM by default would be a redaction
//! regression; an operator who explicitly wants that can already get it from
//! `audit_events`/the evidence pack export, which are pulled on-demand
//! rather than pushed automatically.

use crate::models::{DecisionRecord, SocAlertRecord, SocIncidentRecord};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::OnceLock;

/// Default interval between Splunk HEC export batches (#1286 AC: "default 30s").
pub const DEFAULT_SPLUNK_HEC_BATCH_INTERVAL_SECS: u64 = 30;

/// Splunk HEC destination, read once from `AEGIS_SPLUNK_HEC_URL` /
/// `AEGIS_SPLUNK_HEC_TOKEN` / `AEGIS_SPLUNK_HEC_BATCH_INTERVAL_SECS`.
#[derive(Debug, Clone)]
pub struct SplunkHecConfig {
    /// Base URL of the Splunk HEC endpoint (e.g. `https://splunk.example.com:8088`).
    /// `/services/collector/event` is appended by [`dispatch_batch`].
    pub url: String,
    pub token: String,
    pub batch_interval_secs: u64,
}

impl SplunkHecConfig {
    /// `None` when `AEGIS_SPLUNK_HEC_URL` or `AEGIS_SPLUNK_HEC_TOKEN` is unset
    /// or blank — the hermetic default is "export disabled", matching the
    /// rest of this codebase's optional-integration env-var conventions
    /// (`sign::global_signer`, `notify::from_env`).
    pub fn from_env() -> Option<Self> {
        let url = std::env::var("AEGIS_SPLUNK_HEC_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())?;
        let token = std::env::var("AEGIS_SPLUNK_HEC_TOKEN")
            .ok()
            .filter(|s| !s.trim().is_empty())?;
        let batch_interval_secs = std::env::var("AEGIS_SPLUNK_HEC_BATCH_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_SPLUNK_HEC_BATCH_INTERVAL_SECS);
        Some(Self {
            url,
            token,
            batch_interval_secs,
        })
    }
}

/// Process-wide Splunk HEC delivery health (#1286 AC: "connection health
/// monitoring") — a `OnceLock`-backed static, mirroring `sign::global_signer`,
/// specifically to avoid threading a new field through every `AppState`
/// construction site (14+ across the crate, mostly test helpers — see the
/// comment on `main.rs`'s `RUNTIME_METRICS_START` for the same tradeoff).
pub struct SplunkHealth {
    consecutive_failures: AtomicU32,
    last_success_unix_secs: AtomicU64,
}

impl SplunkHealth {
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    /// 0 means "never succeeded since process start" (distinguishable from a
    /// real Unix timestamp, which is always > 0 for any plausible deployment).
    pub fn last_success_unix_secs(&self) -> u64 {
        self.last_success_unix_secs.load(Ordering::Relaxed)
    }

    pub(crate) fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        self.last_success_unix_secs.store(now, Ordering::Relaxed);
    }

    pub(crate) fn record_failure(&self) {
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
    }
}

static SPLUNK_HEALTH: OnceLock<SplunkHealth> = OnceLock::new();

pub fn global_health() -> &'static SplunkHealth {
    SPLUNK_HEALTH.get_or_init(|| SplunkHealth {
        consecutive_failures: AtomicU32::new(0),
        last_success_unix_secs: AtomicU64::new(0),
    })
}

/// Best-effort RFC3339 -> Unix-epoch-seconds parse for Splunk HEC's `time`
/// field. Never panics: an unparseable timestamp (which should not occur in
/// practice — these columns are always app-supplied RFC3339 strings) falls
/// back to "now" rather than dropping the event or crashing the export job.
fn unix_time_from_rfc3339(s: &str) -> f64 {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.timestamp() as f64)
        .unwrap_or_else(|_| chrono::Utc::now().timestamp() as f64)
}

/// Splunk HEC's documented event envelope: `time` (Unix epoch seconds),
/// `sourcetype` (#1286 AC: `aegis:decision`/`aegis:alert`/`aegis:incident`),
/// `source`, and the actual payload under `event`.
fn hec_envelope(time: f64, sourcetype: &str, event: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "time": time,
        "source": "aegisagent",
        "sourcetype": sourcetype,
        "event": event,
    })
}

/// Structured decision metadata only — never `input_json` (redaction
/// invariant, see module docs).
pub fn decision_to_hec_event(rec: &DecisionRecord) -> serde_json::Value {
    hec_envelope(
        rec.created_at.timestamp() as f64,
        "aegis:decision",
        serde_json::json!({
            "id": rec.id,
            "tenant_id": rec.tenant_id,
            "agent_id": rec.agent_id,
            "skill": rec.skill,
            "action": rec.action,
            "resource": rec.resource,
            "decision": rec.decision,
            "risk_score": rec.risk_score,
            "composite_risk_score": rec.composite_risk_score,
            "root_trust_level": rec.root_trust_level,
            "reason": rec.reason,
        }),
    )
}

pub fn alert_to_hec_event(rec: &SocAlertRecord) -> serde_json::Value {
    hec_envelope(
        unix_time_from_rfc3339(&rec.created_at),
        "aegis:alert",
        serde_json::json!({
            "id": rec.id,
            "tenant_id": rec.tenant_id,
            "rule": rec.rule,
            "severity": rec.severity,
            "agent_id": rec.agent_id,
            "summary": rec.summary,
        }),
    )
}

pub fn incident_to_hec_event(rec: &SocIncidentRecord) -> serde_json::Value {
    hec_envelope(
        unix_time_from_rfc3339(&rec.opened_at),
        "aegis:incident",
        serde_json::json!({
            "id": rec.id,
            "tenant_id": rec.tenant_id,
            "kind": rec.kind,
            "severity": rec.severity,
            "agent_id": rec.agent_id,
            "summary": rec.summary,
            "status": rec.status,
        }),
    )
}

/// POST a batch of HEC events to `{config.url}/services/collector/event`,
/// newline-delimited JSON objects in one body (Splunk HEC's documented
/// multi-event format — not a JSON array). Empty `events` is a no-op
/// success. A 10-second timeout bounds the periodic export job's tick.
pub async fn dispatch_batch(
    client: &reqwest::Client,
    config: &SplunkHecConfig,
    events: &[serde_json::Value],
) -> Result<(), String> {
    if events.is_empty() {
        return Ok(());
    }
    let body = events
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let url = format!(
        "{}/services/collector/event",
        config.url.trim_end_matches('/')
    );

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client
            .post(&url)
            .header("Authorization", format!("Splunk {}", config.token))
            .header("Content-Type", "application/json")
            .body(body)
            .send(),
    )
    .await;

    match result {
        Ok(Ok(resp)) if resp.status().is_success() => Ok(()),
        Ok(Ok(resp)) => Err(format!("Splunk HEC returned HTTP {}", resp.status())),
        Ok(Err(e)) => Err(format!("Splunk HEC request failed: {e}")),
        Err(_) => Err("Splunk HEC request timed out".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_decision() -> DecisionRecord {
        DecisionRecord {
            id: "dec_1".to_string(),
            tenant_id: "tenant_a".to_string(),
            agent_id: "agent_1".to_string(),
            user_id: None,
            run_id: None,
            trace_id: None,
            skill: "github".to_string(),
            action: "merge_pull_request".to_string(),
            resource: Some("payments#42".to_string()),
            input_json: "{\"secret\":\"should never appear in HEC output\"}".to_string(),
            decision: "deny".to_string(),
            risk_score: Some(80),
            reason: Some("untrusted source".to_string()),
            matched_policy_ids: None,
            request_id: None,
            latency_ms: None,
            composite_risk_score: Some(55),
            root_trust_level: Some("untrusted_external".to_string()),
            parent_run_id: None,
            created_at: Utc::now(),
        }
    }

    fn sample_alert() -> SocAlertRecord {
        SocAlertRecord {
            id: "al_1".to_string(),
            tenant_id: "tenant_a".to_string(),
            rule: "deny_storm".to_string(),
            severity: "high".to_string(),
            agent_id: "agent_1".to_string(),
            source_event_id: "evt_1".to_string(),
            summary: "5 denials in 60s".to_string(),
            created_at: Utc::now().to_rfc3339(),
        }
    }

    fn sample_incident() -> SocIncidentRecord {
        SocIncidentRecord {
            id: "inc_1".to_string(),
            tenant_id: "tenant_a".to_string(),
            kind: "deny_storm".to_string(),
            severity: "high".to_string(),
            agent_id: "agent_1".to_string(),
            summary: "5 denials in 60s".to_string(),
            source_event_ids: "[]".to_string(),
            opened_at: Utc::now().to_rfc3339(),
            status: "open".to_string(),
            closed_at: None,
        }
    }

    #[test]
    fn from_env_returns_none_when_url_or_token_unset() {
        std::env::remove_var("AEGIS_SPLUNK_HEC_URL");
        std::env::remove_var("AEGIS_SPLUNK_HEC_TOKEN");
        assert!(SplunkHecConfig::from_env().is_none());

        std::env::set_var("AEGIS_SPLUNK_HEC_URL", "https://splunk.example.com:8088");
        assert!(
            SplunkHecConfig::from_env().is_none(),
            "token alone unset must still disable export"
        );
        std::env::remove_var("AEGIS_SPLUNK_HEC_URL");
    }

    #[test]
    fn from_env_parses_url_token_and_default_interval() {
        std::env::set_var("AEGIS_SPLUNK_HEC_URL", "https://splunk.example.com:8088");
        std::env::set_var("AEGIS_SPLUNK_HEC_TOKEN", "test-token-123");
        std::env::remove_var("AEGIS_SPLUNK_HEC_BATCH_INTERVAL_SECS");

        let config = SplunkHecConfig::from_env().expect("both env vars set");
        assert_eq!(config.url, "https://splunk.example.com:8088");
        assert_eq!(config.token, "test-token-123");
        assert_eq!(
            config.batch_interval_secs,
            DEFAULT_SPLUNK_HEC_BATCH_INTERVAL_SECS
        );

        std::env::set_var("AEGIS_SPLUNK_HEC_BATCH_INTERVAL_SECS", "60");
        let config = SplunkHecConfig::from_env().unwrap();
        assert_eq!(config.batch_interval_secs, 60);

        std::env::remove_var("AEGIS_SPLUNK_HEC_URL");
        std::env::remove_var("AEGIS_SPLUNK_HEC_TOKEN");
        std::env::remove_var("AEGIS_SPLUNK_HEC_BATCH_INTERVAL_SECS");
    }

    #[test]
    fn decision_to_hec_event_has_correct_sourcetype_and_omits_input_json() {
        let event = decision_to_hec_event(&sample_decision());
        assert_eq!(event["sourcetype"], "aegis:decision");
        assert_eq!(event["source"], "aegisagent");
        assert_eq!(event["event"]["id"], "dec_1");
        assert_eq!(event["event"]["decision"], "deny");
        assert_eq!(event["event"]["composite_risk_score"], 55);
        // Redaction invariant: the raw tool-call payload must never appear.
        let serialized = event.to_string();
        assert!(
            !serialized.contains("should never appear"),
            "decision_to_hec_event must never forward input_json"
        );
    }

    #[test]
    fn alert_to_hec_event_has_correct_sourcetype() {
        let event = alert_to_hec_event(&sample_alert());
        assert_eq!(event["sourcetype"], "aegis:alert");
        assert_eq!(event["event"]["rule"], "deny_storm");
        assert_eq!(event["event"]["severity"], "high");
    }

    #[test]
    fn incident_to_hec_event_has_correct_sourcetype() {
        let event = incident_to_hec_event(&sample_incident());
        assert_eq!(event["sourcetype"], "aegis:incident");
        assert_eq!(event["event"]["kind"], "deny_storm");
        assert_eq!(event["event"]["status"], "open");
    }

    #[test]
    fn unix_time_from_rfc3339_falls_back_to_now_on_malformed_input() {
        let before = chrono::Utc::now().timestamp() as f64;
        let parsed = unix_time_from_rfc3339("not-a-timestamp");
        let after = chrono::Utc::now().timestamp() as f64;
        assert!(
            parsed >= before && parsed <= after,
            "malformed timestamp must fall back to current time, not panic"
        );
    }

    #[tokio::test]
    async fn dispatch_batch_is_a_noop_success_for_empty_events() {
        let client = reqwest::Client::new();
        let config = SplunkHecConfig {
            url: "https://unreachable.invalid.example".to_string(),
            token: "x".to_string(),
            batch_interval_secs: 30,
        };
        // No network call should even be attempted for an empty batch — if
        // it were, this would fail/timeout against the deliberately
        // unreachable host.
        let result = dispatch_batch(&client, &config, &[]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn dispatch_batch_reports_error_on_unreachable_host() {
        let client = reqwest::Client::new();
        let config = SplunkHecConfig {
            url: "http://127.0.0.1:1".to_string(), // port 1: nothing listens here
            token: "x".to_string(),
            batch_interval_secs: 30,
        };
        let result = dispatch_batch(
            &client,
            &config,
            &[decision_to_hec_event(&sample_decision())],
        )
        .await;
        assert!(result.is_err());
    }

    #[test]
    fn health_tracks_consecutive_failures_and_resets_on_success() {
        let health = SplunkHealth {
            consecutive_failures: AtomicU32::new(0),
            last_success_unix_secs: AtomicU64::new(0),
        };
        assert_eq!(health.consecutive_failures(), 0);
        assert_eq!(health.last_success_unix_secs(), 0);

        health.record_failure();
        health.record_failure();
        assert_eq!(health.consecutive_failures(), 2);

        health.record_success();
        assert_eq!(health.consecutive_failures(), 0);
        assert!(health.last_success_unix_secs() > 0);
    }
}
