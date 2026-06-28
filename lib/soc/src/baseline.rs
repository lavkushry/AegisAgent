//! SOC-007 (#1190) — per-agent behavioral baselining.
//!
//! Tracks two deterministic, threshold-based signals per `(tenant_id,
//! agent_id)`, computed from a rolling 7-day window of `/v1/authorize`
//! activity (Law 1 — statistical threshold, not ML scoring; Law 3 — runs only
//! in the out-of-band [`crate::events::drain`] consumer, never the inline
//! authorize budget):
//!
//! * **Rate anomaly** (`behavioral_anomaly_rate`, HIGH): the agent's action
//!   count in the current hour exceeds `mean + 3 * stddev` of its hourly
//!   counts over the trailing 7 days (168 one-hour buckets). Requires at
//!   least [`MIN_BASELINE_BUCKETS`] hours of history before firing, so a
//!   brand-new agent isn't flagged on its first burst of activity.
//! * **New tool/action** (`behavioral_anomaly_new_tool`, INFO): the agent has
//!   never been observed calling this `(tool, action)` pair before.
//!
//! Both signals are persisted via [`crate::db`] (not in-memory), so they
//! survive gateway restarts and are correct across multiple drain tasks.

use crate::detect::Alert;
use crate::events::AseEvent;
use aegis_storage::db;
use aegis_storage::db::DbPool;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

/// Minimum number of trailing hourly buckets required before the rate-anomaly
/// check runs. Below this, there isn't enough history to compute a meaningful
/// baseline, so a quiet agent's first active hour is never flagged.
const MIN_BASELINE_BUCKETS: usize = 24;

/// Width of the rolling baseline window, in days.
const BASELINE_WINDOW_DAYS: i64 = 7;

/// Number of standard deviations above the mean an hour's action count must
/// exceed to fire `behavioral_anomaly_rate`.
const SIGMA_THRESHOLD: f64 = 3.0;

/// Truncate an RFC 3339 timestamp to an hour bucket key (`"YYYY-MM-DDTHH"`).
/// Lexicographic comparison of these keys matches chronological order.
fn hour_bucket(occurred_at: &str) -> Option<String> {
    let dt = DateTime::parse_from_rfc3339(occurred_at).ok()?;
    Some(dt.with_timezone(&Utc).format("%Y-%m-%dT%H").to_string())
}

/// `current_bucket` minus [`BASELINE_WINDOW_DAYS`], as the same `"YYYY-MM-DDTHH"`
/// key format. Used as the inclusive lower bound of the baseline window.
fn bucket_minus_window(current_bucket: &str) -> Option<String> {
    let dt = chrono::NaiveDateTime::parse_from_str(
        &format!("{current_bucket}:00:00"),
        "%Y-%m-%dT%H:%M:%S",
    )
    .ok()?;
    let dt = dt - Duration::days(BASELINE_WINDOW_DAYS);
    Some(dt.format("%Y-%m-%dT%H").to_string())
}

/// Evaluate both behavioral signals for `event` and persist the updated
/// counters. Returns any [`Alert`]s that fired.
///
/// Database errors propagate to the caller, which logs and discards them
/// (best-effort, out-of-band — design law 3, matching `respond::dispatch`).
pub async fn evaluate(pool: &DbPool, event: &AseEvent) -> Result<Vec<Alert>, sqlx::Error> {
    let mut alerts = Vec::new();

    // New tool/action signal.
    let is_new = db::record_known_tool_action(
        pool,
        &event.tenant_id,
        &event.agent_id,
        &event.tool,
        &event.action,
        &event.occurred_at,
    )
    .await?;
    if is_new {
        alerts.push(Alert {
            alert_id: Uuid::new_v4().to_string(),
            occurred_at: event.occurred_at.clone(),
            tenant_id: event.tenant_id.clone(),
            rule: "behavioral_anomaly_new_tool".to_string(),
            severity: "info".to_string(),
            agent_id: event.agent_id.clone(),
            summary: format!(
                "Agent {} called {}/{} for the first time",
                event.agent_id, event.tool, event.action
            ),
            source_event_id: event.event_id.clone(),
        });
    }

    // Rate anomaly signal.
    let Some(current_bucket) = hour_bucket(&event.occurred_at) else {
        return Ok(alerts);
    };
    let current_count =
        db::increment_agent_hourly_count(pool, &event.tenant_id, &event.agent_id, &current_bucket)
            .await?;

    if let Some(since_bucket) = bucket_minus_window(&current_bucket) {
        let history = db::get_recent_hourly_counts(
            pool,
            &event.tenant_id,
            &event.agent_id,
            &since_bucket,
            &current_bucket,
        )
        .await?;

        if history.len() >= MIN_BASELINE_BUCKETS {
            let n = history.len() as f64;
            let mean = history.iter().sum::<i64>() as f64 / n;
            let variance = history
                .iter()
                .map(|&c| {
                    let d = c as f64 - mean;
                    d * d
                })
                .sum::<f64>()
                / n;
            let stddev = variance.sqrt();
            let threshold = mean + SIGMA_THRESHOLD * stddev;

            if stddev > 0.0 && (current_count as f64) > threshold {
                alerts.push(Alert {
                    alert_id: Uuid::new_v4().to_string(),
                    occurred_at: event.occurred_at.clone(),
                    tenant_id: event.tenant_id.clone(),
                    rule: "behavioral_anomaly_rate".to_string(),
                    severity: "high".to_string(),
                    agent_id: event.agent_id.clone(),
                    summary: format!(
                        "Agent {} action rate this hour ({}) exceeds its 7-day baseline \
                         (mean={mean:.2}, stddev={stddev:.2}, threshold={threshold:.2})",
                        event.agent_id, current_count
                    ),
                    source_event_id: event.event_id.clone(),
                });
            }
        }
    }

    Ok(alerts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(tenant_id: &str, agent_id: &str, occurred_at: &str, tool: &str) -> AseEvent {
        AseEvent {
            event_id: Uuid::new_v4().to_string(),
            occurred_at: occurred_at.to_string(),
            tenant_id: tenant_id.to_string(),
            kind: "authorize_decision".to_string(),
            agent_id: agent_id.to_string(),
            decision: "allow".to_string(),
            tool: tool.to_string(),
            action: "read".to_string(),
            resource: None,
            risk_score: 0,
            reason: "ok".to_string(),
            run_id: None,
            trace_id: None,
            matched_policies: vec![],
            redacted_fields: vec![],
            schema_version: 1,
            evidence: None,
        }
    }

    async fn setup_pool(test_name: &str) -> DbPool {
        std::fs::create_dir_all("target").unwrap();
        let db_url = format!(
            "sqlite://target/baseline_{}_{}.db",
            test_name,
            Uuid::new_v4().simple()
        );
        db::init_db(&db_url).await.unwrap()
    }

    #[test]
    fn hour_bucket_truncates_and_sorts_lexicographically() {
        assert_eq!(
            hour_bucket("2026-06-10T12:34:56Z").unwrap(),
            "2026-06-10T12"
        );
        assert!(
            hour_bucket("2026-06-10T09:00:00Z").unwrap()
                < hour_bucket("2026-06-10T12:00:00Z").unwrap()
        );
    }

    #[test]
    fn bucket_minus_window_subtracts_seven_days() {
        assert_eq!(
            bucket_minus_window("2026-06-10T12").unwrap(),
            "2026-06-03T12"
        );
    }

    #[tokio::test]
    async fn first_use_of_a_tool_fires_new_tool_alert() {
        let pool = setup_pool("new_tool").await;
        let event = make_event("tenant_a", "agent_1", "2026-06-10T12:00:00Z", "github");

        let alerts = evaluate(&pool, &event).await.unwrap();
        assert!(alerts
            .iter()
            .any(|a| a.rule == "behavioral_anomaly_new_tool"));

        // Second call with the same tool/action does not re-fire.
        let event2 = make_event("tenant_a", "agent_1", "2026-06-10T12:05:00Z", "github");
        let alerts2 = evaluate(&pool, &event2).await.unwrap();
        assert!(!alerts2
            .iter()
            .any(|a| a.rule == "behavioral_anomaly_new_tool"));
    }

    #[tokio::test]
    async fn quiet_agent_first_burst_is_not_flagged() {
        let pool = setup_pool("no_history").await;
        // 50 actions in a single hour with zero baseline history.
        for _ in 0..50 {
            let event = make_event("tenant_a", "agent_1", "2026-06-10T12:00:00Z", "github");
            let alerts = evaluate(&pool, &event).await.unwrap();
            assert!(!alerts.iter().any(|a| a.rule == "behavioral_anomaly_rate"));
        }
    }

    #[tokio::test]
    async fn rate_spike_above_baseline_fires_alert() {
        let pool = setup_pool("rate_spike").await;
        let tenant_id = "tenant_a";
        let agent_id = "agent_1";

        // Seed 168 hours (7 days) of baseline with a little variance (1 or 2
        // actions/hour, alternating), ending just before the spike hour. A
        // little variance keeps stddev > 0 so the threshold check engages.
        let spike_hour: DateTime<Utc> = "2026-06-10T12:00:00Z".parse().unwrap();
        for h in 1..=168 {
            let ts = spike_hour - Duration::hours(h);
            let bucket = hour_bucket(&ts.to_rfc3339()).unwrap();
            let reps = if h % 2 == 0 { 1 } else { 2 };
            for _ in 0..reps {
                db::increment_agent_hourly_count(&pool, tenant_id, agent_id, &bucket)
                    .await
                    .unwrap();
            }
        }

        // Spike hour: 100 actions, all on a tool already known so the
        // new-tool signal doesn't interfere.
        let mut last_alerts = Vec::new();
        for _ in 0..100 {
            let event = make_event(tenant_id, agent_id, "2026-06-10T12:00:00Z", "github");
            last_alerts = evaluate(&pool, &event).await.unwrap();
        }

        assert!(
            last_alerts
                .iter()
                .any(|a| a.rule == "behavioral_anomaly_rate" && a.severity == "high"),
            "expected a rate anomaly alert, got: {last_alerts:?}"
        );
    }

    #[tokio::test]
    async fn alerts_are_tenant_scoped() {
        let pool = setup_pool("tenant_scoped").await;

        let event_a = make_event("tenant_a", "agent_1", "2026-06-10T12:00:00Z", "github");
        let event_b = make_event("tenant_b", "agent_1", "2026-06-10T12:00:00Z", "github");

        let alerts_a = evaluate(&pool, &event_a).await.unwrap();
        let alerts_b = evaluate(&pool, &event_b).await.unwrap();

        // Both are "first use" for their own tenant — neither is suppressed
        // by the other tenant's history.
        assert!(alerts_a
            .iter()
            .any(|a| a.rule == "behavioral_anomaly_new_tool"));
        assert!(alerts_b
            .iter()
            .any(|a| a.rule == "behavioral_anomaly_new_tool"));
    }
}
