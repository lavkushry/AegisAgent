/// Security metrics counters for SOC/ops observability.
///
/// Implemented with `std::sync::atomic` integers — zero extra crate
/// dependencies, non-blocking, and safe to share across Tokio tasks via Arc.
/// Exposed as Prometheus text format on GET /metrics (127.0.0.1 only).
///
/// Counter semantics (monotonically increasing, reset on process restart):
///
/// * `approval_hash_mismatch_total` — incremented each time the gateway detects
///   that the action proposed for execution no longer matches the SHA-256 bound
///   at approval creation time (approve-then-swap / render-vs-bytes defence).
///
/// * `provenance_denials_total` — incremented each time a mutating action is
///   denied because the source trust level is untrusted_external, malicious_suspected
///   or unknown (confused-deputy defence, CLAUDE.md critical invariant).
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Upper bounds (in seconds) of the `aegis_authorize_duration_seconds`
/// histogram buckets (OBS-001, #1154): 5ms, 10ms, 25ms, 50ms, 75ms, 100ms,
/// 250ms, 500ms, 1s. The inline `/v1/authorize` budget is 75ms (design law 3),
/// so buckets are concentrated below and around that threshold.
pub const AUTHORIZE_DURATION_BUCKETS_SECONDS: [f64; 9] =
    [0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 1.0];

/// A minimal Prometheus-style cumulative histogram backed by atomics — no
/// extra crate dependencies, non-blocking, safe to share via `Arc`.
///
/// `bucket_counts[i]` counts observations `<= AUTHORIZE_DURATION_BUCKETS_SECONDS[i]`
/// (cumulative, per Prometheus convention); `+Inf` is tracked separately via
/// `count`.
#[derive(Debug)]
pub struct DurationHistogram {
    bucket_counts: [AtomicU64; AUTHORIZE_DURATION_BUCKETS_SECONDS.len()],
    sum_micros: AtomicU64,
    count: AtomicU64,
}

impl Default for DurationHistogram {
    fn default() -> Self {
        Self {
            bucket_counts: Default::default(),
            sum_micros: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
}

impl DurationHistogram {
    /// Record one observation. `duration` is converted to fractional seconds
    /// for bucket comparison and to microseconds (rounded) for the running sum.
    pub fn observe(&self, duration: std::time::Duration) {
        let seconds = duration.as_secs_f64();
        for (i, bound) in AUTHORIZE_DURATION_BUCKETS_SECONDS.iter().enumerate() {
            if seconds <= *bound {
                self.bucket_counts[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.sum_micros
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Total number of observations recorded.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Render as Prometheus text exposition lines for metric `name`. No labels
    /// containing tenant/agent/payload data (redaction by design).
    fn render(&self, name: &str) -> String {
        let mut out = format!(
            "# HELP {name} Authorize request duration in seconds\n# TYPE {name} histogram\n"
        );
        let mut cumulative = 0u64;
        for (bound, bucket) in AUTHORIZE_DURATION_BUCKETS_SECONDS
            .iter()
            .zip(self.bucket_counts.iter())
        {
            cumulative += bucket.load(Ordering::Relaxed);
            out.push_str(&format!("{name}_bucket{{le=\"{bound}\"}} {cumulative}\n"));
        }
        let total = self.count();
        out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {total}\n"));
        let sum_seconds = self.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        out.push_str(&format!("{name}_sum {sum_seconds}\n"));
        out.push_str(&format!("{name}_count {total}\n"));
        out
    }
}

/// A minimal cumulative rolling average backed by atomics — no extra crate
/// dependencies, non-blocking, safe to share via `Arc`. Resets on process
/// restart, same as every other metric in this module.
#[derive(Debug, Default)]
pub struct RollingAverage {
    sum_micros: AtomicU64,
    count: AtomicU64,
}

impl RollingAverage {
    /// Record one observation.
    pub fn observe(&self, duration: std::time::Duration) {
        self.sum_micros
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Total number of observations recorded.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Mean of all observations recorded so far, in seconds. `0.0` if no
    /// observations have been recorded yet.
    pub fn average_seconds(&self) -> f64 {
        let count = self.count.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        let sum_seconds = self.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        sum_seconds / count as f64
    }

    /// Render as a single Prometheus gauge line for metric `name`.
    fn render(&self, name: &str, help: &str) -> String {
        format!(
            "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {}\n",
            self.average_seconds()
        )
    }
}

/// Process-wide security counters. Held in `AppState` (via `Arc<AppState>`).
#[derive(Debug, Default)]
pub struct SecurityMetrics {
    /// Number of approval hash mismatches detected by this process.
    pub approval_hash_mismatch_total: AtomicU64,
    /// Number of mutating-action denials due to untrusted/malicious/unknown
    /// source provenance.
    pub provenance_denials_total: AtomicU64,
    /// Number of handler panics caught by the CatchPanic layer (#1153).
    /// A non-zero value indicates a bug that would otherwise have dropped
    /// the client's TCP connection without a response.
    pub handler_panics_total: AtomicU64,
    /// `/v1/authorize` request duration histogram (OBS-001, #1154).
    pub authorize_duration: DurationHistogram,
    /// Number of `/v1/authorize` decisions that resulted in "allow" (OBS-002, #1155).
    pub decisions_allow_total: AtomicU64,
    /// Number of `/v1/authorize` decisions that resulted in "deny" (OBS-002, #1155).
    pub decisions_deny_total: AtomicU64,
    /// Number of `/v1/authorize` decisions that resulted in "require_approval" (OBS-002, #1155).
    pub decisions_require_approval_total: AtomicU64,
    /// Number of SOC events successfully enqueued onto the out-of-band pipeline (OBS-002, #1155).
    pub events_emitted_total: AtomicU64,
    /// Number of SOC events dropped because the out-of-band pipeline was full or closed (OBS-002, #1155).
    pub events_dropped_total: AtomicU64,
    /// Per (rule, severity) detection alert counts (OBS-002, #1155).
    /// `rule` and `severity` are enum-like values defined by `detect.rs` — no PII.
    alerts_total: Mutex<HashMap<(String, String), u64>>,
    /// Per `kind` correlated incident counts (OBS-002, #1155).
    /// `kind` is an enum-like value defined by `correlate.rs` — no PII.
    incidents_total: Mutex<HashMap<String, u64>>,
    /// Rolling mean time-to-detect: event occurrence -> alert creation
    /// (SOC-005, #1158). Sampled in `events::handle_alert` from the real
    /// gap between the triggering event's `occurred_at` and the moment the
    /// alert was raised — not derived from the persisted `SocAlertRecord`,
    /// whose `created_at` column intentionally mirrors `occurred_at` for
    /// evidence purposes rather than wall-clock alert-creation time.
    pub soc_mttd: RollingAverage,
    /// Rolling mean time-to-resolve: incident open -> incident close
    /// (SOC-005, #1158). Sampled in `routes::close_incident` from the real
    /// gap between `opened_at` and `closed_at`.
    pub soc_mttr: RollingAverage,
    /// Rolling mean DB connection-pool acquire latency (REL-004, #1150).
    /// Sampled by `jobs::sample_pool_health`'s periodic background probe — a
    /// synthetic `pool.acquire()` timed and released immediately, since
    /// instrumenting every real query call site across the codebase would be
    /// far more invasive for the same observability signal under load.
    pub db_pool_acquire_wait: RollingAverage,
}

impl SecurityMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment `approval_hash_mismatch_total` by 1 (relaxed — ordering is not
    /// needed here; the counter is only ever read for scraping).
    #[inline]
    pub fn inc_hash_mismatch(&self) {
        self.approval_hash_mismatch_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `provenance_denials_total` by 1.
    #[inline]
    pub fn inc_provenance_denial(&self) {
        self.provenance_denials_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `handler_panics_total` by 1.
    #[inline]
    pub fn inc_handler_panic(&self) {
        self.handler_panics_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the per-decision counter for `/v1/authorize` outcomes.
    /// `decision` must be one of `"allow"`, `"deny"`, `"require_approval"`;
    /// any other value is ignored (no PII labels permitted).
    #[inline]
    pub fn inc_decision(&self, decision: &str) {
        match decision {
            "allow" => self.decisions_allow_total.fetch_add(1, Ordering::Relaxed),
            "deny" => self.decisions_deny_total.fetch_add(1, Ordering::Relaxed),
            "require_approval" => self
                .decisions_require_approval_total
                .fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }

    /// Increment `events_emitted_total` by 1.
    #[inline]
    pub fn inc_event_emitted(&self) {
        self.events_emitted_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `events_dropped_total` by 1.
    #[inline]
    pub fn inc_event_dropped(&self) {
        self.events_dropped_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the alert counter for the given detection `rule` and `severity`.
    /// Both must be enum-like values defined by `detect.rs` (no PII).
    pub fn inc_alert(&self, rule: &str, severity: &str) {
        let mut alerts = self.alerts_total.lock().unwrap_or_else(|e| e.into_inner());
        *alerts
            .entry((rule.to_string(), severity.to_string()))
            .or_insert(0) += 1;
    }

    /// Increment the incident counter for the given correlated incident `kind`.
    /// `kind` must be an enum-like value defined by `correlate.rs` (no PII).
    pub fn inc_incident(&self, kind: &str) {
        let mut incidents = self
            .incidents_total
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *incidents.entry(kind.to_string()).or_insert(0) += 1;
    }

    /// Record one mean-time-to-detect sample (SOC-005, #1158).
    #[inline]
    pub fn observe_mttd(&self, duration: std::time::Duration) {
        self.soc_mttd.observe(duration);
    }

    /// Record one mean-time-to-resolve sample (SOC-005, #1158).
    #[inline]
    pub fn observe_mttr(&self, duration: std::time::Duration) {
        self.soc_mttr.observe(duration);
    }

    /// Render the current counter values as a Prometheus text exposition (v0.0.4).
    /// Only the security counters are exposed; no labels containing
    /// tenant/agent/payload data (redaction by design).
    pub fn render_prometheus(&self) -> String {
        let mismatch = self.approval_hash_mismatch_total.load(Ordering::Relaxed);
        let provenance = self.provenance_denials_total.load(Ordering::Relaxed);
        let panics = self.handler_panics_total.load(Ordering::Relaxed);

        let mut out = format!(
            "# HELP approval_hash_mismatch_total Number of approve-then-swap / hash-mismatch events detected\n\
             # TYPE approval_hash_mismatch_total counter\n\
             approval_hash_mismatch_total {mismatch}\n\
             # HELP provenance_denials_total Number of mutating-action denials due to untrusted/malicious/unknown source provenance\n\
             # TYPE provenance_denials_total counter\n\
             provenance_denials_total {provenance}\n\
             # HELP aegis_handler_panics_total Number of handler panics caught by the CatchPanic layer\n\
             # TYPE aegis_handler_panics_total counter\n\
             aegis_handler_panics_total {panics}\n"
        );
        out.push_str(
            &self
                .authorize_duration
                .render("aegis_authorize_duration_seconds"),
        );

        let allow = self.decisions_allow_total.load(Ordering::Relaxed);
        let deny = self.decisions_deny_total.load(Ordering::Relaxed);
        let require_approval = self
            .decisions_require_approval_total
            .load(Ordering::Relaxed);
        out.push_str(&format!(
            "# HELP aegis_decisions_total Number of /v1/authorize decisions by outcome\n\
             # TYPE aegis_decisions_total counter\n\
             aegis_decisions_total{{decision=\"allow\"}} {allow}\n\
             aegis_decisions_total{{decision=\"deny\"}} {deny}\n\
             aegis_decisions_total{{decision=\"require_approval\"}} {require_approval}\n"
        ));

        let emitted = self.events_emitted_total.load(Ordering::Relaxed);
        let dropped = self.events_dropped_total.load(Ordering::Relaxed);
        out.push_str(&format!(
            "# HELP aegis_events_emitted_total Number of SOC events enqueued onto the out-of-band pipeline\n\
             # TYPE aegis_events_emitted_total counter\n\
             aegis_events_emitted_total {emitted}\n\
             # HELP aegis_events_dropped_total Number of SOC events dropped because the out-of-band pipeline was full or closed\n\
             # TYPE aegis_events_dropped_total counter\n\
             aegis_events_dropped_total {dropped}\n"
        ));

        let alerts = self.alerts_total.lock().unwrap_or_else(|e| e.into_inner());
        out.push_str(
            "# HELP aegis_alerts_total Number of detection alerts raised by rule and severity\n\
             # TYPE aegis_alerts_total counter\n",
        );
        let mut alert_keys: Vec<&(String, String)> = alerts.keys().collect();
        alert_keys.sort();
        for (rule, severity) in alert_keys {
            let count = alerts[&(rule.clone(), severity.clone())];
            out.push_str(&format!(
                "aegis_alerts_total{{rule=\"{rule}\",severity=\"{severity}\"}} {count}\n"
            ));
        }
        drop(alerts);

        let incidents = self
            .incidents_total
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        out.push_str(
            "# HELP aegis_incidents_total Number of correlated incidents raised by kind\n\
             # TYPE aegis_incidents_total counter\n",
        );
        let mut incident_keys: Vec<&String> = incidents.keys().collect();
        incident_keys.sort();
        for kind in incident_keys {
            let count = incidents[kind];
            out.push_str(&format!(
                "aegis_incidents_total{{kind=\"{kind}\"}} {count}\n"
            ));
        }
        drop(incidents);

        out.push_str(&self.soc_mttd.render(
            "aegis_soc_mttd_seconds",
            "Rolling mean time from event occurrence to alert creation",
        ));
        out.push_str(&self.soc_mttr.render(
            "aegis_soc_mttr_seconds",
            "Rolling mean time from incident open to incident close",
        ));
        out.push_str(&self.db_pool_acquire_wait.render(
            "db_pool_acquire_wait_seconds",
            "Rolling mean DB connection-pool acquire latency, sampled periodically",
        ));

        out
    }
}

/// Trust levels that trigger a provenance denial when the action mutates state.
/// Kept here so the check is in one place and easy to audit.
pub const UNTRUSTED_PROVENANCE_LEVELS: &[&str] =
    &["untrusted_external", "malicious_suspected", "unknown"];

/// Returns `true` if the source trust level is one of the three untrusted
/// levels that mandate a deny for mutating actions.
#[inline]
pub fn is_untrusted_provenance(source_trust: &str) -> bool {
    UNTRUSTED_PROVENANCE_LEVELS.contains(&source_trust)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_start_at_zero() {
        let m = SecurityMetrics::new();
        assert_eq!(m.approval_hash_mismatch_total.load(Ordering::Relaxed), 0);
        assert_eq!(m.provenance_denials_total.load(Ordering::Relaxed), 0);
        assert_eq!(m.handler_panics_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn inc_handler_panic_increments() {
        let m = SecurityMetrics::new();
        m.inc_handler_panic();
        m.inc_handler_panic();
        assert_eq!(m.handler_panics_total.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn inc_hash_mismatch_increments() {
        let m = SecurityMetrics::new();
        m.inc_hash_mismatch();
        m.inc_hash_mismatch();
        assert_eq!(m.approval_hash_mismatch_total.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn inc_provenance_denial_increments() {
        let m = SecurityMetrics::new();
        m.inc_provenance_denial();
        assert_eq!(m.provenance_denials_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn render_prometheus_format() {
        let m = SecurityMetrics::new();
        m.inc_hash_mismatch();
        m.inc_provenance_denial();
        m.inc_provenance_denial();
        m.inc_handler_panic();
        let out = m.render_prometheus();
        assert!(out.contains("approval_hash_mismatch_total 1\n"));
        assert!(out.contains("provenance_denials_total 2\n"));
        assert!(out.contains("aegis_handler_panics_total 1\n"));
        assert!(out.contains("# TYPE approval_hash_mismatch_total counter"));
        assert!(out.contains("# TYPE provenance_denials_total counter"));
        assert!(out.contains("# TYPE aegis_handler_panics_total counter"));
    }

    #[test]
    fn inc_decision_increments_correct_counter() {
        let m = SecurityMetrics::new();
        m.inc_decision("allow");
        m.inc_decision("allow");
        m.inc_decision("deny");
        m.inc_decision("require_approval");
        m.inc_decision("bogus"); // ignored, no panic
        assert_eq!(m.decisions_allow_total.load(Ordering::Relaxed), 2);
        assert_eq!(m.decisions_deny_total.load(Ordering::Relaxed), 1);
        assert_eq!(
            m.decisions_require_approval_total.load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn inc_event_emitted_and_dropped_increment() {
        let m = SecurityMetrics::new();
        m.inc_event_emitted();
        m.inc_event_emitted();
        m.inc_event_dropped();
        assert_eq!(m.events_emitted_total.load(Ordering::Relaxed), 2);
        assert_eq!(m.events_dropped_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn inc_alert_and_incident_increment() {
        let m = SecurityMetrics::new();
        m.inc_alert("rapid_fire_denials", "high");
        m.inc_alert("rapid_fire_denials", "high");
        m.inc_alert("anomalous_action", "medium");
        m.inc_incident("burst_denials");
        let out = m.render_prometheus();
        assert!(
            out.contains("aegis_alerts_total{rule=\"rapid_fire_denials\",severity=\"high\"} 2\n")
        );
        assert!(
            out.contains("aegis_alerts_total{rule=\"anomalous_action\",severity=\"medium\"} 1\n")
        );
        assert!(out.contains("aegis_incidents_total{kind=\"burst_denials\"} 1\n"));
    }

    #[test]
    fn render_prometheus_includes_decisions_and_events() {
        let m = SecurityMetrics::new();
        m.inc_decision("allow");
        m.inc_decision("deny");
        m.inc_event_emitted();
        m.inc_event_dropped();
        let out = m.render_prometheus();
        assert!(out.contains("# TYPE aegis_decisions_total counter"));
        assert!(out.contains("aegis_decisions_total{decision=\"allow\"} 1\n"));
        assert!(out.contains("aegis_decisions_total{decision=\"deny\"} 1\n"));
        assert!(out.contains("aegis_decisions_total{decision=\"require_approval\"} 0\n"));
        assert!(out.contains("# TYPE aegis_events_emitted_total counter"));
        assert!(out.contains("aegis_events_emitted_total 1\n"));
        assert!(out.contains("# TYPE aegis_events_dropped_total counter"));
        assert!(out.contains("aegis_events_dropped_total 1\n"));
    }

    #[test]
    fn mttd_and_mttr_default_to_zero_with_no_observations() {
        let m = SecurityMetrics::new();
        let out = m.render_prometheus();
        assert!(out.contains("# TYPE aegis_soc_mttd_seconds gauge"));
        assert!(out.contains("aegis_soc_mttd_seconds 0\n"));
        assert!(out.contains("# TYPE aegis_soc_mttr_seconds gauge"));
        assert!(out.contains("aegis_soc_mttr_seconds 0\n"));
    }

    #[test]
    fn observe_mttd_and_mttr_compute_rolling_average() {
        let m = SecurityMetrics::new();
        m.observe_mttd(std::time::Duration::from_millis(500));
        m.observe_mttd(std::time::Duration::from_millis(1500));
        m.observe_mttr(std::time::Duration::from_secs(60));

        let out = m.render_prometheus();
        assert!(out.contains("aegis_soc_mttd_seconds 1\n")); // (0.5 + 1.5) / 2
        assert!(out.contains("aegis_soc_mttr_seconds 60\n"));
    }

    #[test]
    fn is_untrusted_provenance_classification() {
        assert!(is_untrusted_provenance("untrusted_external"));
        assert!(is_untrusted_provenance("malicious_suspected"));
        assert!(is_untrusted_provenance("unknown"));
        assert!(!is_untrusted_provenance("trusted_internal_signed"));
        assert!(!is_untrusted_provenance("trusted_internal_unsigned"));
        assert!(!is_untrusted_provenance("semi_trusted_customer"));
    }
}
