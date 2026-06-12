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

/// A counter keyed by a small, fixed set of string labels (e.g. policy rule
/// names, alert/incident kinds). Label values come only from deterministic,
/// closed sets defined in `detect.rs`/`correlate.rs`/this module — never from
/// agent- or tenant-supplied data — so cardinality stays bounded (redaction
/// invariant: no tenant/agent PII in label values).
#[derive(Debug, Default)]
pub struct LabeledCounter {
    counts: Mutex<HashMap<Vec<String>, u64>>,
}

impl LabeledCounter {
    /// Increment the counter for `labels` by 1. Lock contention is
    /// out-of-band for all current call sites (decision write, SOC drain
    /// loop) and bounded by the small fixed label cardinality.
    pub fn inc(&self, labels: &[&str]) {
        let key: Vec<String> = labels.iter().map(|s| s.to_string()).collect();
        let mut counts = match self.counts.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *counts.entry(key).or_insert(0) += 1;
    }

    /// Render as Prometheus text exposition lines for metric `name`, with
    /// `label_names` (e.g. `["decision"]`) zipped against each recorded
    /// label-value tuple.
    fn render(&self, name: &str, help: &str, label_names: &[&str]) -> String {
        let mut out = format!("# HELP {name} {help}\n# TYPE {name} counter\n");
        let counts = match self.counts.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut entries: Vec<(&Vec<String>, &u64)> = counts.iter().collect();
        entries.sort();
        for (labels, count) in entries {
            let label_str = label_names
                .iter()
                .zip(labels.iter())
                .map(|(k, v)| format!("{k}=\"{v}\""))
                .collect::<Vec<_>>()
                .join(",");
            out.push_str(&format!("{name}{{{label_str}}} {count}\n"));
        }
        out
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
    /// `aegis_decisions_total{decision="allow|deny|require_approval"}` (OBS-002, #1155).
    pub decisions_total: LabeledCounter,
    /// `aegis_alerts_total{rule="...",severity="..."}` (OBS-002, #1155).
    pub alerts_total: LabeledCounter,
    /// `aegis_incidents_total{kind="..."}` (OBS-002, #1155).
    pub incidents_total: LabeledCounter,
    /// Number of SOC events successfully enqueued onto the async stream
    /// (OBS-002, #1155).
    pub events_emitted_total: AtomicU64,
    /// Number of SOC events dropped because the async stream channel was
    /// full or closed (OBS-002, #1155). Non-zero values indicate the
    /// drain task is falling behind.
    pub events_dropped_total: AtomicU64,
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

    /// Record one `/v1/authorize` decision (`"allow"`, `"deny"`, or
    /// `"require_approval"`) on `aegis_decisions_total`.
    #[inline]
    pub fn inc_decision(&self, decision: &str) {
        self.decisions_total.inc(&[decision]);
    }

    /// Record one SOC alert on `aegis_alerts_total{rule, severity}`.
    #[inline]
    pub fn inc_alert(&self, rule: &str, severity: &str) {
        self.alerts_total.inc(&[rule, severity]);
    }

    /// Record one SOC incident on `aegis_incidents_total{kind}`.
    #[inline]
    pub fn inc_incident(&self, kind: &str) {
        self.incidents_total.inc(&[kind]);
    }

    /// Increment `aegis_events_emitted_total` by 1.
    #[inline]
    pub fn inc_event_emitted(&self) {
        self.events_emitted_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `aegis_events_dropped_total` by 1.
    #[inline]
    pub fn inc_event_dropped(&self) {
        self.events_dropped_total.fetch_add(1, Ordering::Relaxed);
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
        out.push_str(&self.decisions_total.render(
            "aegis_decisions_total",
            "Number of /v1/authorize decisions by outcome",
            &["decision"],
        ));
        out.push_str(&self.alerts_total.render(
            "aegis_alerts_total",
            "Number of SOC alerts raised, by rule and severity",
            &["rule", "severity"],
        ));
        out.push_str(&self.incidents_total.render(
            "aegis_incidents_total",
            "Number of SOC incidents opened, by kind",
            &["kind"],
        ));
        let emitted = self.events_emitted_total.load(Ordering::Relaxed);
        let dropped = self.events_dropped_total.load(Ordering::Relaxed);
        out.push_str(&format!(
            "# HELP aegis_events_emitted_total Number of SOC events enqueued onto the async stream\n\
             # TYPE aegis_events_emitted_total counter\n\
             aegis_events_emitted_total {emitted}\n\
             # HELP aegis_events_dropped_total Number of SOC events dropped because the async stream was full or closed\n\
             # TYPE aegis_events_dropped_total counter\n\
             aegis_events_dropped_total {dropped}\n"
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
    fn inc_decision_renders_labeled_counter() {
        let m = SecurityMetrics::new();
        m.inc_decision("allow");
        m.inc_decision("allow");
        m.inc_decision("deny");
        let out = m.render_prometheus();
        assert!(out.contains("# TYPE aegis_decisions_total counter"));
        assert!(out.contains("aegis_decisions_total{decision=\"allow\"} 2\n"));
        assert!(out.contains("aegis_decisions_total{decision=\"deny\"} 1\n"));
    }

    #[test]
    fn inc_alert_renders_labeled_counter() {
        let m = SecurityMetrics::new();
        m.inc_alert("deny_storm", "high");
        let out = m.render_prometheus();
        assert!(out.contains("# TYPE aegis_alerts_total counter"));
        assert!(out.contains("aegis_alerts_total{rule=\"deny_storm\",severity=\"high\"} 1\n"));
    }

    #[test]
    fn inc_incident_renders_labeled_counter() {
        let m = SecurityMetrics::new();
        m.inc_incident("deny_storm");
        m.inc_incident("deny_storm");
        let out = m.render_prometheus();
        assert!(out.contains("# TYPE aegis_incidents_total counter"));
        assert!(out.contains("aegis_incidents_total{kind=\"deny_storm\"} 2\n"));
    }

    #[test]
    fn event_emitted_and_dropped_counters() {
        let m = SecurityMetrics::new();
        m.inc_event_emitted();
        m.inc_event_emitted();
        m.inc_event_dropped();
        let out = m.render_prometheus();
        assert!(out.contains("# TYPE aegis_events_emitted_total counter"));
        assert!(out.contains("aegis_events_emitted_total 2\n"));
        assert!(out.contains("# TYPE aegis_events_dropped_total counter"));
        assert!(out.contains("aegis_events_dropped_total 1\n"));
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
