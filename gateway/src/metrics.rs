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
use std::sync::atomic::{AtomicU64, Ordering};

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
    fn is_untrusted_provenance_classification() {
        assert!(is_untrusted_provenance("untrusted_external"));
        assert!(is_untrusted_provenance("malicious_suspected"));
        assert!(is_untrusted_provenance("unknown"));
        assert!(!is_untrusted_provenance("trusted_internal_signed"));
        assert!(!is_untrusted_provenance("trusted_internal_unsigned"));
        assert!(!is_untrusted_provenance("semi_trusted_customer"));
    }
}
