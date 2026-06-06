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

/// Process-wide security counters. Held in `AppState` (via `Arc<AppState>`).
#[derive(Debug, Default)]
pub struct SecurityMetrics {
    /// Number of approval hash mismatches detected by this process.
    pub approval_hash_mismatch_total: AtomicU64,
    /// Number of mutating-action denials due to untrusted/malicious/unknown
    /// source provenance.
    pub provenance_denials_total: AtomicU64,
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

    /// Render the current counter values as a Prometheus text exposition (v0.0.4).
    /// Only the two security counters are exposed; no labels containing
    /// tenant/agent/payload data (redaction by design).
    pub fn render_prometheus(&self) -> String {
        let mismatch = self.approval_hash_mismatch_total.load(Ordering::Relaxed);
        let provenance = self.provenance_denials_total.load(Ordering::Relaxed);

        format!(
            "# HELP approval_hash_mismatch_total Number of approve-then-swap / hash-mismatch events detected\n\
             # TYPE approval_hash_mismatch_total counter\n\
             approval_hash_mismatch_total {mismatch}\n\
             # HELP provenance_denials_total Number of mutating-action denials due to untrusted/malicious/unknown source provenance\n\
             # TYPE provenance_denials_total counter\n\
             provenance_denials_total {provenance}\n"
        )
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
        let out = m.render_prometheus();
        assert!(out.contains("approval_hash_mismatch_total 1\n"));
        assert!(out.contains("provenance_denials_total 2\n"));
        assert!(out.contains("# TYPE approval_hash_mismatch_total counter"));
        assert!(out.contains("# TYPE provenance_denials_total counter"));
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
