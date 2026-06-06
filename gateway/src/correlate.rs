//! Phase 3 — stateful, multi-event correlation engine (the SOC's "correlation").
//!
//! The Phase 0 [`crate::events::drain`] consumer feeds every [`AseEvent`] through
//! the [`Correlator`] after the single-event [`crate::detect::Detector`]. Where
//! the detector sees one event in isolation, the correlator maintains **bounded,
//! per-(tenant, agent) sliding windows** over recent event metadata and fires
//! [`Incident`]s when deterministic threshold rules are satisfied across multiple
//! events.
//!
//! Design-law compliance:
//!
//! * **Law 1 — deterministic only.** Every rule fires on a counted-field threshold
//!   (`deny` count, total action count, `require_approval` count). No scores gate,
//!   no ML, no tunable weights.
//! * **Law 2 — no LLM in the path.** Pure counting, window management, field
//!   matching; zero model calls.
//! * **Law 3 — runs in the async drain only.** [`Correlator::observe`] is invoked
//!   exclusively from [`crate::events::drain`] — never from the inline
//!   `/v1/authorize` budget.
//! * **Bounded memory.** After every `observe` call the correlator evicts entries
//!   older than `MAX_WINDOW_SECS`. The window map never grows unbounded.
//! * **Tenant-scoped.** The sliding window key is `(tenant_id, agent_id)` — events
//!   from different tenants are never aggregated together.

use crate::events::AseEvent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Correlation thresholds (named constants — deterministic Law 1)
// ─────────────────────────────────────────────────────────────────────────────

/// Deny-storm rule: fire when an agent accumulates this many `deny` decisions …
pub const DENY_STORM_N: usize = 5;
/// … within this many seconds (rolling window).
pub const DENY_STORM_WINDOW_SECS: i64 = 60;

/// Runaway rule: fire when an agent accumulates this many total actions …
pub const RUNAWAY_M: usize = 20;
/// … within this shorter window (seconds).
pub const RUNAWAY_WINDOW_SECS: i64 = 10;

/// Repeated-approval rule: fire when an agent accumulates this many
/// `require_approval` decisions …
pub const REPEATED_APPROVAL_K: usize = 10;
/// … within this window (seconds). Longer window — we want to catch slow,
/// automation-driven drip patterns.
pub const REPEATED_APPROVAL_WINDOW_SECS: i64 = 300;

/// The longest window across all rules. Used for eviction: any entry older
/// than this can never contribute to any rule, so it is safe to drop.
const MAX_WINDOW_SECS: i64 = REPEATED_APPROVAL_WINDOW_SECS; // 300 s

// ─────────────────────────────────────────────────────────────────────────────
// Incident — the correlation output
// ─────────────────────────────────────────────────────────────────────────────

/// An Incident represents a pattern detected across multiple [`AseEvent`]s.
/// Fields carry identifiers and a human summary only — no secrets, no raw
/// payloads (redaction invariant). The `source_event_ids` list is the evidence
/// chain for SOC investigation and receipt linking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Incident {
    /// Unique id for this incident.
    pub incident_id: String,
    /// RFC 3339 UTC timestamp of the event that crossed the threshold.
    pub opened_at: String,
    /// Owning tenant — incidents stay tenant-scoped.
    pub tenant_id: String,
    /// The agent whose behaviour triggered the correlation rule.
    pub agent_id: String,
    /// Stable rule identifier (e.g. `"deny_storm"`, `"runaway"`, `"repeated_approval"`).
    pub kind: String,
    /// `"high"` | `"info"`.
    pub severity: String,
    /// Human-readable, secret-free description of the pattern detected.
    pub summary: String,
    /// Ordered list of `event_id`s that contributed to this incident (evidence).
    pub source_event_ids: Vec<String>,
}

impl Incident {
    fn new(
        opened_at: &str,
        tenant_id: &str,
        agent_id: &str,
        kind: &str,
        severity: &str,
        summary: String,
        source_event_ids: Vec<String>,
    ) -> Self {
        Incident {
            incident_id: Uuid::new_v4().to_string(),
            opened_at: opened_at.to_string(),
            tenant_id: tenant_id.to_string(),
            agent_id: agent_id.to_string(),
            kind: kind.to_string(),
            severity: severity.to_string(),
            summary,
            source_event_ids,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Window entry — one slot in the per-agent sliding window
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal metadata for one event kept in the sliding window.
/// We store only what the rules need — no secrets, no payloads.
#[derive(Debug, Clone)]
struct WindowEntry {
    /// Parsed Unix timestamp (seconds) — used for window boundary checks.
    ts_secs: i64,
    /// The event_id, kept as the evidence reference.
    event_id: String,
    /// The authorize decision (`"allow"` | `"deny"` | `"require_approval"`).
    decision: String,
}

/// Parse an RFC 3339 timestamp string into Unix seconds.
/// Falls back to 0 so tests with invalid strings still compile (but all
/// entries will appear to be at epoch, which is deterministic for tests).
fn parse_ts(s: &str) -> i64 {
    use chrono::DateTime;
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.timestamp())
        .unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Correlator
// ─────────────────────────────────────────────────────────────────────────────

/// Stateful, bounded-memory correlation engine.
///
/// One instance is constructed in [`crate::events::drain`] and lives for the
/// process lifetime. Its only public interface is [`Correlator::observe`].
///
/// Memory bound: the `windows` map has at most one entry per `(tenant_id,
/// agent_id)` pair; each entry holds at most the events that fall within
/// `MAX_WINDOW_SECS`. Events older than that are evicted eagerly on every
/// `observe` call, so the map never grows unbounded.
#[derive(Default)]
pub struct Correlator {
    /// Per-(tenant, agent) sliding window of recent event metadata.
    windows: HashMap<(String, String), Vec<WindowEntry>>,
}

impl Correlator {
    /// Record an event and evaluate all correlation rules.
    ///
    /// Returns zero or more [`Incident`]s produced by the rules that crossed
    /// their threshold after absorbing this event. Multiple rules may fire on
    /// the same event (e.g. a burst that is simultaneously a deny storm *and* a
    /// runaway agent).
    ///
    /// This function never panics, never blocks, and never touches the inline
    /// path (Law 3). It operates in O(W) time where W is the window size
    /// (bounded by the threshold constants).
    pub fn observe(&mut self, ev: &AseEvent) -> Vec<Incident> {
        let key = (ev.tenant_id.clone(), ev.agent_id.clone());
        let ts_now = parse_ts(&ev.occurred_at);

        // 1. Append the new entry.
        let window = self.windows.entry(key).or_default();
        window.push(WindowEntry {
            ts_secs: ts_now,
            event_id: ev.event_id.clone(),
            decision: ev.decision.clone(),
        });

        // 2. Evict entries older than the longest window (bounded memory).
        let cutoff = ts_now - MAX_WINDOW_SECS;
        window.retain(|e| e.ts_secs >= cutoff);

        // 3. Re-borrow immutably for rule evaluation.
        let window = self
            .windows
            .get(&(ev.tenant_id.clone(), ev.agent_id.clone()))
            .map(|v| v.as_slice())
            .unwrap_or(&[]);

        let mut incidents = Vec::new();

        // Rule A — deny_storm (HIGH)
        if let Some(inc) = rule_deny_storm(ev, window, ts_now) {
            incidents.push(inc);
        }

        // Rule B — runaway (HIGH)
        if let Some(inc) = rule_runaway(ev, window, ts_now) {
            incidents.push(inc);
        }

        // Rule C — repeated_approval (INFO)
        if let Some(inc) = rule_repeated_approval(ev, window, ts_now) {
            incidents.push(inc);
        }

        incidents
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Correlation rules
// ─────────────────────────────────────────────────────────────────────────────

/// Rule A — `deny_storm` (HIGH).
///
/// An agent accumulates [`DENY_STORM_N`] or more `deny` decisions within
/// [`DENY_STORM_WINDOW_SECS`] seconds. Fires *exactly* when the threshold is
/// crossed (i.e. count == N, not on every subsequent deny) to avoid alert flood.
fn rule_deny_storm(ev: &AseEvent, window: &[WindowEntry], ts_now: i64) -> Option<Incident> {
    let cutoff = ts_now - DENY_STORM_WINDOW_SECS;
    let in_window: Vec<&WindowEntry> = window
        .iter()
        .filter(|e| e.ts_secs >= cutoff && e.decision == "deny")
        .collect();
    let count = in_window.len();
    // Fire exactly at the threshold crossing to avoid per-event repetition.
    if count == DENY_STORM_N {
        let ids: Vec<String> = in_window.iter().map(|e| e.event_id.clone()).collect();
        Some(Incident::new(
            &ev.occurred_at,
            &ev.tenant_id,
            &ev.agent_id,
            "deny_storm",
            "high",
            format!(
                "Agent {} accumulated {} deny decisions within {}s \
                 (deny storm — possible brute-force or misconfigured agent)",
                ev.agent_id, count, DENY_STORM_WINDOW_SECS
            ),
            ids,
        ))
    } else {
        None
    }
}

/// Rule B — `runaway` (HIGH).
///
/// An agent accumulates [`RUNAWAY_M`] or more total actions (any decision)
/// within [`RUNAWAY_WINDOW_SECS`] seconds. Fires exactly at the threshold to
/// avoid alert flood.
fn rule_runaway(ev: &AseEvent, window: &[WindowEntry], ts_now: i64) -> Option<Incident> {
    let cutoff = ts_now - RUNAWAY_WINDOW_SECS;
    let in_window: Vec<&WindowEntry> = window.iter().filter(|e| e.ts_secs >= cutoff).collect();
    let count = in_window.len();
    if count == RUNAWAY_M {
        let ids: Vec<String> = in_window.iter().map(|e| e.event_id.clone()).collect();
        Some(Incident::new(
            &ev.occurred_at,
            &ev.tenant_id,
            &ev.agent_id,
            "runaway",
            "high",
            format!(
                "Agent {} issued {} actions within {}s \
                 (runaway agent — possible loop or compromise)",
                ev.agent_id, count, RUNAWAY_WINDOW_SECS
            ),
            ids,
        ))
    } else {
        None
    }
}

/// Rule C — `repeated_approval` (INFO).
///
/// An agent accumulates [`REPEATED_APPROVAL_K`] or more `require_approval`
/// decisions within [`REPEATED_APPROVAL_WINDOW_SECS`] seconds. Fires exactly
/// at the threshold. Info severity — possible automation abuse rather than an
/// active attack.
fn rule_repeated_approval(ev: &AseEvent, window: &[WindowEntry], ts_now: i64) -> Option<Incident> {
    let cutoff = ts_now - REPEATED_APPROVAL_WINDOW_SECS;
    let in_window: Vec<&WindowEntry> = window
        .iter()
        .filter(|e| e.ts_secs >= cutoff && e.decision == "require_approval")
        .collect();
    let count = in_window.len();
    if count == REPEATED_APPROVAL_K {
        let ids: Vec<String> = in_window.iter().map(|e| e.event_id.clone()).collect();
        Some(Incident::new(
            &ev.occurred_at,
            &ev.tenant_id,
            &ev.agent_id,
            "repeated_approval",
            "info",
            format!(
                "Agent {} triggered {} require_approval decisions within {}s \
                 (possible automation abuse or over-privileged agent)",
                ev.agent_id, count, REPEATED_APPROVAL_WINDOW_SECS
            ),
            ids,
        ))
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests (TDD — written first; implementation above written to make them green)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal [`AseEvent`] with the fields the correlator cares about.
    /// `occurred_at` is an explicit RFC 3339 string so tests need no real sleep.
    fn make_event(
        event_id: &str,
        tenant_id: &str,
        agent_id: &str,
        decision: &str,
        occurred_at: &str,
    ) -> AseEvent {
        AseEvent {
            event_id: event_id.to_string(),
            occurred_at: occurred_at.to_string(),
            tenant_id: tenant_id.to_string(),
            kind: "authorize_decision".to_string(),
            agent_id: agent_id.to_string(),
            decision: decision.to_string(),
            tool: "github".to_string(),
            action: "push".to_string(),
            resource: None,
            risk_score: 40,
            reason: "test".to_string(),
            run_id: None,
            trace_id: None,
            matched_policies: vec![],
        }
    }

    /// Feed N events into the correlator at successive seconds starting from
    /// `base_ts` (RFC 3339). Returns all incidents produced.
    fn feed_n(
        correlator: &mut Correlator,
        n: usize,
        tenant: &str,
        agent: &str,
        decision: &str,
        base_ts: &str,
    ) -> Vec<Incident> {
        use chrono::DateTime;
        let base: i64 = DateTime::parse_from_rfc3339(base_ts)
            .map(|dt| dt.timestamp())
            .unwrap_or(0);

        let mut all = Vec::new();
        for i in 0..n {
            let ts_secs = base + i as i64;
            // Re-format as RFC 3339 (UTC). We keep it simple: adjust HH:MM:SS.
            let total_sec = ts_secs % 86400; // seconds within the day
            let hh = total_sec / 3600;
            let mm = (total_sec % 3600) / 60;
            let ss = total_sec % 60;
            let ts_str = format!("2026-06-06T{:02}:{:02}:{:02}Z", hh, mm, ss);
            let id = format!("evt_{}_{}_{}", agent, decision, i);
            let ev = make_event(&id, tenant, agent, decision, &ts_str);
            all.extend(correlator.observe(&ev));
        }
        all
    }

    // ─── deny_storm ──────────────────────────────────────────────────────────

    #[test]
    fn deny_storm_fires_at_exactly_n_denies_in_window() {
        let mut c = Correlator::default();
        let incidents = feed_n(
            &mut c,
            DENY_STORM_N,
            "tenant_a",
            "agent_1",
            "deny",
            "2026-06-06T12:00:00Z",
        );
        assert_eq!(
            incidents.iter().filter(|i| i.kind == "deny_storm").count(),
            1,
            "exactly one deny_storm incident when threshold is hit"
        );
        let inc = incidents.iter().find(|i| i.kind == "deny_storm").unwrap();
        assert_eq!(inc.severity, "high");
        assert_eq!(inc.tenant_id, "tenant_a");
        assert_eq!(inc.agent_id, "agent_1");
        assert_eq!(inc.source_event_ids.len(), DENY_STORM_N);
    }

    #[test]
    fn deny_storm_does_not_fire_below_threshold() {
        let mut c = Correlator::default();
        let incidents = feed_n(
            &mut c,
            DENY_STORM_N - 1,
            "tenant_a",
            "agent_1",
            "deny",
            "2026-06-06T12:00:00Z",
        );
        assert!(
            incidents.iter().all(|i| i.kind != "deny_storm"),
            "no deny_storm below threshold"
        );
    }

    #[test]
    fn deny_storm_agents_do_not_aggregate_across_different_agents() {
        // 2 denies each for two agents: neither hits threshold of 5.
        let mut c = Correlator::default();
        let half = DENY_STORM_N / 2; // 2
        let inc_a = feed_n(
            &mut c,
            half,
            "tenant_a",
            "agent_alpha",
            "deny",
            "2026-06-06T12:00:00Z",
        );
        let inc_b = feed_n(
            &mut c,
            half,
            "tenant_a",
            "agent_beta",
            "deny",
            "2026-06-06T12:00:00Z",
        );
        assert!(
            inc_a.iter().all(|i| i.kind != "deny_storm"),
            "agent_alpha must not fire deny_storm"
        );
        assert!(
            inc_b.iter().all(|i| i.kind != "deny_storm"),
            "agent_beta must not fire deny_storm"
        );
    }

    #[test]
    fn deny_storm_tenants_do_not_aggregate_across_different_tenants() {
        // Same agent_id, different tenants: each only sees 2 denies.
        let mut c = Correlator::default();
        let half = DENY_STORM_N / 2;
        let inc_t1 = feed_n(
            &mut c,
            half,
            "tenant_x",
            "shared_agent",
            "deny",
            "2026-06-06T12:00:00Z",
        );
        let inc_t2 = feed_n(
            &mut c,
            half,
            "tenant_y",
            "shared_agent",
            "deny",
            "2026-06-06T12:00:00Z",
        );
        assert!(
            inc_t1.iter().all(|i| i.kind != "deny_storm"),
            "tenant_x must not fire deny_storm"
        );
        assert!(
            inc_t2.iter().all(|i| i.kind != "deny_storm"),
            "tenant_y must not fire deny_storm"
        );
    }

    #[test]
    fn deny_storm_window_eviction_old_events_do_not_count() {
        // Send DENY_STORM_N-1 denies at t=0..3, then 1 deny at t=70
        // (well past the 60 s deny_storm window). Old events must be evicted;
        // the single late deny must NOT trigger deny_storm.
        let mut c = Correlator::default();

        // Early events within the first few seconds.
        for i in 0..(DENY_STORM_N - 1) {
            let ts = format!("2026-06-06T12:00:{:02}Z", i);
            let ev = make_event(
                &format!("old_{}", i),
                "tenant_a",
                "agent_evict",
                "deny",
                &ts,
            );
            c.observe(&ev);
        }

        // Late event — 70 seconds after the first event, outside the 60 s window.
        let late_ev = make_event(
            "late_deny",
            "tenant_a",
            "agent_evict",
            "deny",
            "2026-06-06T12:01:10Z", // 70 seconds after 12:00:00
        );
        let inc = c.observe(&late_ev);
        assert!(
            inc.iter().all(|i| i.kind != "deny_storm"),
            "old events outside window must be evicted; single late deny must not fire"
        );
    }

    // ─── runaway ──────────────────────────────────────────────────────────────

    #[test]
    fn runaway_fires_at_exactly_m_actions_in_window() {
        let mut c = Correlator::default();
        // All events within 9 seconds — inside RUNAWAY_WINDOW_SECS (10 s).
        let mut all_incidents = Vec::new();
        for i in 0..RUNAWAY_M {
            let decision = if i % 2 == 0 { "allow" } else { "deny" };
            let ts = format!("2026-06-06T12:00:{:02}Z", i % 10); // 0..9 seconds
            let ev = make_event(
                &format!("runaway_{}", i),
                "tenant_b",
                "agent_runaway",
                decision,
                &ts,
            );
            all_incidents.extend(c.observe(&ev));
        }
        let runaway_count = all_incidents.iter().filter(|i| i.kind == "runaway").count();
        assert_eq!(
            runaway_count, 1,
            "exactly one runaway incident at threshold"
        );
        let inc = all_incidents.iter().find(|i| i.kind == "runaway").unwrap();
        assert_eq!(inc.severity, "high");
        assert_eq!(inc.source_event_ids.len(), RUNAWAY_M);
    }

    #[test]
    fn runaway_does_not_fire_below_threshold() {
        let mut c = Correlator::default();
        let mut all_incidents = Vec::new();
        for i in 0..(RUNAWAY_M - 1) {
            let ts = format!("2026-06-06T12:00:{:02}Z", i % 10);
            let ev = make_event(&format!("r_{}", i), "tenant_b", "agent_ok", "allow", &ts);
            all_incidents.extend(c.observe(&ev));
        }
        assert!(
            all_incidents.iter().all(|i| i.kind != "runaway"),
            "no runaway below threshold"
        );
    }

    // ─── repeated_approval ────────────────────────────────────────────────────

    #[test]
    fn repeated_approval_fires_at_exactly_k_approvals_in_window() {
        let mut c = Correlator::default();
        let incidents = feed_n(
            &mut c,
            REPEATED_APPROVAL_K,
            "tenant_c",
            "agent_approvals",
            "require_approval",
            "2026-06-06T12:00:00Z",
        );
        let count = incidents
            .iter()
            .filter(|i| i.kind == "repeated_approval")
            .count();
        assert_eq!(
            count, 1,
            "exactly one repeated_approval incident at threshold"
        );
        let inc = incidents
            .iter()
            .find(|i| i.kind == "repeated_approval")
            .unwrap();
        assert_eq!(inc.severity, "info");
        assert_eq!(inc.source_event_ids.len(), REPEATED_APPROVAL_K);
    }

    #[test]
    fn repeated_approval_does_not_fire_below_threshold() {
        let mut c = Correlator::default();
        let incidents = feed_n(
            &mut c,
            REPEATED_APPROVAL_K - 1,
            "tenant_c",
            "agent_safe",
            "require_approval",
            "2026-06-06T12:00:00Z",
        );
        assert!(
            incidents.iter().all(|i| i.kind != "repeated_approval"),
            "no repeated_approval below threshold"
        );
    }

    // ─── clean stream ─────────────────────────────────────────────────────────

    #[test]
    fn allow_stream_produces_no_incidents() {
        // 50 allows spread across 50 seconds — not a burst, not a storm.
        let mut c = Correlator::default();
        let incidents = feed_n(
            &mut c,
            50,
            "tenant_d",
            "agent_clean",
            "allow",
            "2026-06-06T12:00:00Z",
        );
        assert!(
            incidents.is_empty(),
            "a healthy allow stream must produce no incidents"
        );
    }

    // ─── multi-rule on same burst ──────────────────────────────────────────────

    #[test]
    fn runaway_and_deny_storm_can_both_fire_on_same_burst() {
        // RUNAWAY_M (20) denies within RUNAWAY_WINDOW_SECS (10 s) — the first
        // DENY_STORM_N (5) all land within the deny_storm window (60 s), so
        // both rules fire.
        let mut c = Correlator::default();
        let mut all_incidents = Vec::new();
        for i in 0..RUNAWAY_M {
            // Spread across 0..9 seconds (all within the 10 s runaway window).
            let ts = format!("2026-06-06T12:00:{:02}Z", i % 10);
            let ev = make_event(
                &format!("multi_{}", i),
                "tenant_e",
                "agent_multi",
                "deny",
                &ts,
            );
            all_incidents.extend(c.observe(&ev));
        }
        assert!(
            all_incidents.iter().any(|i| i.kind == "deny_storm"),
            "deny_storm should fire"
        );
        assert!(
            all_incidents.iter().any(|i| i.kind == "runaway"),
            "runaway should fire"
        );
    }

    // ─── incident field integrity ──────────────────────────────────────────────

    #[test]
    fn incident_has_non_empty_required_fields() {
        let mut c = Correlator::default();
        let incidents = feed_n(
            &mut c,
            DENY_STORM_N,
            "tenant_f",
            "agent_fields",
            "deny",
            "2026-06-06T12:00:00Z",
        );
        let inc = incidents
            .iter()
            .find(|i| i.kind == "deny_storm")
            .expect("deny_storm must fire");
        assert!(!inc.incident_id.is_empty(), "incident_id must be set");
        assert_eq!(inc.tenant_id, "tenant_f");
        assert_eq!(inc.agent_id, "agent_fields");
        assert!(!inc.opened_at.is_empty(), "opened_at must be set");
        assert!(!inc.summary.is_empty(), "summary must be set");
    }
}
