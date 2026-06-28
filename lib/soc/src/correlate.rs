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
//!   (`deny` count, total action count, `require_approval` count) or a structural
//!   Source→Sink sequence (Rule D). No scores gate, no ML, no tunable weights.
//! * **Law 2 — no LLM in the path.** Pure counting, window management, field
//!   matching; zero model calls.
//! * **Law 3 — runs in the async drain only.** [`Correlator::observe`] is invoked
//!   exclusively from [`crate::events::drain`] — never from the inline
//!   `/v1/authorize` budget.
//! * **Bounded memory.** After every `observe` call the correlator evicts entries
//!   older than `MAX_WINDOW_SECS`. The window map never grows unbounded.
//! * **Tenant-scoped.** The sliding window key is `(tenant_id, agent_id)` — events
//!   from different tenants or agents are never aggregated together.

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

/// Data-exfiltration pattern rule: fire when a Source action is followed by a
/// Sink action for the same (tenant, agent) within this window (seconds).
/// 120 s is long enough to catch a read-then-upload pair in one run, short
/// enough to limit false positives from unrelated sequential tool calls.
pub const EXFIL_WINDOW_SECS: i64 = 120;

/// Trust-escalation rule: fire when a hard `deny` for a (tool, action) is
/// followed by an `allow` for the **exact same** (agent, tool, action) within
/// this window (seconds). A deny→allow flip for the same action moments later
/// is suspicious privilege-probing / trust manipulation.
///
/// `require_approval` → (human approves) → `allow` is the **legitimate**
/// human-in-the-loop path and deliberately does NOT trigger this rule —
/// only a hard `deny` counts as the prior trigger.
pub const TRUST_ESCALATION_WINDOW_SECS: i64 = 120;

/// The longest window across all rules. Used for eviction: any entry older
/// than this can never contribute to any rule, so it is safe to drop.
const MAX_WINDOW_SECS: i64 = REPEATED_APPROVAL_WINDOW_SECS; // 300 s

// ─────────────────────────────────────────────────────────────────────────────
// Exfiltration action classifier (Rule D — deterministic, no scores)
// ─────────────────────────────────────────────────────────────────────────────

/// Role of an action in the Source→Sink exfiltration pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExfilRole {
    /// Data-access action: the agent is reading/fetching data from a store.
    Source,
    /// Data-egress action: the agent is sending/writing data outward.
    /// Preferred over Source when a token could match both — egress-safety.
    Sink,
    /// Neither a clear data source nor a clear egress action.
    Other,
}

/// Lowercase substrings that classify an action as a data **source** (reads).
/// Tokens are checked case-insensitively via `action.to_lowercase().contains(tok)`.
/// These represent data retrieval operations.
const SOURCE_TOKENS: &[&str] = &[
    "read",     // read_file, readfile, read_record …
    "get",      // get_object, getUser …
    "fetch",    // fetch_data, fetchRows …
    "list",     // list_files, listBuckets …
    "download", // download_blob …
    "query",    // query_db, queryTable …
    "select",   // select_rows …
    "export",   // export_csv …
    "dump",     // dump_table, mysqldump …
    "cat",      // cat (shell), concatenate file contents …
];

/// Lowercase substrings that classify an action as a data **sink** (egress).
/// Checked BEFORE Source tokens when a name matches both — egress is the
/// more dangerous role, so we prefer Sink for conservative alerting.
///
/// Rationale for potential overlap:
/// * `"write_external"` could sound like a write (source side for some) but
///   it names an outbound write path — Sink.
/// * `"http"` covers generic HTTP POSTs/PUTs to external endpoints.
/// * `"exfil"` is always Sink by definition.
const SINK_TOKENS: &[&str] = &[
    "send",           // send_message, sendEmail …
    "post",           // post_webhook, postData …
    "upload",         // upload_file, uploadBlob …
    "email",          // email_report, emailUser …
    "webhook",        // fire_webhook, callWebhook …
    "push",           // push_notification, gitPush (egress to remote) …
    "publish",        // publish_event, publishMessage …
    "write_external", // explicit external-write convention
    "share",          // share_document, shareLink …
    "transfer",       // transfer_file, transferFunds …
    "exfil",          // any action explicitly named exfil
    "http",           // http_call, httpPost — generic outbound HTTP
];

/// Classify an action name into its [`ExfilRole`].
///
/// Sink tokens are tested **first** so that any ambiguous name (e.g. an action
/// called `"post_read_result"`) is conservatively treated as egress.
///
/// The comparison is case-insensitive (lowercased once; O(tokens × action_len)).
pub fn action_kind(action: &str) -> ExfilRole {
    let lower = action.to_lowercase();
    // Prefer Sink over Source for egress safety.
    for tok in SINK_TOKENS {
        if lower.contains(tok) {
            return ExfilRole::Sink;
        }
    }
    for tok in SOURCE_TOKENS {
        if lower.contains(tok) {
            return ExfilRole::Source;
        }
    }
    ExfilRole::Other
}

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
    /// The tool name — stored for Rule E (trust-escalation deny→allow matching).
    tool: String,
    /// The action name, stored for Rule D (data-exfil source→sink matching)
    /// and Rule E (trust-escalation deny→allow matching).
    action: String,
    /// True once this Source entry has been paired with a Sink by Rule D.
    /// Prevents the same Source from generating a second incident when a
    /// later Sink arrives (no-flood guarantee).
    exfil_paired: bool,
    /// True once this hard-`deny` entry has been paired with an `allow` by
    /// Rule E. Prevents a second `allow` for the same (tool, action) from
    /// re-firing the trust-escalation incident (no-flood guarantee).
    trust_escalation_paired: bool,
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
        let window = self.windows.entry(key.clone()).or_default();
        window.push(WindowEntry {
            ts_secs: ts_now,
            event_id: ev.event_id.clone(),
            decision: ev.decision.clone(),
            tool: ev.tool.clone(),
            action: ev.action.clone(),
            exfil_paired: false,
            trust_escalation_paired: false,
        });

        // 2. Evict entries older than the longest window (bounded memory).
        let cutoff = ts_now - MAX_WINDOW_SECS;
        window.retain(|e| e.ts_secs >= cutoff);

        // 3. Re-borrow immutably for rules A/B/C evaluation.
        let window_slice = self.windows.get(&key).map(|v| v.as_slice()).unwrap_or(&[]);

        let mut incidents = Vec::new();

        // Rule A — deny_storm (HIGH)
        if let Some(inc) = rule_deny_storm(ev, window_slice, ts_now) {
            incidents.push(inc);
        }

        // Rule B — runaway (HIGH)
        if let Some(inc) = rule_runaway(ev, window_slice, ts_now) {
            incidents.push(inc);
        }

        // Rule C — repeated_approval (INFO)
        if let Some(inc) = rule_repeated_approval(ev, window_slice, ts_now) {
            incidents.push(inc);
        }

        // Rule D — data_exfil_pattern (HIGH).
        // Needs a mutable borrow of the window to mark paired Source entries,
        // so we re-borrow mutably here (rules A/B/C are already done).
        if let Some(window_mut) = self.windows.get_mut(&key) {
            if let Some(inc) = rule_data_exfil(ev, window_mut, ts_now) {
                incidents.push(inc);
            }
        }

        // Rule E — trust_escalation (HIGH).
        // Needs a mutable borrow to mark the paired deny entry; runs after D.
        if let Some(window_mut) = self.windows.get_mut(&key) {
            if let Some(inc) = rule_trust_escalation(ev, window_mut, ts_now) {
                incidents.push(inc);
            }
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

/// Rule D — `data_exfil_pattern` (HIGH).
///
/// Within [`EXFIL_WINDOW_SECS`] seconds for the same (tenant, agent), a
/// **Source** action (data access) is followed by a **Sink** action (egress),
/// where `Source.ts <= Sink.ts` and both fall within the window.
///
/// Fires **on the completing Sink event** — i.e. only when the current event
/// is a Sink and an un-paired Source exists in-window. The matched Source entry
/// is marked `exfil_paired = true` so subsequent Sink events from the same
/// agent do not re-fire on the same Source (no-flood guarantee).
///
/// Takes a mutable slice so it can mark the paired Source entry in place.
fn rule_data_exfil(ev: &AseEvent, window: &mut [WindowEntry], ts_now: i64) -> Option<Incident> {
    // Only fire when the current (triggering) event is a Sink.
    if action_kind(&ev.action) != ExfilRole::Sink {
        return None;
    }

    let exfil_cutoff = ts_now - EXFIL_WINDOW_SECS;

    // Find the earliest un-paired Source entry inside the exfil window whose
    // timestamp is <= the current Sink timestamp (causal ordering).
    // We look for the first (oldest) qualifying Source so the pairing is
    // deterministic regardless of window order.
    let source_idx = window.iter().position(|e| {
        e.ts_secs >= exfil_cutoff
            && e.ts_secs <= ts_now
            && !e.exfil_paired
            && action_kind(&e.action) == ExfilRole::Source
    });

    let source_idx = source_idx?;

    // Collect evidence: the Source event id + the Sink event id (current).
    let source_event_id = window[source_idx].event_id.clone();
    let source_action = window[source_idx].action.clone();

    // Mark the Source as paired — prevents re-firing on subsequent Sinks
    // without adding any new state (bounded by the window length).
    window[source_idx].exfil_paired = true;

    Some(Incident::new(
        &ev.occurred_at,
        &ev.tenant_id,
        &ev.agent_id,
        "data_exfil_pattern",
        "high",
        format!(
            "Agent {} performed a data-access action ('{}') followed by an egress action \
             ('{}') within {}s — possible data exfiltration pattern",
            ev.agent_id, source_action, ev.action, EXFIL_WINDOW_SECS
        ),
        vec![source_event_id, ev.event_id.clone()],
    ))
}

/// Rule E — `trust_escalation` (HIGH).
///
/// Within [`TRUST_ESCALATION_WINDOW_SECS`] seconds for the same (tenant, agent),
/// a hard `deny` decision for a `(tool, action)` pair is followed by an `allow`
/// decision for the **exact same** `(tool, action)` pair by the **same agent**.
///
/// This is suspicious privilege-probing / trust manipulation: an action that was
/// hard-denied should not flip to allowed for the same agent moments later without
/// scrutiny. Fires **on the completing `allow` event**.
///
/// **Exclusion:** `require_approval` → (human approves) → `allow` is the
/// legitimate human-in-the-loop path and must NOT fire this rule. Only a hard
/// `deny` (decision string exactly `"deny"`) counts as the prior trigger.
///
/// The matched `deny` entry is marked `trust_escalation_paired = true` so
/// subsequent `allow` events for the same `(tool, action)` do not re-fire on
/// the same prior deny (no-flood guarantee).
///
/// Takes a mutable slice so it can mark the paired `deny` entry in place.
fn rule_trust_escalation(
    ev: &AseEvent,
    window: &mut [WindowEntry],
    ts_now: i64,
) -> Option<Incident> {
    // Only fire when the current (completing) event is a hard allow.
    if ev.decision != "allow" {
        return None;
    }

    let cutoff = ts_now - TRUST_ESCALATION_WINDOW_SECS;

    // Find the earliest un-paired hard `deny` entry in-window for the exact
    // same (tool, action). Case-sensitive equality on both fields (deterministic).
    // We require ts_secs <= ts_now (causal ordering — deny precedes allow).
    let deny_idx = window.iter().position(|e| {
        e.ts_secs >= cutoff
            && e.ts_secs <= ts_now
            && e.decision == "deny"
            && !e.trust_escalation_paired
            && e.tool == ev.tool
            && e.action == ev.action
    });

    let deny_idx = deny_idx?;

    // Collect evidence: the deny event id + the current allow event id.
    let deny_event_id = window[deny_idx].event_id.clone();
    let deny_tool = window[deny_idx].tool.clone();
    let deny_action = window[deny_idx].action.clone();

    // Mark the deny as paired — prevents re-firing on subsequent allows for
    // the same (tool, action) without adding any new state.
    window[deny_idx].trust_escalation_paired = true;

    Some(Incident::new(
        &ev.occurred_at,
        &ev.tenant_id,
        &ev.agent_id,
        "trust_escalation",
        "high",
        format!(
            "Agent {} had a hard deny for {}.{} followed by an allow within {}s \
             — possible privilege-probing or trust manipulation",
            ev.agent_id, deny_tool, deny_action, TRUST_ESCALATION_WINDOW_SECS
        ),
        vec![deny_event_id, ev.event_id.clone()],
    ))
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
            redacted_fields: vec![],
            schema_version: 1,
            evidence: None,
        }
    }

    /// Like `make_event` but also sets the `action` field.
    fn make_event_with_action(
        event_id: &str,
        tenant_id: &str,
        agent_id: &str,
        decision: &str,
        occurred_at: &str,
        action: &str,
    ) -> AseEvent {
        AseEvent {
            event_id: event_id.to_string(),
            occurred_at: occurred_at.to_string(),
            tenant_id: tenant_id.to_string(),
            kind: "authorize_decision".to_string(),
            agent_id: agent_id.to_string(),
            decision: decision.to_string(),
            tool: "files".to_string(),
            action: action.to_string(),
            resource: None,
            risk_score: 60,
            reason: "test".to_string(),
            run_id: None,
            trace_id: None,
            matched_policies: vec![],
            redacted_fields: vec![],
            schema_version: 1,
            evidence: None,
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

    // ─── action_kind classifier ───────────────────────────────────────────────

    #[test]
    fn action_kind_classifies_sources_correctly() {
        // Plain source tokens.
        assert_eq!(
            action_kind("read_file"),
            ExfilRole::Source,
            "read_file → Source"
        );
        assert_eq!(
            action_kind("get_object"),
            ExfilRole::Source,
            "get_object → Source"
        );
        assert_eq!(
            action_kind("fetch_data"),
            ExfilRole::Source,
            "fetch_data → Source"
        );
        assert_eq!(
            action_kind("list_buckets"),
            ExfilRole::Source,
            "list_buckets → Source"
        );
        assert_eq!(
            action_kind("download_blob"),
            ExfilRole::Source,
            "download_blob → Source"
        );
        assert_eq!(
            action_kind("query_db"),
            ExfilRole::Source,
            "query_db → Source"
        );
        assert_eq!(
            action_kind("select_rows"),
            ExfilRole::Source,
            "select_rows → Source"
        );
        assert_eq!(
            action_kind("export_csv"),
            ExfilRole::Source,
            "export_csv → Source"
        );
        assert_eq!(
            action_kind("dump_table"),
            ExfilRole::Source,
            "dump_table → Source"
        );
        assert_eq!(action_kind("cat"), ExfilRole::Source, "cat → Source");
        // Case-insensitive.
        assert_eq!(
            action_kind("READ_FILE"),
            ExfilRole::Source,
            "READ_FILE → Source"
        );
        assert_eq!(
            action_kind("GetUser"),
            ExfilRole::Source,
            "GetUser → Source"
        );
    }

    #[test]
    fn action_kind_classifies_sinks_correctly() {
        assert_eq!(
            action_kind("send_message"),
            ExfilRole::Sink,
            "send_message → Sink"
        );
        assert_eq!(
            action_kind("post_webhook"),
            ExfilRole::Sink,
            "post_webhook → Sink"
        );
        assert_eq!(
            action_kind("upload_file"),
            ExfilRole::Sink,
            "upload_file → Sink"
        );
        assert_eq!(
            action_kind("email_report"),
            ExfilRole::Sink,
            "email_report → Sink"
        );
        assert_eq!(
            action_kind("call_webhook"),
            ExfilRole::Sink,
            "call_webhook → Sink"
        );
        assert_eq!(
            action_kind("push_notification"),
            ExfilRole::Sink,
            "push_notification → Sink"
        );
        assert_eq!(
            action_kind("publish_event"),
            ExfilRole::Sink,
            "publish_event → Sink"
        );
        assert_eq!(
            action_kind("write_external"),
            ExfilRole::Sink,
            "write_external → Sink"
        );
        assert_eq!(
            action_kind("share_document"),
            ExfilRole::Sink,
            "share_document → Sink"
        );
        assert_eq!(
            action_kind("transfer_file"),
            ExfilRole::Sink,
            "transfer_file → Sink"
        );
        assert_eq!(
            action_kind("exfil_data"),
            ExfilRole::Sink,
            "exfil_data → Sink"
        );
        assert_eq!(
            action_kind("http_post"),
            ExfilRole::Sink,
            "http_post → Sink"
        );
        // Case-insensitive.
        assert_eq!(
            action_kind("UPLOAD_FILE"),
            ExfilRole::Sink,
            "UPLOAD_FILE → Sink"
        );
        assert_eq!(
            action_kind("SendEmail"),
            ExfilRole::Sink,
            "SendEmail → Sink"
        );
    }

    #[test]
    fn action_kind_classifies_others_correctly() {
        assert_eq!(action_kind("approve"), ExfilRole::Other, "approve → Other");
        assert_eq!(
            action_kind("merge_pr"),
            ExfilRole::Other,
            "merge_pr → Other"
        );
        assert_eq!(
            action_kind("create_branch"),
            ExfilRole::Other,
            "create_branch → Other"
        );
        assert_eq!(action_kind(""), ExfilRole::Other, "empty → Other");
        assert_eq!(
            action_kind("unknown_action_xyz"),
            ExfilRole::Other,
            "unknown → Other"
        );
    }

    #[test]
    fn action_kind_sink_wins_over_source_for_ambiguous_names() {
        // "post_read_result" contains both "post" (Sink) and "read" (Source).
        // Sink must win (egress-safety rule: Sink tokens checked first).
        assert_eq!(
            action_kind("post_read_result"),
            ExfilRole::Sink,
            "when a name matches both Sink and Source, Sink must win"
        );
    }

    // ─── Rule D — data_exfil_pattern ─────────────────────────────────────────

    #[test]
    fn exfil_source_then_sink_in_window_fires_exactly_once() {
        // A Source (read_file) followed by a Sink (upload) within EXFIL_WINDOW_SECS
        // → exactly one data_exfil_pattern incident.
        let mut c = Correlator::default();

        let source_ev = make_event_with_action(
            "src_evt_1",
            "tenant_ex",
            "agent_ex",
            "allow",
            "2026-06-06T10:00:00Z",
            "read_file",
        );
        let sink_ev = make_event_with_action(
            "sink_evt_1",
            "tenant_ex",
            "agent_ex",
            "allow",
            "2026-06-06T10:00:30Z", // 30 s later, well within 120 s
            "upload",
        );

        let inc_source = c.observe(&source_ev);
        assert!(
            inc_source.iter().all(|i| i.kind != "data_exfil_pattern"),
            "Source event alone must not fire exfil"
        );

        let inc_sink = c.observe(&sink_ev);
        let exfil_incidents: Vec<_> = inc_sink
            .iter()
            .filter(|i| i.kind == "data_exfil_pattern")
            .collect();
        assert_eq!(
            exfil_incidents.len(),
            1,
            "exactly one data_exfil_pattern incident on the completing Sink event"
        );

        let inc = exfil_incidents[0];
        assert_eq!(inc.severity, "high");
        assert_eq!(inc.tenant_id, "tenant_ex");
        assert_eq!(inc.agent_id, "agent_ex");
        // Evidence must include both the source and sink event ids.
        assert!(
            inc.source_event_ids.contains(&"src_evt_1".to_string()),
            "source event id must be in evidence"
        );
        assert!(
            inc.source_event_ids.contains(&"sink_evt_1".to_string()),
            "sink event id must be in evidence"
        );
        assert_eq!(
            inc.source_event_ids.len(),
            2,
            "evidence has exactly two event ids"
        );
        // Summary names both actions and the agent.
        assert!(
            inc.summary.contains("read_file"),
            "summary names source action"
        );
        assert!(inc.summary.contains("upload"), "summary names sink action");
        assert!(inc.summary.contains("agent_ex"), "summary names agent");
    }

    #[test]
    fn exfil_sink_then_source_wrong_order_does_not_fire() {
        // Sink before Source — causal order violated, must not fire.
        let mut c = Correlator::default();

        let sink_ev = make_event_with_action(
            "sink_first",
            "tenant_ex2",
            "agent_ex2",
            "allow",
            "2026-06-06T10:00:00Z",
            "upload",
        );
        let source_ev = make_event_with_action(
            "src_after",
            "tenant_ex2",
            "agent_ex2",
            "allow",
            "2026-06-06T10:00:30Z",
            "read_file",
        );

        let inc1 = c.observe(&sink_ev);
        let inc2 = c.observe(&source_ev);
        let all: Vec<_> = inc1.iter().chain(inc2.iter()).collect();
        assert!(
            all.iter().all(|i| i.kind != "data_exfil_pattern"),
            "Sink-before-Source must not fire exfil pattern"
        );
    }

    #[test]
    fn exfil_source_only_does_not_fire() {
        let mut c = Correlator::default();
        let source_ev = make_event_with_action(
            "src_only",
            "tenant_ex3",
            "agent_ex3",
            "allow",
            "2026-06-06T10:00:00Z",
            "get_object",
        );
        let inc = c.observe(&source_ev);
        assert!(
            inc.iter().all(|i| i.kind != "data_exfil_pattern"),
            "Source-only must not fire"
        );
    }

    #[test]
    fn exfil_sink_only_does_not_fire() {
        let mut c = Correlator::default();
        let sink_ev = make_event_with_action(
            "sink_only",
            "tenant_ex4",
            "agent_ex4",
            "allow",
            "2026-06-06T10:00:00Z",
            "send_message",
        );
        let inc = c.observe(&sink_ev);
        assert!(
            inc.iter().all(|i| i.kind != "data_exfil_pattern"),
            "Sink-only must not fire"
        );
    }

    #[test]
    fn exfil_different_agents_same_tenant_do_not_pair() {
        // Agent A does Source, Agent B does Sink — must NOT pair across agents.
        let mut c = Correlator::default();

        let source_ev = make_event_with_action(
            "src_agent_a",
            "tenant_shared",
            "agent_A",
            "allow",
            "2026-06-06T10:00:00Z",
            "read_file",
        );
        let sink_ev = make_event_with_action(
            "sink_agent_b",
            "tenant_shared",
            "agent_B",
            "allow",
            "2026-06-06T10:00:10Z",
            "upload",
        );

        let inc1 = c.observe(&source_ev);
        let inc2 = c.observe(&sink_ev);
        let all: Vec<_> = inc1.iter().chain(inc2.iter()).collect();
        assert!(
            all.iter().all(|i| i.kind != "data_exfil_pattern"),
            "events from different agents must not produce an exfil incident"
        );
    }

    #[test]
    fn exfil_different_tenants_same_agent_do_not_pair() {
        // Tenant X has a Source; Tenant Y has a Sink — must NOT pair across tenants.
        let mut c = Correlator::default();

        let source_ev = make_event_with_action(
            "src_t1",
            "tenant_X",
            "shared_agent",
            "allow",
            "2026-06-06T10:00:00Z",
            "fetch_data",
        );
        let sink_ev = make_event_with_action(
            "sink_t2",
            "tenant_Y",
            "shared_agent",
            "allow",
            "2026-06-06T10:00:10Z",
            "upload",
        );

        let inc1 = c.observe(&source_ev);
        let inc2 = c.observe(&sink_ev);
        let all: Vec<_> = inc1.iter().chain(inc2.iter()).collect();
        assert!(
            all.iter().all(|i| i.kind != "data_exfil_pattern"),
            "events from different tenants must not produce an exfil incident"
        );
    }

    #[test]
    fn exfil_outside_window_does_not_fire() {
        // Source at T=0, Sink at T=EXFIL_WINDOW_SECS+1 — outside the window.
        let mut c = Correlator::default();

        let source_ev = make_event_with_action(
            "src_old",
            "tenant_ew",
            "agent_ew",
            "allow",
            "2026-06-06T10:00:00Z",
            "query_db",
        );
        // Sink is 121 s later — 1 s past the 120 s exfil window.
        // Note: MAX_WINDOW_SECS is 300 s so the entry is still in the outer
        // window but outside the exfil-specific cutoff.
        let sink_ev = make_event_with_action(
            "sink_late",
            "tenant_ew",
            "agent_ew",
            "allow",
            "2026-06-06T10:02:01Z", // 121 s after source
            "upload",
        );

        c.observe(&source_ev);
        let inc = c.observe(&sink_ev);
        assert!(
            inc.iter().all(|i| i.kind != "data_exfil_pattern"),
            "Source outside the exfil window must not pair with Sink"
        );
    }

    #[test]
    fn exfil_third_event_after_pair_does_not_re_fire() {
        // Source → Sink → another_allow: only one incident, no re-fire on the
        // third event.
        let mut c = Correlator::default();

        let source_ev = make_event_with_action(
            "src_v1",
            "tenant_nf",
            "agent_nf",
            "allow",
            "2026-06-06T10:00:00Z",
            "read_file",
        );
        let sink_ev = make_event_with_action(
            "sink_v1",
            "tenant_nf",
            "agent_nf",
            "allow",
            "2026-06-06T10:00:10Z",
            "upload",
        );
        // Third event: an unrelated allow that is not a Sink action.
        let other_ev = make_event_with_action(
            "other_v1",
            "tenant_nf",
            "agent_nf",
            "allow",
            "2026-06-06T10:00:20Z",
            "approve",
        );

        let inc1 = c.observe(&source_ev);
        let inc2 = c.observe(&sink_ev);
        let inc3 = c.observe(&other_ev);

        let exfil_count = inc1
            .iter()
            .chain(inc2.iter())
            .chain(inc3.iter())
            .filter(|i| i.kind == "data_exfil_pattern")
            .count();

        assert_eq!(
            exfil_count, 1,
            "exactly one exfil incident total; third event must not re-fire"
        );
    }

    #[test]
    fn exfil_second_sink_after_paired_does_not_re_fire_on_same_source() {
        // Source → Sink1 (fires) → Sink2 (no second incident from same source).
        let mut c = Correlator::default();

        let source_ev = make_event_with_action(
            "src_multi",
            "tenant_ms",
            "agent_ms",
            "allow",
            "2026-06-06T10:00:00Z",
            "list_files",
        );
        let sink_ev1 = make_event_with_action(
            "sink_multi_1",
            "tenant_ms",
            "agent_ms",
            "allow",
            "2026-06-06T10:00:10Z",
            "upload",
        );
        let sink_ev2 = make_event_with_action(
            "sink_multi_2",
            "tenant_ms",
            "agent_ms",
            "allow",
            "2026-06-06T10:00:20Z",
            "send_message",
        );

        let inc1 = c.observe(&source_ev);
        let inc2 = c.observe(&sink_ev1);
        let inc3 = c.observe(&sink_ev2);

        // Only one incident total (the Source was paired after the first Sink).
        let exfil_count = inc1
            .iter()
            .chain(inc2.iter())
            .chain(inc3.iter())
            .filter(|i| i.kind == "data_exfil_pattern")
            .count();

        assert_eq!(
            exfil_count, 1,
            "second Sink must not re-fire on an already-paired Source"
        );
    }

    // ─── Rule E — trust_escalation ───────────────────────────────────────────

    /// Build an event with explicit tool + action, for trust-escalation tests.
    fn make_te_event(
        event_id: &str,
        tenant_id: &str,
        agent_id: &str,
        decision: &str,
        occurred_at: &str,
        tool: &str,
        action: &str,
    ) -> AseEvent {
        AseEvent {
            event_id: event_id.to_string(),
            occurred_at: occurred_at.to_string(),
            tenant_id: tenant_id.to_string(),
            kind: "authorize_decision".to_string(),
            agent_id: agent_id.to_string(),
            decision: decision.to_string(),
            tool: tool.to_string(),
            action: action.to_string(),
            resource: None,
            risk_score: 80,
            reason: "test".to_string(),
            run_id: None,
            trace_id: None,
            matched_policies: vec![],
            redacted_fields: vec![],
            schema_version: 1,
            evidence: None,
        }
    }

    #[test]
    fn trust_escalation_deny_then_allow_same_tool_action_fires_exactly_once() {
        // Hard deny followed by allow for same (agent, tool, action) in-window
        // → exactly one trust_escalation incident.
        let mut c = Correlator::default();

        let deny_ev = make_te_event(
            "te_deny_1",
            "tenant_te",
            "agent_te",
            "deny",
            "2026-06-06T14:00:00Z",
            "github",
            "merge_pr",
        );
        let allow_ev = make_te_event(
            "te_allow_1",
            "tenant_te",
            "agent_te",
            "allow",
            "2026-06-06T14:01:00Z", // 60 s later, within 120 s window
            "github",
            "merge_pr",
        );

        let inc_deny = c.observe(&deny_ev);
        assert!(
            inc_deny.iter().all(|i| i.kind != "trust_escalation"),
            "deny event alone must not fire trust_escalation"
        );

        let inc_allow = c.observe(&allow_ev);
        let te_incidents: Vec<_> = inc_allow
            .iter()
            .filter(|i| i.kind == "trust_escalation")
            .collect();

        assert_eq!(
            te_incidents.len(),
            1,
            "exactly one trust_escalation incident on the completing allow event"
        );

        let inc = te_incidents[0];
        assert_eq!(inc.severity, "high");
        assert_eq!(inc.tenant_id, "tenant_te");
        assert_eq!(inc.agent_id, "agent_te");
        assert_eq!(inc.source_event_ids.len(), 2);
        assert!(
            inc.source_event_ids.contains(&"te_deny_1".to_string()),
            "deny event id must be in evidence"
        );
        assert!(
            inc.source_event_ids.contains(&"te_allow_1".to_string()),
            "allow event id must be in evidence"
        );
        // Summary names the agent and tool.action.
        assert!(inc.summary.contains("agent_te"), "summary names the agent");
        assert!(inc.summary.contains("github"), "summary names the tool");
        assert!(inc.summary.contains("merge_pr"), "summary names the action");
    }

    #[test]
    fn trust_escalation_require_approval_then_allow_is_legit_path_no_incident() {
        // require_approval → allow is the legitimate human-in-the-loop path;
        // must NOT fire trust_escalation (only a hard deny triggers).
        let mut c = Correlator::default();

        let ra_ev = make_te_event(
            "te_ra_1",
            "tenant_te2",
            "agent_te2",
            "require_approval",
            "2026-06-06T14:00:00Z",
            "github",
            "merge_pr",
        );
        let allow_ev = make_te_event(
            "te_allow_ra",
            "tenant_te2",
            "agent_te2",
            "allow",
            "2026-06-06T14:01:00Z",
            "github",
            "merge_pr",
        );

        let inc1 = c.observe(&ra_ev);
        let inc2 = c.observe(&allow_ev);
        let all: Vec<_> = inc1.iter().chain(inc2.iter()).collect();
        assert!(
            all.iter().all(|i| i.kind != "trust_escalation"),
            "require_approval → allow is the legit HITL path; must NOT fire trust_escalation"
        );
    }

    #[test]
    fn trust_escalation_allow_then_deny_wrong_order_no_incident() {
        // allow before deny — not the suspicious sequence; must not fire.
        let mut c = Correlator::default();

        let allow_ev = make_te_event(
            "te_allow_first",
            "tenant_te3",
            "agent_te3",
            "allow",
            "2026-06-06T14:00:00Z",
            "github",
            "merge_pr",
        );
        let deny_ev = make_te_event(
            "te_deny_after",
            "tenant_te3",
            "agent_te3",
            "deny",
            "2026-06-06T14:01:00Z",
            "github",
            "merge_pr",
        );

        let inc1 = c.observe(&allow_ev);
        let inc2 = c.observe(&deny_ev);
        let all: Vec<_> = inc1.iter().chain(inc2.iter()).collect();
        assert!(
            all.iter().all(|i| i.kind != "trust_escalation"),
            "allow→deny order must not fire trust_escalation"
        );
    }

    #[test]
    fn trust_escalation_deny_then_allow_different_tool_no_incident() {
        // Deny for tool A, allow for tool B — different tool; must not pair.
        let mut c = Correlator::default();

        let deny_ev = make_te_event(
            "te_deny_ta",
            "tenant_te4",
            "agent_te4",
            "deny",
            "2026-06-06T14:00:00Z",
            "github",
            "merge_pr",
        );
        let allow_ev = make_te_event(
            "te_allow_tb",
            "tenant_te4",
            "agent_te4",
            "allow",
            "2026-06-06T14:01:00Z",
            "jira", // different tool
            "merge_pr",
        );

        let inc1 = c.observe(&deny_ev);
        let inc2 = c.observe(&allow_ev);
        let all: Vec<_> = inc1.iter().chain(inc2.iter()).collect();
        assert!(
            all.iter().all(|i| i.kind != "trust_escalation"),
            "different tool must not pair for trust_escalation"
        );
    }

    #[test]
    fn trust_escalation_deny_then_allow_different_action_no_incident() {
        // Deny for action A, allow for action B — different action; must not pair.
        let mut c = Correlator::default();

        let deny_ev = make_te_event(
            "te_deny_aa",
            "tenant_te5",
            "agent_te5",
            "deny",
            "2026-06-06T14:00:00Z",
            "github",
            "merge_pr",
        );
        let allow_ev = make_te_event(
            "te_allow_ab",
            "tenant_te5",
            "agent_te5",
            "allow",
            "2026-06-06T14:01:00Z",
            "github",
            "create_branch", // different action
        );

        let inc1 = c.observe(&deny_ev);
        let inc2 = c.observe(&allow_ev);
        let all: Vec<_> = inc1.iter().chain(inc2.iter()).collect();
        assert!(
            all.iter().all(|i| i.kind != "trust_escalation"),
            "different action must not pair for trust_escalation"
        );
    }

    #[test]
    fn trust_escalation_different_agents_no_incident() {
        // Agent A gets a deny; Agent B gets an allow for same tool+action.
        // Must NOT pair — the deny-then-allow must be for the SAME agent.
        let mut c = Correlator::default();

        let deny_ev = make_te_event(
            "te_deny_agA",
            "tenant_te6",
            "agent_te6_A",
            "deny",
            "2026-06-06T14:00:00Z",
            "github",
            "merge_pr",
        );
        let allow_ev = make_te_event(
            "te_allow_agB",
            "tenant_te6",
            "agent_te6_B",
            "allow",
            "2026-06-06T14:01:00Z",
            "github",
            "merge_pr",
        );

        let inc1 = c.observe(&deny_ev);
        let inc2 = c.observe(&allow_ev);
        let all: Vec<_> = inc1.iter().chain(inc2.iter()).collect();
        assert!(
            all.iter().all(|i| i.kind != "trust_escalation"),
            "events from different agents must not produce trust_escalation"
        );
    }

    #[test]
    fn trust_escalation_different_tenants_no_incident() {
        // Tenant X agent gets a deny; Tenant Y same-name agent gets an allow.
        // Must NOT pair — isolated by (tenant_id, agent_id) window key.
        let mut c = Correlator::default();

        let deny_ev = make_te_event(
            "te_deny_tx",
            "tenant_X",
            "shared_agent",
            "deny",
            "2026-06-06T14:00:00Z",
            "github",
            "merge_pr",
        );
        let allow_ev = make_te_event(
            "te_allow_ty",
            "tenant_Y",
            "shared_agent",
            "allow",
            "2026-06-06T14:01:00Z",
            "github",
            "merge_pr",
        );

        let inc1 = c.observe(&deny_ev);
        let inc2 = c.observe(&allow_ev);
        let all: Vec<_> = inc1.iter().chain(inc2.iter()).collect();
        assert!(
            all.iter().all(|i| i.kind != "trust_escalation"),
            "events from different tenants must not produce trust_escalation"
        );
    }

    #[test]
    fn trust_escalation_outside_window_no_incident() {
        // Deny at T=0, allow at T=TRUST_ESCALATION_WINDOW_SECS+1 — outside window.
        let mut c = Correlator::default();

        let deny_ev = make_te_event(
            "te_deny_ow",
            "tenant_ow",
            "agent_ow",
            "deny",
            "2026-06-06T14:00:00Z",
            "github",
            "merge_pr",
        );
        // 121 s later — 1 s past the 120 s trust-escalation window.
        // MAX_WINDOW_SECS (300 s) keeps the entry in memory, but the
        // escalation-specific cutoff (120 s) must exclude it.
        let allow_ev = make_te_event(
            "te_allow_ow",
            "tenant_ow",
            "agent_ow",
            "allow",
            "2026-06-06T14:02:01Z", // 121 s after deny
            "github",
            "merge_pr",
        );

        c.observe(&deny_ev);
        let inc = c.observe(&allow_ev);
        assert!(
            inc.iter().all(|i| i.kind != "trust_escalation"),
            "deny outside the trust-escalation window must not pair with allow"
        );
    }

    #[test]
    fn trust_escalation_second_allow_after_pair_does_not_re_fire() {
        // deny → allow1 (fires) → allow2 (same tool+action): only one incident,
        // no re-fire because the deny is already paired.
        let mut c = Correlator::default();

        let deny_ev = make_te_event(
            "te_deny_nf",
            "tenant_nf2",
            "agent_nf2",
            "deny",
            "2026-06-06T14:00:00Z",
            "github",
            "merge_pr",
        );
        let allow_ev1 = make_te_event(
            "te_allow_nf1",
            "tenant_nf2",
            "agent_nf2",
            "allow",
            "2026-06-06T14:00:30Z",
            "github",
            "merge_pr",
        );
        let allow_ev2 = make_te_event(
            "te_allow_nf2",
            "tenant_nf2",
            "agent_nf2",
            "allow",
            "2026-06-06T14:01:00Z",
            "github",
            "merge_pr",
        );

        let inc1 = c.observe(&deny_ev);
        let inc2 = c.observe(&allow_ev1);
        let inc3 = c.observe(&allow_ev2);

        let te_count = inc1
            .iter()
            .chain(inc2.iter())
            .chain(inc3.iter())
            .filter(|i| i.kind == "trust_escalation")
            .count();

        assert_eq!(
            te_count, 1,
            "second allow must not re-fire on an already-paired deny"
        );
    }
}
