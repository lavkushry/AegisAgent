//! Phase 0 — the Agent-SOC event stream (the keystone).
//!
//! After the inline `/v1/authorize` decision is recorded, the handler emits an
//! [`AseEvent`] (Agent Security Event) onto a bounded `tokio::mpsc` channel that
//! a background task drains. Emission is **non-blocking** ([`EventSink::emit`] uses
//! `try_send`): a full or closed channel is logged and dropped so the <75 ms
//! authorize hot path is never blocked (design law 3). Every later SOC phase
//! (detection, correlation, response, indexing) is a *consumer* of this one
//! stream and never touches the inline path again.

use crate::baseline;
use crate::correlate::Correlator;
use crate::db;
use crate::detect::Detector;
use crate::models::{AuditEventRecord, SocAlertRecord, SocIncidentRecord};
use crate::notify::{self, NotifyMessage, NotifySink};
use crate::respond;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Default in-memory buffer for the SOC event channel.
pub const DEFAULT_CAPACITY: usize = 1024;

/// An Agent Security Event — the unit the SOC plane consumes. v0 schema: a
/// normalized record of one authorize decision. Carries no secrets (the moat's
/// redaction rule); identifiers and the decision only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AseEvent {
    /// Unique id for this event (not the decision id).
    pub event_id: String,
    /// RFC 3339 UTC timestamp the event was produced.
    pub occurred_at: String,
    /// Owning tenant — every consumer stays tenant-scoped.
    pub tenant_id: String,
    /// Event class. Phase 0 emits only `"authorize_decision"`.
    pub kind: String,
    pub agent_id: String,
    /// `allow` | `deny` | `require_approval` (mirrors the inline decision).
    pub decision: String,
    pub tool: String,
    pub action: String,
    pub resource: Option<String>,
    /// Advisory risk score (metadata only — never gates; design law 1).
    pub risk_score: i32,
    pub reason: String,
    pub run_id: Option<String>,
    pub trace_id: Option<String>,
    pub matched_policies: Vec<String>,
}

/// Non-blocking handle the authorize hot path holds to feed the SOC stream.
/// Cloneable so future inline call-sites can share one sink.
#[derive(Clone)]
pub struct EventSink {
    tx: mpsc::Sender<AseEvent>,
    tx_broadcast: tokio::sync::broadcast::Sender<AseEvent>,
    metrics: std::sync::Arc<crate::metrics::SecurityMetrics>,
}

impl EventSink {
    /// Build a sink and its receiver. Production spawns [`drain`] on the
    /// receiver; tests keep it to assert exactly what was emitted. `metrics`
    /// is shared with [`drain`] and `AppState` so `aegis_events_emitted_total`
    /// / `aegis_events_dropped_total` (OBS-002, #1155) reflect this sink.
    pub fn channel(
        capacity: usize,
        metrics: std::sync::Arc<crate::metrics::SecurityMetrics>,
    ) -> (Self, mpsc::Receiver<AseEvent>) {
        let (tx, rx) = mpsc::channel(capacity);
        let (tx_broadcast, _) = tokio::sync::broadcast::channel(capacity);
        (
            Self {
                tx,
                tx_broadcast,
                metrics,
            },
            rx,
        )
    }

    /// Subscribe to live events.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<AseEvent> {
        self.tx_broadcast.subscribe()
    }

    /// Emit one event. Never blocks and never propagates an error into the
    /// caller: a full or closed channel is logged and the event dropped, so the
    /// inline decision is unaffected (fail-open for *observability*, never for
    /// the security decision itself).
    pub fn emit(&self, event: AseEvent) {
        // Broadcast the event to any active subscribers (WebSockets)
        let _ = self.tx_broadcast.send(event.clone());

        match self.tx.try_send(event) {
            Ok(()) => {
                self.metrics.inc_event_emitted();
            }
            Err(mpsc::error::TrySendError::Full(ev)) => {
                self.metrics.inc_event_dropped();
                warn!(event_id = %ev.event_id, "SOC event stream full — dropping event");
            }
            Err(mpsc::error::TrySendError::Closed(ev)) => {
                self.metrics.inc_event_dropped();
                debug!(event_id = %ev.event_id, "SOC event stream closed — dropping event");
            }
        }
    }
}

/// Background drain (Phase 0 consumer + Phase 1 detection + Phase 2 notify +
/// Phase 3 correlation + Phase 5 indexing).
///
/// Observes the stream, runs the deterministic [`Detector`] over each event,
/// feeds high-signal events and alerts to the out-of-band [`NotifySink`]
/// (Phase 2), runs the stateful [`Correlator`] for multi-event pattern detection
/// (Phase 3), and persists alerts + incidents to `soc_alerts`/`soc_incidents`
/// (Phase 5). All of this is out-of-band (design law 3): the inline authorize
/// budget is never touched.
///
/// ## Notify trigger policy (high-signal only, no spam)
///
/// * `deny` decision → notify (every denied action is SOC-visible).
/// * `require_approval` decision → notify (human-in-the-loop gate opened).
/// * HIGH-severity alert/incident → notify (active threat pattern detected).
/// * `allow` decision → NOT notified (no noise).
/// * INFO-severity alert/incident → NOT notified (logged only).
///
/// ## Persistence (Phase 5)
///
/// Alerts and incidents are inserted via [`db::insert_soc_alert`] /
/// [`db::insert_soc_incident`] on every event loop iteration. Errors are logged
/// and discarded; the drain loop never panics or aborts on a DB failure (design
/// law 3 — out-of-band best-effort). Secrets are never stored: only ids,
/// summaries, and severity (redaction invariant).
/// Log, notify (HIGH only), and persist (Phase 5) one detection alert —
/// shared by Phase 1 ([`Detector`]) and SOC-007 ([`baseline`]) alerts.
/// Best-effort: a persistence error is logged and never panics or aborts the
/// drain loop (design law 3).
async fn handle_alert(
    alert: &crate::detect::Alert,
    sink: &dyn NotifySink,
    pool: &SqlitePool,
    notify_enabled: bool,
) {
    match alert.severity.as_str() {
        "high" => {
            warn!(
                alert_id = %alert.alert_id,
                rule = %alert.rule,
                severity = %alert.severity,
                tenant = %alert.tenant_id,
                agent = %alert.agent_id,
                source_event_id = %alert.source_event_id,
                summary = %alert.summary,
                "SOC alert",
            );
            // Phase 2 — alert notify: HIGH alerts only. SOC-002 (#1185): suppressed
            // entirely at autonomy level L0 (log-only).
            if notify_enabled {
                sink.notify(NotifyMessage {
                    kind: "alert".to_string(),
                    severity: alert.severity.clone(),
                    tenant_id: alert.tenant_id.clone(),
                    agent_id: alert.agent_id.clone(),
                    summary: alert.summary.clone(),
                    alert_or_incident_id: Some(alert.alert_id.clone()),
                    occurred_at: alert.occurred_at.clone(),
                });
            }
        }
        _ => info!(
            alert_id = %alert.alert_id,
            rule = %alert.rule,
            severity = %alert.severity,
            tenant = %alert.tenant_id,
            agent = %alert.agent_id,
            source_event_id = %alert.source_event_id,
            summary = %alert.summary,
            "SOC alert",
        ),
    }

    // Phase 5 — persist the alert (best-effort; never panics on failure).
    let alert_record = SocAlertRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: alert.tenant_id.clone(),
        rule: alert.rule.clone(),
        severity: alert.severity.clone(),
        agent_id: alert.agent_id.clone(),
        source_event_id: alert.source_event_id.clone(),
        summary: alert.summary.clone(),
        created_at: alert.occurred_at.clone(),
    };
    if let Err(e) = db::insert_soc_alert(pool, &alert_record).await {
        error!(
            alert_id = %alert.alert_id,
            "Phase 5: failed to persist SOC alert: {:?}", e
        );
    }
}

pub async fn drain(
    mut rx: mpsc::Receiver<AseEvent>,
    pool: SqlitePool,
    metrics: std::sync::Arc<crate::metrics::SecurityMetrics>,
) -> usize {
    let detector = Detector::default();
    // Phase 2: construct the notify sink once from env; NullSink when
    // AEGIS_WEBHOOK_URL is absent (safe default — no network calls in tests).
    let sink: Box<dyn NotifySink> = notify::from_env();
    // Phase 3: one Correlator per drain task — mutable, bounded-memory sliding
    // windows keyed by (tenant_id, agent_id). Never touches the inline path.
    let mut correlator = Correlator::default();
    let mut count = 0;

    while let Some(ev) = rx.recv().await {
        count += 1;
        debug!(
            event_id = %ev.event_id,
            tenant = %ev.tenant_id,
            decision = %ev.decision,
            tool = %ev.tool,
            action = %ev.action,
            "ASE",
        );

        // SOC-002 (#1185): resolve the SOC Response Engine's autonomy level for
        // this event's tenant. L0 (log-only) suppresses all notifications and
        // auto-response below; L1-L2 suppress auto-response (dispatch); L3-L4
        // run dispatch, with L4 suppressing the resulting notifications.
        let autonomy = db::get_soc_autonomy_level(&pool, &ev.tenant_id).await;
        let notify_enabled = autonomy != "L0";

        // Phase 2 — decision notify: deny and require_approval are high-signal.
        // allow is intentionally excluded to avoid alert fatigue.
        if notify_enabled && (ev.decision == "deny" || ev.decision == "require_approval") {
            sink.notify(NotifyMessage {
                kind: ev.kind.clone(),
                severity: "high".to_string(),
                tenant_id: ev.tenant_id.clone(),
                agent_id: ev.agent_id.clone(),
                summary: format!(
                    "decision={} tool={} action={} reason={}",
                    ev.decision, ev.tool, ev.action, ev.reason
                ),
                alert_or_incident_id: None,
                occurred_at: ev.occurred_at.clone(),
            });
        }

        // Phase 1: deterministic, atomic detection over the single event.
        for alert in detector.evaluate(&ev) {
            handle_alert(&alert, sink.as_ref(), &pool, notify_enabled).await;
        }

        // SOC-007 (#1190): per-agent behavioral baselining (rate anomaly +
        // first-use-of-tool). Runs after Phase 1 — out-of-band (Law 3).
        match baseline::evaluate(&pool, &ev).await {
            Ok(baseline_alerts) => {
                for alert in baseline_alerts {
                    handle_alert(&alert, sink.as_ref(), &pool, notify_enabled).await;
                }
            }
            Err(e) => {
                error!(
                    event_id = %ev.event_id,
                    "SOC-007: behavioral baseline evaluation failed: {:?}", e
                );
            }
        }

        // Phase 3: stateful, multi-event correlation (deny_storm / runaway /
        // repeated_approval). Runs after Phase 1 — both are out-of-band (Law 3).
        for incident in correlator.observe(&ev) {
            // Phase 5 — persist the incident (best-effort; never panics on failure).
            // source_event_ids is serialised to JSON so the column stores structured
            // evidence without SQL concatenation (redaction + parameterization).
            // SOC-005 (#1188): repeat incidents for the same (tenant, agent, kind)
            // within the dedup window are merged into the existing open incident
            // rather than creating a new row.
            let source_ids_json = serde_json::to_string(&incident.source_event_ids)
                .unwrap_or_else(|_| "[]".to_string());
            let incident_record = SocIncidentRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: incident.tenant_id.clone(),
                kind: incident.kind.clone(),
                severity: incident.severity.clone(),
                agent_id: incident.agent_id.clone(),
                summary: incident.summary.clone(),
                source_event_ids: source_ids_json,
                opened_at: incident.opened_at.clone(),
                // Lifecycle defaults — the DB INSERT always writes 'open'/NULL regardless
                // of these struct fields; they exist to satisfy the type.
                status: "open".to_string(),
                closed_at: None,
            };
            let mut was_merged = false;
            match db::upsert_soc_incident(&pool, &incident_record).await {
                Ok(db::IncidentUpsertResult::Merged { id }) => {
                    was_merged = true;
                    debug!(
                        incident_id = %incident.incident_id,
                        merged_into = %id,
                        "SOC-005: merged repeat incident into existing open incident",
                    );
                }
                Ok(db::IncidentUpsertResult::Inserted) => {}
                Err(e) => {
                    error!(
                        incident_id = %incident.incident_id,
                        "Phase 5: failed to persist SOC incident: {:?}", e
                    );
                }
            }

            match incident.severity.as_str() {
                "high" => {
                    warn!(
                        incident_id = %incident.incident_id,
                        kind = %incident.kind,
                        severity = %incident.severity,
                        tenant = %incident.tenant_id,
                        agent = %incident.agent_id,
                        contributing_events = ?incident.source_event_ids.len(),
                        summary = %incident.summary,
                        merged = was_merged,
                        "SOC incident",
                    );
                    // Phase 2 — incident notify: HIGH incidents only. SOC-005
                    // (#1188): suppressed for repeat incidents merged into an
                    // already-notified open incident (no alert fatigue).
                    if !was_merged {
                        sink.notify(NotifyMessage {
                            kind: "incident".to_string(),
                            severity: incident.severity.clone(),
                            tenant_id: incident.tenant_id.clone(),
                            agent_id: incident.agent_id.clone(),
                            summary: incident.summary.clone(),
                            alert_or_incident_id: Some(incident.incident_id.clone()),
                            occurred_at: incident.opened_at.clone(),
                        });
                    }
                }
                _ => info!(
                    incident_id = %incident.incident_id,
                    kind = %incident.kind,
                    severity = %incident.severity,
                    tenant = %incident.tenant_id,
                    agent = %incident.agent_id,
                    contributing_events = ?incident.source_event_ids.len(),
                    summary = %incident.summary,
                    merged = was_merged,
                    "SOC incident",
                ),
            }

            // Phase 4 — Response Engine auto-dispatch (#1184). Best-effort:
            // a DB error here is logged and never panics or aborts the drain
            // loop (design law 3, out-of-band).
            match respond::dispatch(&pool, &incident).await {
                Ok(Some(action)) => {
                    warn!(
                        incident_id = %incident.incident_id,
                        action = %action.action,
                        "SOC response: {}", action.description,
                    );

                    // L4 (auto-respond + silent) suppresses the response notification.
                    if autonomy == "L3" && action.critical_notify {
                        sink.notify(NotifyMessage {
                            kind: "response".to_string(),
                            severity: "critical".to_string(),
                            tenant_id: incident.tenant_id.clone(),
                            agent_id: incident.agent_id.clone(),
                            summary: action.description.clone(),
                            alert_or_incident_id: Some(incident.incident_id.clone()),
                            occurred_at: incident.opened_at.clone(),
                        });
                    }

                    let audit_record = AuditEventRecord {
                        id: Uuid::new_v4().to_string(),
                        tenant_id: incident.tenant_id.clone(),
                        event_type: "soc_response".to_string(),
                        agent_id: Some(incident.agent_id.clone()),
                        user_id: None,
                        run_id: None,
                        trace_id: None,
                        span_id: None,
                        skill: None,
                        action: Some(action.action.clone()),
                        resource: Some(incident.incident_id.clone()),
                        event_json: action.description.clone(),
                        input_hash: None,
                        output_hash: None,
                        created_at: chrono::Utc::now(),
                    };
                    if let Err(e) = db::insert_audit_event(&pool, &audit_record).await {
                        error!(
                            incident_id = %incident.incident_id,
                            "Phase 4: failed to persist SOC response audit event: {:?}", e
                        );
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    error!(
                        incident_id = %incident.incident_id,
                        "Phase 4: response dispatch failed: {:?}", e
                    );
                }
            }
        }
    }
    count
}
