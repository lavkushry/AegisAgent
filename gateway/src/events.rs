//! Phase 0 — the Agent-SOC event stream (the keystone).
//!
//! After the inline `/v1/authorize` decision is recorded, the handler emits an
//! [`AseEvent`] (Agent Security Event) onto a bounded `tokio::mpsc` channel that
//! a background task drains. Emission is **non-blocking** ([`EventSink::emit`] uses
//! `try_send`): a full or closed channel is logged and dropped so the <75 ms
//! authorize hot path is never blocked (design law 3). Every later SOC phase
//! (detection, correlation, response, indexing) is a *consumer* of this one
//! stream and never touches the inline path again.

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, warn};

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
}

impl EventSink {
    /// Build a sink and its receiver. Production spawns [`drain`] on the
    /// receiver; tests keep it to assert exactly what was emitted.
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<AseEvent>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self { tx }, rx)
    }

    /// Emit one event. Never blocks and never propagates an error into the
    /// caller: a full or closed channel is logged and the event dropped, so the
    /// inline decision is unaffected (fail-open for *observability*, never for
    /// the security decision itself).
    pub fn emit(&self, event: AseEvent) {
        match self.tx.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(ev)) => {
                warn!(event_id = %ev.event_id, "SOC event stream full — dropping event");
            }
            Err(mpsc::error::TrySendError::Closed(ev)) => {
                debug!(event_id = %ev.event_id, "SOC event stream closed — dropping event");
            }
        }
    }
}

/// Background drain (the Phase 0 consumer). For now it only observes the stream;
/// Phases 1+ replace/extend this with detection, correlation, and indexing.
pub async fn drain(mut rx: mpsc::Receiver<AseEvent>) {
    while let Some(ev) = rx.recv().await {
        debug!(
            event_id = %ev.event_id,
            tenant = %ev.tenant_id,
            decision = %ev.decision,
            tool = %ev.tool,
            action = %ev.action,
            "ASE",
        );
    }
}
