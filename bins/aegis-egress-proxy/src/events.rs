//! Proxy-side event emission, mirroring the cage runner's sink pattern
//! (`bins/aegis-cage-runner/src/events.rs`): the proxy records what it
//! decided and observed through a pluggable [`ProxyEventSink`]. In gateway
//! mode the durable evidence (runtime events + receipts) is written by the
//! gateway inside `POST /v1/egress/check`; this local sink additionally
//! covers tunnel-time observations the gateway never sees at check time —
//! large uploads and SNI mismatches.

use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyEventType {
    EgressAllowed,
    EgressBlocked,
    LargeUpload,
    SniMismatch,
}

impl ProxyEventType {
    /// Matches the gateway's runtime-event ingest convention for the
    /// `egress` source component.
    pub fn as_event_type_str(&self) -> &'static str {
        match self {
            ProxyEventType::EgressAllowed => "egress_allowed",
            ProxyEventType::EgressBlocked => "egress_blocked",
            ProxyEventType::LargeUpload => "egress_large_upload",
            ProxyEventType::SniMismatch => "egress_sni_mismatch",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyEvent {
    pub event_type: ProxyEventType,
    pub host: String,
    pub port: u16,
    pub occurred_at: DateTime<Utc>,
    pub detail: Option<String>,
}

impl ProxyEvent {
    pub fn new(event_type: ProxyEventType, host: impl Into<String>, port: u16) -> Self {
        Self {
            event_type,
            host: host.into(),
            port,
            occurred_at: Utc::now(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

pub trait ProxyEventSink: Send + Sync {
    fn record(&self, event: ProxyEvent);
}

/// Drops every event. The explicit opt-out.
#[derive(Debug, Default)]
pub struct NullEventSink;

impl ProxyEventSink for NullEventSink {
    fn record(&self, _event: ProxyEvent) {}
}

/// Logs every event through `tracing` — the skeleton's production default
/// until the sensor-shipped event pipeline picks these up.
#[derive(Debug, Default)]
pub struct TracingEventSink;

impl ProxyEventSink for TracingEventSink {
    fn record(&self, event: ProxyEvent) {
        tracing::info!(
            event_type = event.event_type.as_event_type_str(),
            host = %event.host,
            port = event.port,
            detail = event.detail.as_deref().unwrap_or(""),
            "egress proxy event"
        );
    }
}

/// Captures events in memory, in emission order. Test instrumentation.
#[derive(Debug, Default)]
pub struct RecordingEventSink {
    inner: std::sync::Mutex<Vec<ProxyEvent>>,
}

impl RecordingEventSink {
    pub fn events(&self) -> Vec<ProxyEvent> {
        match self.inner.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl ProxyEventSink for RecordingEventSink {
    fn record(&self, event: ProxyEvent) {
        match self.inner.lock() {
            Ok(mut guard) => guard.push(event),
            Err(poisoned) => poisoned.into_inner().push(event),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_strings_match_the_gateway_runtime_event_ingest_convention() {
        assert_eq!(
            ProxyEventType::EgressAllowed.as_event_type_str(),
            "egress_allowed"
        );
        assert_eq!(
            ProxyEventType::EgressBlocked.as_event_type_str(),
            "egress_blocked"
        );
        assert_eq!(
            ProxyEventType::LargeUpload.as_event_type_str(),
            "egress_large_upload"
        );
        assert_eq!(
            ProxyEventType::SniMismatch.as_event_type_str(),
            "egress_sni_mismatch"
        );
    }

    #[test]
    fn recording_sink_keeps_events_in_emission_order() {
        let sink = RecordingEventSink::default();
        sink.record(ProxyEvent::new(
            ProxyEventType::EgressAllowed,
            "a.example",
            443,
        ));
        sink.record(
            ProxyEvent::new(ProxyEventType::LargeUpload, "a.example", 443)
                .with_detail("12345 bytes"),
        );
        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, ProxyEventType::EgressAllowed);
        assert_eq!(events[1].event_type, ProxyEventType::LargeUpload);
        assert_eq!(events[1].detail.as_deref(), Some("12345 bytes"));
    }

    #[test]
    fn null_sink_drops_events_without_panicking() {
        NullEventSink.record(ProxyEvent::new(
            ProxyEventType::EgressBlocked,
            "b.example",
            443,
        ));
    }
}
