//! Phase 4.4 (Agent Cage): the sandbox runtime-event stream.
//!
//! `docs/AegisAgent_Agent_Cage.md` requires runtime telemetry to reach the
//! gateway only by way of `aegis-node-sensor`
//! ("Sandbox --> Telemetry --> Sensor --> Gateway") — the cage runner never
//! talks to the gateway directly. This module defines that event stream's
//! shape and the [`CageEventSink`] trait a [`crate::runtime::SandboxRuntime`]
//! emits it through. The concrete transport that hands these off to the
//! sensor is later wiring, not this skeleton's job; [`RecordingEventSink`]
//! is what today's tests (and any in-process caller) inspect.

use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CageEventType {
    AgentRunStarted,
    ProcessStarted,
    ProcessExited,
    AgentRunFinished,
}

impl CageEventType {
    /// The `event_type` string the gateway's runtime-event ingest
    /// (`POST /v1/ingest/runtime-events`) and per-run timeline
    /// (`GET /v1/runtime/runs/:id/events`) expect.
    pub fn as_event_type_str(self) -> &'static str {
        match self {
            CageEventType::AgentRunStarted => "agent_run_started",
            CageEventType::ProcessStarted => "process_started",
            CageEventType::ProcessExited => "process_exited",
            CageEventType::AgentRunFinished => "agent_run_finished",
        }
    }
}

/// One runtime-event-stream entry. Always tagged with the owning tenant,
/// run, and sandbox — the gateway timeline is keyed on `run_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageEvent {
    pub event_type: CageEventType,
    pub tenant_id: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub occurred_at: DateTime<Utc>,
    /// Set only on `ProcessExited`, and only when the backend can report
    /// one — `None` for a signal-killed process (Docker's `kill` doesn't
    /// surface an exit code) or any other event type.
    pub exit_code: Option<i32>,
}

impl CageEvent {
    pub fn new(event_type: CageEventType, tenant_id: &str, run_id: &str, sandbox_id: &str) -> Self {
        Self {
            event_type,
            tenant_id: tenant_id.to_string(),
            run_id: run_id.to_string(),
            sandbox_id: sandbox_id.to_string(),
            occurred_at: Utc::now(),
            exit_code: None,
        }
    }

    pub fn with_exit_code(mut self, exit_code: Option<i32>) -> Self {
        self.exit_code = exit_code;
        self
    }
}

/// Where a runtime hands off the events it emits. Kept separate from
/// `SandboxRuntime` itself so a backend never has to know or care how (or
/// whether) events actually leave the process — swap sinks, not runtimes.
/// Synchronous and infallible by design: emitting telemetry must never
/// block or fail a sandbox lifecycle operation.
pub trait CageEventSink: Send + Sync {
    fn record(&self, event: CageEvent);
}

/// The default sink: drops every event. Used whenever no telemetry
/// destination is configured — this is best-effort observability, not an
/// authorization control, so a missing sink must not affect sandbox
/// behavior.
#[derive(Debug, Default)]
pub struct NullEventSink;

impl CageEventSink for NullEventSink {
    fn record(&self, _event: CageEvent) {}
}

/// An in-memory sink that keeps every event it's given, oldest first.
#[derive(Debug, Default)]
pub struct RecordingEventSink {
    events: Mutex<Vec<CageEvent>>,
}

impl RecordingEventSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// A snapshot of every event recorded so far, oldest first — the
    /// timeline a run's evidence trail is built from.
    pub fn events(&self) -> Vec<CageEvent> {
        self.events.lock().unwrap().clone()
    }
}

impl CageEventSink for RecordingEventSink {
    fn record(&self, event: CageEvent) {
        self.events.lock().unwrap().push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_sink_keeps_events_in_emission_order_tagged_with_run_and_sandbox() {
        let sink = RecordingEventSink::new();
        sink.record(CageEvent::new(
            CageEventType::AgentRunStarted,
            "tenant_a",
            "run_1",
            "sandbox_1",
        ));
        sink.record(CageEvent::new(
            CageEventType::ProcessStarted,
            "tenant_a",
            "run_1",
            "sandbox_1",
        ));
        sink.record(
            CageEvent::new(
                CageEventType::ProcessExited,
                "tenant_a",
                "run_1",
                "sandbox_1",
            )
            .with_exit_code(Some(0)),
        );
        sink.record(CageEvent::new(
            CageEventType::AgentRunFinished,
            "tenant_a",
            "run_1",
            "sandbox_1",
        ));

        let events = sink.events();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].event_type, CageEventType::AgentRunStarted);
        assert_eq!(events[1].event_type, CageEventType::ProcessStarted);
        assert_eq!(events[2].event_type, CageEventType::ProcessExited);
        assert_eq!(events[2].exit_code, Some(0));
        assert_eq!(events[3].event_type, CageEventType::AgentRunFinished);
        for event in &events {
            assert_eq!(event.tenant_id, "tenant_a");
            assert_eq!(event.run_id, "run_1");
            assert_eq!(event.sandbox_id, "sandbox_1");
        }
    }

    #[test]
    fn null_sink_drops_events_without_panicking() {
        let sink = NullEventSink;
        sink.record(CageEvent::new(
            CageEventType::AgentRunStarted,
            "tenant_a",
            "run_1",
            "sandbox_1",
        ));
    }

    #[test]
    fn event_type_strings_match_the_gateway_runtime_event_ingest_convention() {
        assert_eq!(
            CageEventType::AgentRunStarted.as_event_type_str(),
            "agent_run_started"
        );
        assert_eq!(
            CageEventType::ProcessStarted.as_event_type_str(),
            "process_started"
        );
        assert_eq!(
            CageEventType::ProcessExited.as_event_type_str(),
            "process_exited"
        );
        assert_eq!(
            CageEventType::AgentRunFinished.as_event_type_str(),
            "agent_run_finished"
        );
    }
}
