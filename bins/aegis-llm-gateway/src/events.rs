//! Local model-call event sink (started / finished).
//!
//! Event type strings match the world-class LLD runtime event vocabulary
//! (`model_call_started`, `model_call_finished`, `prompt_observed` in
//! `docs/AegisAgent_World_Class_LLD.md`).

use chrono::{DateTime, Utc};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelCallEventType {
    PromptObserved,
    ModelCallStarted,
    ModelCallFinished,
}

impl ModelCallEventType {
    pub fn as_event_type_str(&self) -> &'static str {
        match self {
            ModelCallEventType::PromptObserved => "prompt_observed",
            ModelCallEventType::ModelCallStarted => "model_call_started",
            ModelCallEventType::ModelCallFinished => "model_call_finished",
        }
    }
}

/// Lineage-only model-call observation. Never carries raw prompt/response
/// bodies — only hashes, metadata, and (optionally) a redacted preview.
#[derive(Debug, Clone)]
pub struct ModelCallEvent {
    pub event_type: ModelCallEventType,
    pub event_id: String,
    pub provider: String,
    pub model: String,
    pub status: Option<String>,
    pub request_hash: Option<String>,
    pub response_hash: Option<String>,
    pub prompt_hash: Option<String>,
    pub redacted_prompt_preview: Option<String>,
    pub token_counts: Option<Value>,
    /// Failure detail after redaction. Must never contain secret-shaped text.
    pub detail: Option<String>,
    pub run_id: Option<String>,
    pub trace_id: Option<String>,
    pub occurred_at: DateTime<Utc>,
}

impl ModelCallEvent {
    pub fn started(
        event_id: impl Into<String>,
        provider: impl Into<String>,
        model: impl Into<String>,
        request_hash: impl Into<String>,
    ) -> Self {
        Self {
            event_type: ModelCallEventType::ModelCallStarted,
            event_id: event_id.into(),
            provider: provider.into(),
            model: model.into(),
            status: None,
            request_hash: Some(request_hash.into()),
            response_hash: None,
            prompt_hash: None,
            redacted_prompt_preview: None,
            token_counts: None,
            detail: None,
            run_id: None,
            trace_id: None,
            occurred_at: Utc::now(),
        }
    }

    pub fn finished(
        event_id: impl Into<String>,
        provider: impl Into<String>,
        model: impl Into<String>,
        status: impl Into<String>,
    ) -> Self {
        Self {
            event_type: ModelCallEventType::ModelCallFinished,
            event_id: event_id.into(),
            provider: provider.into(),
            model: model.into(),
            status: Some(status.into()),
            request_hash: None,
            response_hash: None,
            prompt_hash: None,
            redacted_prompt_preview: None,
            token_counts: None,
            detail: None,
            run_id: None,
            trace_id: None,
            occurred_at: Utc::now(),
        }
    }

    pub fn with_request_hash(mut self, hash: impl Into<String>) -> Self {
        self.request_hash = Some(hash.into());
        self
    }

    pub fn with_response_hash(mut self, hash: impl Into<String>) -> Self {
        self.response_hash = Some(hash.into());
        self
    }

    pub fn with_token_counts(mut self, counts: Value) -> Self {
        self.token_counts = Some(counts);
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_run_id(mut self, run_id: Option<String>) -> Self {
        self.run_id = run_id;
        self
    }

    pub fn with_trace_id(mut self, trace_id: Option<String>) -> Self {
        self.trace_id = trace_id;
        self
    }

    pub fn with_prompt_hash(mut self, hash: impl Into<String>) -> Self {
        self.prompt_hash = Some(hash.into());
        self
    }

    pub fn with_redacted_preview(mut self, preview: impl Into<String>) -> Self {
        self.redacted_prompt_preview = Some(preview.into());
        self
    }
}

pub trait ModelCallEventSink: Send + Sync {
    fn record(&self, event: ModelCallEvent);
}

/// Drops every event. Explicit opt-out.
#[derive(Debug, Default)]
pub struct NullEventSink;

impl ModelCallEventSink for NullEventSink {
    fn record(&self, _event: ModelCallEvent) {}
}

/// Logs every event through `tracing` — production default when no other
/// sink is configured.
#[derive(Debug, Default)]
pub struct TracingEventSink;

impl ModelCallEventSink for TracingEventSink {
    fn record(&self, event: ModelCallEvent) {
        tracing::info!(
            event_type = event.event_type.as_event_type_str(),
            event_id = %event.event_id,
            provider = %event.provider,
            model = %event.model,
            status = event.status.as_deref().unwrap_or(""),
            request_hash = event.request_hash.as_deref().unwrap_or(""),
            response_hash = event.response_hash.as_deref().unwrap_or(""),
            detail = event.detail.as_deref().unwrap_or(""),
            "llm gateway event"
        );
    }
}

/// Captures events in memory, in emission order. Test instrumentation.
#[derive(Debug, Default)]
pub struct RecordingEventSink {
    inner: std::sync::Mutex<Vec<ModelCallEvent>>,
}

impl RecordingEventSink {
    pub fn events(&self) -> Vec<ModelCallEvent> {
        match self.inner.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl ModelCallEventSink for RecordingEventSink {
    fn record(&self, event: ModelCallEvent) {
        match self.inner.lock() {
            Ok(mut guard) => guard.push(event),
            Err(poisoned) => poisoned.into_inner().push(event),
        }
    }
}

/// Fan-out sink: records to every child. Used to pair tracing + gateway ship.
pub struct FanoutEventSink {
    sinks: Vec<Box<dyn ModelCallEventSink>>,
}

impl FanoutEventSink {
    pub fn new(sinks: Vec<Box<dyn ModelCallEventSink>>) -> Self {
        Self { sinks }
    }
}

impl ModelCallEventSink for FanoutEventSink {
    fn record(&self, event: ModelCallEvent) {
        for sink in &self.sinks {
            sink.record(event.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_strings_match_lld_vocabulary() {
        assert_eq!(
            ModelCallEventType::ModelCallStarted.as_event_type_str(),
            "model_call_started"
        );
        assert_eq!(
            ModelCallEventType::ModelCallFinished.as_event_type_str(),
            "model_call_finished"
        );
        assert_eq!(
            ModelCallEventType::PromptObserved.as_event_type_str(),
            "prompt_observed"
        );
    }

    #[test]
    fn recording_sink_keeps_started_then_finished_order() {
        let sink = RecordingEventSink::default();
        sink.record(ModelCallEvent::started(
            "e1",
            "openai",
            "gpt-4o-mini",
            "a".repeat(64),
        ));
        sink.record(
            ModelCallEvent::finished("e1", "openai", "gpt-4o-mini", "success")
                .with_response_hash("b".repeat(64))
                .with_token_counts(
                    serde_json::json!({"prompt_tokens": 10, "completion_tokens": 5}),
                ),
        );
        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, ModelCallEventType::ModelCallStarted);
        assert_eq!(events[1].event_type, ModelCallEventType::ModelCallFinished);
        assert_eq!(events[1].status.as_deref(), Some("success"));
        assert!(events[1].token_counts.is_some());
    }
}
