//! Reverse-proxy loop: accept OpenAI-compatible requests, capture lineage,
//! forward to upstream, return the provider response.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use bytes::Bytes;
use chrono::Utc;
use uuid::Uuid;

use crate::capture::{
    normalize_status, parse_request_meta, parse_response_meta, safe_failure_detail,
    safe_prompt_preview, sha256_hex,
};
use crate::events::{ModelCallEvent, ModelCallEventSink, ModelCallEventType};
use crate::gateway_client::{
    LineageClient, ModelCallIngestPayload, PromptEventIngestPayload,
};

/// Shared proxy configuration + collaborators.
#[derive(Clone)]
pub struct ProxyState {
    pub upstream_base: String,
    pub provider: String,
    pub run_id: Option<String>,
    pub trace_id: Option<String>,
    pub source_trust: Option<String>,
    /// When true (default), also emit a prompt lineage event for the
    /// concatenated message contents.
    pub capture_prompts: bool,
    pub http: reqwest::Client,
    pub sink: Arc<dyn ModelCallEventSink>,
    pub lineage: Arc<dyn LineageClient>,
}

impl ProxyState {
    pub fn router(self) -> Router {
        Router::new()
            .route("/", any(proxy_handler))
            .route("/*path", any(proxy_handler))
            .with_state(Arc::new(self))
    }
}

async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match handle_request(state, method, uri, headers, body).await {
        Ok(response) => response,
        Err((status, message)) => (status, message).into_response(),
    }
}

async fn handle_request(
    state: Arc<ProxyState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, (StatusCode, String)> {
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(uri.path());
    let upstream_url = format!(
        "{}{}",
        state.upstream_base.trim_end_matches('/'),
        path_and_query
    );

    let is_model_call = method == Method::POST && looks_like_model_call(uri.path(), &body);
    let call_ctx = if is_model_call {
        Some(begin_capture(&state, &body).await)
    } else {
        None
    };

    let mut req = state.http.request(method.clone(), &upstream_url);
    // Forward hop-safe headers; drop hop-by-hop and host (reqwest sets Host).
    for (name, value) in headers.iter() {
        if is_hop_by_hop(name.as_str()) || name == http::header::HOST {
            continue;
        }
        req = req.header(name, value);
    }
    if !body.is_empty() {
        req = req.body(body.clone());
    }

    let started_at = call_ctx.as_ref().map(|c| c.started_at);
    let upstream_result = req.send().await;

    match upstream_result {
        Ok(upstream) => {
            let status = upstream.status();
            let resp_headers = upstream.headers().clone();
            let resp_bytes = upstream
                .bytes()
                .await
                .map_err(|e| (StatusCode::BAD_GATEWAY, format!("upstream body: {e}")))?;

            if let Some(ctx) = call_ctx {
                finish_capture(
                    &state,
                    ctx,
                    if status.is_success() {
                        Ok(&resp_bytes)
                    } else {
                        Err(format!(
                            "upstream status {status}: {}",
                            String::from_utf8_lossy(&resp_bytes)
                        ))
                    },
                    started_at.unwrap_or_else(Utc::now),
                )
                .await;
            }

            let mut builder = Response::builder().status(status);
            for (name, value) in resp_headers.iter() {
                if is_hop_by_hop(name.as_str()) {
                    continue;
                }
                builder = builder.header(name, value);
            }
            builder
                .body(Body::from(resp_bytes))
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
        Err(err) => {
            if let Some(ctx) = call_ctx {
                finish_capture(
                    &state,
                    ctx,
                    Err(err.to_string()),
                    started_at.unwrap_or_else(Utc::now),
                )
                .await;
            }
            Err((
                StatusCode::BAD_GATEWAY,
                format!("upstream request failed: {err}"),
            ))
        }
    }
}

struct CallContext {
    event_id: String,
    model: String,
    request_hash: String,
    prompt_hash: Option<String>,
    redacted_preview: Option<String>,
    started_at: chrono::DateTime<Utc>,
}

fn looks_like_model_call(path: &str, body: &[u8]) -> bool {
    let path_l = path.to_lowercase();
    if path_l.contains("chat/completions")
        || path_l.contains("completions")
        || path_l.contains("messages")
        || path_l.contains("responses")
    {
        return true;
    }
    // Fallback: JSON body with a "model" field.
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("model").map(|_| true))
        .unwrap_or(false)
}

async fn begin_capture(state: &ProxyState, body: &[u8]) -> CallContext {
    let event_id = Uuid::new_v4().to_string();
    let request_hash = sha256_hex(body);
    let meta = parse_request_meta(body);
    let prompt_hash = if meta.prompt_text.is_empty() {
        None
    } else {
        Some(sha256_hex(meta.prompt_text.as_bytes()))
    };
    let redacted_preview = safe_prompt_preview(&meta.prompt_text);

    let mut started = ModelCallEvent::started(
        event_id.clone(),
        state.provider.clone(),
        meta.model.clone(),
        request_hash.clone(),
    )
    .with_run_id(state.run_id.clone())
    .with_trace_id(state.trace_id.clone());
    if let Some(ref ph) = prompt_hash {
        started = started.with_prompt_hash(ph.clone());
    }
    if let Some(ref preview) = redacted_preview {
        started = started.with_redacted_preview(preview.clone());
    }
    state.sink.record(started);

    if state.capture_prompts {
        if let (Some(ph), Some(preview)) = (&prompt_hash, &redacted_preview) {
            let prompt_payload = PromptEventIngestPayload {
                event_id: format!("{event_id}-prompt"),
                run_id: state.run_id.clone(),
                trace_id: state.trace_id.clone(),
                prompt_hash: ph.clone(),
                redacted_prompt_preview: Some(preview.clone()),
                role: Some("user".into()),
                source_trust: state.source_trust.clone(),
                model_provider: Some(state.provider.clone()),
                redaction_status: Some("redacted".into()),
            };
            // Best-effort: capture must not block the model call.
            if let Err(err) = state.lineage.ingest_prompt_event(&prompt_payload).await {
                tracing::warn!(error = %err, "prompt lineage ingest failed");
            }
            state.sink.record(
                ModelCallEvent {
                    event_type: ModelCallEventType::PromptObserved,
                    event_id: format!("{event_id}-prompt"),
                    provider: state.provider.clone(),
                    model: meta.model.clone(),
                    status: None,
                    request_hash: None,
                    response_hash: None,
                    prompt_hash: Some(ph.clone()),
                    redacted_prompt_preview: Some(preview.clone()),
                    token_counts: None,
                    detail: None,
                    run_id: state.run_id.clone(),
                    trace_id: state.trace_id.clone(),
                    occurred_at: Utc::now(),
                },
            );
        }
    }

    CallContext {
        event_id,
        model: meta.model,
        request_hash,
        prompt_hash,
        redacted_preview,
        started_at: Utc::now(),
    }
}

async fn finish_capture(
    state: &ProxyState,
    ctx: CallContext,
    result: Result<&Bytes, String>,
    started_at: chrono::DateTime<Utc>,
) {
    let finished_at = Utc::now();
    let (status, response_hash, token_counts, detail) = match result {
        Ok(bytes) => {
            let resp_meta = parse_response_meta(bytes);
            (
                "success".to_string(),
                Some(sha256_hex(bytes)),
                resp_meta.token_counts,
                None,
            )
        }
        Err(err) => {
            let scrubbed = safe_failure_detail(&err);
            ("error".to_string(), None, None, Some(scrubbed))
        }
    };
    let status = normalize_status(&status).to_string();

    let mut finished = ModelCallEvent::finished(
        ctx.event_id.clone(),
        state.provider.clone(),
        ctx.model.clone(),
        status.clone(),
    )
    .with_request_hash(ctx.request_hash.clone())
    .with_run_id(state.run_id.clone())
    .with_trace_id(state.trace_id.clone());
    if let Some(rh) = &response_hash {
        finished = finished.with_response_hash(rh.clone());
    }
    if let Some(tc) = &token_counts {
        finished = finished.with_token_counts(tc.clone());
    }
    if let Some(d) = &detail {
        finished = finished.with_detail(d.clone());
    }
    if let Some(ph) = &ctx.prompt_hash {
        finished = finished.with_prompt_hash(ph.clone());
    }
    if let Some(preview) = &ctx.redacted_preview {
        finished = finished.with_redacted_preview(preview.clone());
    }
    state.sink.record(finished);

    let payload = ModelCallIngestPayload {
        event_id: ctx.event_id,
        run_id: state.run_id.clone(),
        trace_id: state.trace_id.clone(),
        provider: state.provider.clone(),
        model: ctx.model,
        request_hash: Some(ctx.request_hash),
        response_hash,
        started_at: Some(started_at),
        finished_at: Some(finished_at),
        token_counts,
        status,
        redaction_status: Some("redacted".into()),
    };
    if let Err(err) = state.lineage.ingest_model_call(&payload).await {
        tracing::warn!(error = %err, "model-call lineage ingest failed");
    }
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Build a `HeaderValue` only when valid — unused outside tests but kept
/// for future header-injection helpers.
#[allow(dead_code)]
fn try_header_value(value: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(value).ok()
}

/// Drive a full capture cycle without a live HTTP server — used by unit tests
/// of the started/finished + redaction contract.
pub async fn capture_cycle_for_test(
    state: &ProxyState,
    request_body: &[u8],
    upstream_result: Result<Bytes, String>,
) {
    let ctx = begin_capture(state, request_body).await;
    let started_at = ctx.started_at;
    match &upstream_result {
        Ok(bytes) => finish_capture(state, ctx, Ok(bytes), started_at).await,
        Err(err) => finish_capture(state, ctx, Err(err.clone()), started_at).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{ModelCallEventType, RecordingEventSink};
    use crate::gateway_client::RecordingLineageClient;
    use crate::redact::looks_unredacted;

    fn test_state(
        sink: Arc<RecordingEventSink>,
        lineage: Arc<RecordingLineageClient>,
    ) -> ProxyState {
        ProxyState {
            upstream_base: "http://127.0.0.1:9".into(),
            provider: "openai".into(),
            run_id: Some("run-1".into()),
            trace_id: Some("trace-1".into()),
            source_trust: Some("trusted_internal_unsigned".into()),
            capture_prompts: true,
            http: reqwest::Client::new(),
            sink,
            lineage,
        }
    }

    #[tokio::test]
    async fn model_call_started_and_finished_events_on_success() {
        let sink = Arc::new(RecordingEventSink::default());
        let lineage = Arc::new(RecordingLineageClient::default());
        let state = test_state(Arc::clone(&sink), Arc::clone(&lineage));

        let request = br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello world"}]}"#;
        let response = Bytes::from_static(
            br#"{"model":"gpt-4o-mini","usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7},"choices":[{"message":{"content":"hi"}}]}"#,
        );

        capture_cycle_for_test(&state, request, Ok(response)).await;

        let events = sink.events();
        let types: Vec<_> = events.iter().map(|e| e.event_type).collect();
        assert!(
            types.contains(&ModelCallEventType::ModelCallStarted),
            "expected model_call_started, got {types:?}"
        );
        assert!(
            types.contains(&ModelCallEventType::ModelCallFinished),
            "expected model_call_finished, got {types:?}"
        );
        assert!(types.contains(&ModelCallEventType::PromptObserved));

        let finished = events
            .iter()
            .find(|e| e.event_type == ModelCallEventType::ModelCallFinished)
            .expect("finished event");
        assert_eq!(finished.status.as_deref(), Some("success"));
        assert_eq!(finished.model, "gpt-4o-mini");
        assert!(finished.request_hash.as_ref().is_some_and(|h| h.len() == 64));
        assert!(finished.response_hash.as_ref().is_some_and(|h| h.len() == 64));
        let usage = finished.token_counts.as_ref().expect("token counts");
        assert_eq!(usage["prompt_tokens"], 5);
        assert_eq!(usage["completion_tokens"], 2);

        let shipped = lineage.model_calls();
        assert_eq!(shipped.len(), 1);
        assert_eq!(shipped[0].status, "success");
        assert_eq!(shipped[0].provider, "openai");
        assert!(shipped[0].token_counts.is_some());
        assert_eq!(shipped[0].redaction_status.as_deref(), Some("redacted"));
    }

    #[tokio::test]
    async fn failure_detail_is_redacted_and_status_is_error() {
        let sink = Arc::new(RecordingEventSink::default());
        let lineage = Arc::new(RecordingLineageClient::default());
        let state = test_state(Arc::clone(&sink), Arc::clone(&lineage));

        let request = br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"ping"}]}"#;
        let err = "upstream 401: Authorization Bearer sk-super-secret-key-value rejected".to_string();

        capture_cycle_for_test(&state, request, Err(err)).await;

        let events = sink.events();
        let finished = events
            .iter()
            .find(|e| e.event_type == ModelCallEventType::ModelCallFinished)
            .expect("finished event");
        assert_eq!(finished.status.as_deref(), Some("error"));
        let detail = finished.detail.as_deref().unwrap_or("");
        assert!(
            !looks_unredacted(detail),
            "failure detail still looks unredacted: {detail}"
        );
        assert!(
            !detail.to_lowercase().contains("sk-super"),
            "raw API key leaked into failure detail: {detail}"
        );

        let shipped = lineage.model_calls();
        assert_eq!(shipped.len(), 1);
        assert_eq!(shipped[0].status, "error");
        assert!(shipped[0].response_hash.is_none());
        // Lineage payload itself must not carry the failure string at all.
        let json = serde_json::to_string(&shipped[0]).unwrap();
        assert!(!json.to_lowercase().contains("sk-super"));
    }

    #[tokio::test]
    async fn prompt_with_secret_ships_only_redacted_preview() {
        let sink = Arc::new(RecordingEventSink::default());
        let lineage = Arc::new(RecordingLineageClient::default());
        let state = test_state(Arc::clone(&sink), Arc::clone(&lineage));

        let request = br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"rotate sk-live-abcdef012345 and report"}]}"#;
        let response = Bytes::from_static(br#"{"model":"gpt-4o-mini","usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#);

        capture_cycle_for_test(&state, request, Ok(response)).await;

        let prompts = lineage.prompt_events();
        assert_eq!(prompts.len(), 1);
        let preview = prompts[0]
            .redacted_prompt_preview
            .as_deref()
            .unwrap_or("");
        assert!(!looks_unredacted(preview));
        assert!(!preview.contains("sk-live"));
        assert_eq!(prompts[0].prompt_hash.len(), 64);
    }
}
