//! A real, HTTP-posting `CageEventSink` for production use, replacing the
//! crate's `NullEventSink` default. Ships each `CageEvent` to the gateway's
//! `POST /v1/ingest/runtime-events` (the endpoint the event-type strings in
//! `events.rs` are already designed to match).
//!
//! Fire-and-forget: `CageEventSink::record` is synchronous and infallible by
//! contract ("emitting telemetry must never block or fail a sandbox
//! lifecycle operation" — `events.rs`'s own doc comment), so this spawns a
//! detached task and logs-and-drops on failure rather than propagating an
//! error or blocking the caller.
//!
//! No local durable spool (unlike `aegis-node-sensor`'s `SpoolQueue`) --
//! deliberately: losing one of the 4 coarse lifecycle events on a crash is
//! low-blast-radius observability, not the run's authoritative state (that
//! lives in `agent_runs.status`, independently durable via the
//! claim/heartbeat/status endpoints). Building a persistent queue here
//! would be new machinery this feature doesn't need.

use std::sync::Arc;

use crate::events::{CageEvent, CageEventSink};
use crate::gateway_client::{GatewayClient, RuntimeEventPayload};

pub struct HttpEventSink {
    client: Arc<GatewayClient>,
}

impl HttpEventSink {
    pub fn new(client: Arc<GatewayClient>) -> Self {
        Self { client }
    }
}

impl CageEventSink for HttpEventSink {
    fn record(&self, event: CageEvent) {
        // Deterministic per (sandbox, event_type) -- each of the 4
        // lifecycle events fires at most once per sandbox in this design,
        // so this fits the gateway's `(tenant_id, event_id)` dedup index
        // with zero extra retry-tracking state on this side.
        let event_id = format!(
            "{}:{}",
            event.sandbox_id,
            event.event_type.as_event_type_str()
        );
        let payload = RuntimeEventPayload {
            event_id,
            event_type: event.event_type.as_event_type_str().to_string(),
            agent_id: None,
            run_id: Some(event.run_id.clone()),
            sandbox_id: Some(event.sandbox_id.clone()),
            source_component: "cage-runner".to_string(),
            reason: event.exit_code.map(|code| format!("exit_code={code}")),
        };
        let client = self.client.clone();
        tokio::spawn(async move {
            if let Err(e) = client.ingest_runtime_event(&payload).await {
                tracing::warn!("failed to ship runtime event to gateway: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::CageEventType;
    use axum::{routing::post, Json, Router};
    use std::sync::Mutex;
    use url::Url;

    #[tokio::test]
    async fn record_posts_the_expected_event_shape() {
        let received: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
        let received_clone = received.clone();
        let app = Router::new().route(
            "/v1/ingest/runtime-events",
            post(move |Json(body): Json<serde_json::Value>| {
                let received = received_clone.clone();
                async move {
                    *received.lock().unwrap() = Some(body);
                    Json(serde_json::json!({"ingested": true}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = Arc::new(GatewayClient::new(
            Url::parse(&format!("http://{addr}")).unwrap(),
            "tok".to_string(),
        ));
        let sink = HttpEventSink::new(client);
        sink.record(
            CageEvent::new(
                CageEventType::ProcessExited,
                "tenant_a",
                "run-1",
                "sandbox-1",
            )
            .with_exit_code(Some(0)),
        );

        // record() is fire-and-forget (spawns a detached task) -- poll
        // briefly rather than assuming it landed synchronously.
        let mut attempts = 0;
        loop {
            if received.lock().unwrap().is_some() || attempts > 50 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            attempts += 1;
        }

        let body = received
            .lock()
            .unwrap()
            .clone()
            .expect("event must have been posted");
        assert_eq!(body["event_id"], "sandbox-1:process_exited");
        assert_eq!(body["event_type"], "process_exited");
        assert_eq!(body["run_id"], "run-1");
        assert_eq!(body["sandbox_id"], "sandbox-1");
        assert_eq!(body["reason"], "exit_code=0");
    }
}
