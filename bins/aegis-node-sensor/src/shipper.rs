//! Phase 3.4 (Agent Cage): drains the durable spool (Phase 3.3) to the
//! gateway's runtime-event ingest endpoint (Phase 2.6). Each record is
//! retried with exponential backoff before the shipper gives up on it for
//! this tick; only a confirmed gateway response (success OR a dedup
//! `ingested: false`, which is not a failure) advances the spool's ack
//! watermark. A sustained gateway outage naturally "buffers" — the shipper
//! simply stops draining and leaves everything queued on disk for the next
//! tick or the next sensor restart, no separate buffering logic needed
//! beyond what the spool already provides.

use std::time::Duration;

use crate::gateway_client::{GatewayClient, GatewayClientError, RuntimeEventPayload};
use crate::spool::{Lane, SpoolError, SpoolQueue};

const SHIP_MAX_ATTEMPTS: u32 = 5;
const SHIP_BASE_DELAY: Duration = Duration::from_millis(200);

#[derive(Debug, thiserror::Error)]
pub enum ShipperError {
    #[error(transparent)]
    Spool(#[from] SpoolError),
    #[error("record payload is not valid JSON: {0}")]
    InvalidPayload(#[from] serde_json::Error),
}

pub struct EventShipper<'a> {
    client: &'a GatewayClient,
}

impl<'a> EventShipper<'a> {
    pub fn new(client: &'a GatewayClient) -> Self {
        Self { client }
    }

    /// Drain every currently-pending record in `lane`, shipping and acking
    /// each in turn. Stops at the first record that exhausts its retries
    /// (leaving it and everything behind it queued) rather than skipping
    /// ahead — event order within a lane is preserved.
    pub async fn ship_lane(&self, spool: &SpoolQueue, lane: Lane) -> Result<u32, ShipperError> {
        let mut shipped = 0;
        while let Some(record) = spool.read_next(lane)? {
            let payload: RuntimeEventPayload = serde_json::from_slice(&record.payload)?;
            match self.ship_with_retries(&payload).await {
                Ok(()) => {
                    spool.ack(lane, &record)?;
                    shipped += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        event_id = %payload.event_id,
                        error = %e,
                        "giving up on shipping this record for now, will retry next tick"
                    );
                    break;
                }
            }
        }
        Ok(shipped)
    }

    /// Ship one record, retrying transient failures with exponential
    /// backoff. A dedup response (`ingested: false` — the gateway already
    /// has this `event_id`) is treated as success: the event is confirmed
    /// delivered either way.
    async fn ship_with_retries(
        &self,
        payload: &RuntimeEventPayload,
    ) -> Result<(), GatewayClientError> {
        let mut delay = SHIP_BASE_DELAY;
        for attempt in 1..=SHIP_MAX_ATTEMPTS {
            match self.client.ingest_runtime_event(payload).await {
                Ok(_response) => return Ok(()),
                Err(e) if attempt < SHIP_MAX_ATTEMPTS => {
                    tracing::warn!(
                        attempt,
                        max_attempts = SHIP_MAX_ATTEMPTS,
                        event_id = %payload.event_id,
                        error = %e,
                        "ship attempt failed, backing off"
                    );
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!("loop always returns by the final attempt")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use axum::{routing::post, Json, Router};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use url::Url;

    fn sample_payload(event_id: &str) -> RuntimeEventPayload {
        RuntimeEventPayload {
            event_id: event_id.to_string(),
            event_type: "tool_call".to_string(),
            source_component: "sensor".to_string(),
            ..Default::default()
        }
    }

    fn enqueue(spool: &SpoolQueue, lane: Lane, payload: &RuntimeEventPayload) {
        let bytes = serde_json::to_vec(payload).unwrap();
        spool.enqueue(lane, &bytes).unwrap();
    }

    async fn spawn_gateway(app: Router) -> Url {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Url::parse(&format!("http://{addr}")).unwrap()
    }

    #[tokio::test]
    async fn ships_and_acks_every_pending_record() {
        let hit_count = Arc::new(AtomicU32::new(0));
        let hit_count_clone = hit_count.clone();
        let app = Router::new().route(
            "/v1/ingest/runtime-events",
            post(move || {
                let hit_count = hit_count_clone.clone();
                async move {
                    hit_count.fetch_add(1, Ordering::SeqCst);
                    Json(serde_json::json!({"ingested": true}))
                }
            }),
        );
        let base_url = spawn_gateway(app).await;

        let dir = tempfile::tempdir().unwrap();
        let spool = SpoolQueue::open(dir.path(), 1_000_000).unwrap();
        enqueue(&spool, Lane::Normal, &sample_payload("evt-1"));
        enqueue(&spool, Lane::Normal, &sample_payload("evt-2"));

        let client = GatewayClient::new(base_url, "tok".to_string());
        let shipper = EventShipper::new(&client);
        let shipped = shipper.ship_lane(&spool, Lane::Normal).await.unwrap();

        assert_eq!(shipped, 2);
        assert_eq!(hit_count.load(Ordering::SeqCst), 2);
        assert!(spool.read_next(Lane::Normal).unwrap().is_none());
    }

    #[tokio::test]
    async fn gateway_down_leaves_records_buffered_in_the_spool() {
        let dir = tempfile::tempdir().unwrap();
        let spool = SpoolQueue::open(dir.path(), 1_000_000).unwrap();
        enqueue(&spool, Lane::Normal, &sample_payload("evt-1"));

        // Nothing listens on this port.
        let client =
            GatewayClient::new(Url::parse("http://127.0.0.1:1").unwrap(), "tok".to_string());
        let shipper = EventShipper::new(&client);
        let shipped = shipper.ship_lane(&spool, Lane::Normal).await.unwrap();

        assert_eq!(shipped, 0);
        // The record is still there, unacked — durably buffered, not lost.
        let record = spool.read_next(Lane::Normal).unwrap().unwrap();
        let payload: RuntimeEventPayload = serde_json::from_slice(&record.payload).unwrap();
        assert_eq!(payload.event_id, "evt-1");
    }

    #[tokio::test]
    async fn a_later_success_ships_after_gateway_recovers() {
        // Simulates "gateway down, sensor buffers, gateway comes back":
        // ship once against an unreachable host, then reopen the same spool
        // dir against a live gateway and confirm the buffered record ships.
        let dir = tempfile::tempdir().unwrap();
        {
            let spool = SpoolQueue::open(dir.path(), 1_000_000).unwrap();
            enqueue(&spool, Lane::Normal, &sample_payload("evt-1"));
            let down_client =
                GatewayClient::new(Url::parse("http://127.0.0.1:1").unwrap(), "tok".to_string());
            let shipper = EventShipper::new(&down_client);
            assert_eq!(shipper.ship_lane(&spool, Lane::Normal).await.unwrap(), 0);
        }

        let app = Router::new().route(
            "/v1/ingest/runtime-events",
            post(|| async { Json(serde_json::json!({"ingested": true})) }),
        );
        let base_url = spawn_gateway(app).await;
        let spool = SpoolQueue::open(dir.path(), 1_000_000).unwrap(); // replays the buffered record
        let client = GatewayClient::new(base_url, "tok".to_string());
        let shipper = EventShipper::new(&client);
        assert_eq!(shipper.ship_lane(&spool, Lane::Normal).await.unwrap(), 1);
        assert!(spool.read_next(Lane::Normal).unwrap().is_none());
    }

    #[tokio::test]
    async fn duplicate_event_id_dedup_response_is_treated_as_success() {
        let app = Router::new().route(
            "/v1/ingest/runtime-events",
            post(|| async { Json(serde_json::json!({"ingested": false})) }),
        );
        let base_url = spawn_gateway(app).await;

        let dir = tempfile::tempdir().unwrap();
        let spool = SpoolQueue::open(dir.path(), 1_000_000).unwrap();
        enqueue(&spool, Lane::Normal, &sample_payload("evt-already-seen"));

        let client = GatewayClient::new(base_url, "tok".to_string());
        let shipper = EventShipper::new(&client);
        // A dedup ("already have this event_id") response must still ack —
        // the event is confirmed delivered, just not newly recorded.
        assert_eq!(shipper.ship_lane(&spool, Lane::Normal).await.unwrap(), 1);
        assert!(spool.read_next(Lane::Normal).unwrap().is_none());
    }

    #[tokio::test]
    async fn a_stuck_record_blocks_records_behind_it_preserving_order() {
        let hit_count = Arc::new(AtomicU32::new(0));
        let hit_count_clone = hit_count.clone();
        let app = Router::new().route(
            "/v1/ingest/runtime-events",
            post(move || {
                let hit_count = hit_count_clone.clone();
                async move {
                    hit_count.fetch_add(1, Ordering::SeqCst);
                    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response()
                }
            }),
        );
        let base_url = spawn_gateway(app).await;

        let dir = tempfile::tempdir().unwrap();
        let spool = SpoolQueue::open(dir.path(), 1_000_000).unwrap();
        enqueue(&spool, Lane::Normal, &sample_payload("evt-1"));
        enqueue(&spool, Lane::Normal, &sample_payload("evt-2"));

        let client = GatewayClient::new(base_url, "tok".to_string());
        let shipper = EventShipper::new(&client);
        // evt-1 exhausts all SHIP_MAX_ATTEMPTS retries (the handler always
        // errors) and is left queued; evt-2 must never be attempted while
        // evt-1 is still unacked, preserving delivery order within a lane.
        let shipped = shipper.ship_lane(&spool, Lane::Normal).await.unwrap();
        assert_eq!(shipped, 0);
        assert_eq!(hit_count.load(Ordering::SeqCst), SHIP_MAX_ATTEMPTS);
        let record = spool.read_next(Lane::Normal).unwrap().unwrap();
        let payload: RuntimeEventPayload = serde_json::from_slice(&record.payload).unwrap();
        assert_eq!(payload.event_id, "evt-1");
    }
}
