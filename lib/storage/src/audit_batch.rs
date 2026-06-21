//! #1315 — audit-event write batching.
//!
//! The `/v1/authorize` hot path (`write_decision_and_audit`) emits one
//! `audit_events` row per decision. Under sustained load, one `INSERT` per
//! decision dominates write throughput. [`AuditBatchSink`] lets the hot path
//! hand off non-critical audit rows to a background task
//! ([`run_audit_batch_writer`]) that accumulates them and flushes with
//! [`db::insert_audit_events_batch`] once `batch_size` rows are buffered or
//! `flush_interval` elapses, whichever comes first.
//!
//! Critical events (deny on critical risk) bypass this sink entirely and are
//! written synchronously via [`db::insert_audit_event`] — see
//! `write_decision_and_audit` in `routes.rs`.
//!
//! Failure modes:
//! - A full channel falls back to a synchronous insert in [`AuditBatchSink::emit`]
//!   so an audit row is never silently dropped.
//! - A failed batch flush sets `audit_writer_unhealthy` (shared `Arc<AtomicBool>`,
//!   surfaced via `GET /readyz`), exactly like the synchronous path.
//! - On shutdown, dropping every [`AuditBatchSink`] clone closes the channel;
//!   [`run_audit_batch_writer`] flushes any remaining buffered rows before
//!   returning, mirroring the `events::drain` graceful-shutdown pattern.

use crate::db;
use aegis_api::models::AuditEventRecord;
use sqlx::SqlitePool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, warn};

/// Default number of buffered events that triggers an immediate flush.
/// Overridable via `AEGIS_AUDIT_BATCH_SIZE`.
pub const DEFAULT_BATCH_SIZE: usize = 100;

/// Default time between timer-driven flushes (milliseconds). Overridable via
/// `AEGIS_AUDIT_BATCH_FLUSH_MS`.
pub const DEFAULT_FLUSH_INTERVAL_MS: u64 = 500;

/// Default channel capacity for the batch sink.
pub const DEFAULT_CAPACITY: usize = 1024;

/// Read `AEGIS_AUDIT_BATCH_SIZE`, falling back to [`DEFAULT_BATCH_SIZE`].
pub fn batch_size_from_env() -> usize {
    std::env::var("AEGIS_AUDIT_BATCH_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &usize| n > 0)
        .unwrap_or(DEFAULT_BATCH_SIZE)
}

/// Read `AEGIS_AUDIT_BATCH_FLUSH_MS`, falling back to [`DEFAULT_FLUSH_INTERVAL_MS`].
pub fn flush_interval_from_env() -> Duration {
    let ms = std::env::var("AEGIS_AUDIT_BATCH_FLUSH_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &u64| n > 0)
        .unwrap_or(DEFAULT_FLUSH_INTERVAL_MS);
    Duration::from_millis(ms)
}

/// Non-blocking handle the authorize hot path holds to enqueue non-critical
/// audit rows. Cloneable so it can live on `AppState` alongside `EventSink`.
#[derive(Clone)]
pub struct AuditBatchSink {
    tx: mpsc::Sender<AuditEventRecord>,
}

impl AuditBatchSink {
    /// Build a sink and its receiver. Production spawns
    /// [`run_audit_batch_writer`] on the receiver.
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<AuditEventRecord>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self { tx }, rx)
    }

    /// Enqueue `record` for batched insertion. If the channel is full or the
    /// writer task has shut down, falls back to a synchronous
    /// [`db::insert_audit_event`] so the row is never silently dropped.
    pub async fn emit(
        &self,
        pool: &SqlitePool,
        record: AuditEventRecord,
    ) -> Result<(), sqlx::Error> {
        match self.tx.try_send(record) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(record)) => {
                warn!(event_id = %record.id, "audit batch channel full — writing synchronously");
                db::insert_audit_event(pool, &record).await
            }
            Err(mpsc::error::TrySendError::Closed(record)) => {
                warn!(event_id = %record.id, "audit batch writer stopped — writing synchronously");
                db::insert_audit_event(pool, &record).await
            }
        }
    }
}

/// Flush `buf` via [`db::insert_audit_events_batch`], updating
/// `audit_writer_unhealthy` on success/failure, and clear it. Returns the
/// number of records the flush attempted (0 if `buf` was empty).
async fn flush(
    pool: &SqlitePool,
    buf: &mut Vec<AuditEventRecord>,
    audit_writer_unhealthy: &Arc<AtomicBool>,
) -> usize {
    if buf.is_empty() {
        return 0;
    }
    let n = buf.len();
    match db::insert_audit_events_batch(pool, buf).await {
        Ok(()) => audit_writer_unhealthy.store(false, Ordering::Relaxed),
        Err(e) => {
            error!("audit batch flush failed: {:?}", e);
            audit_writer_unhealthy.store(true, Ordering::Relaxed);
        }
    }
    buf.clear();
    n
}

/// Drain `rx`, batching records into `db::insert_audit_events_batch` calls of
/// up to `batch_size`, flushing early if `flush_interval` elapses with a
/// non-empty buffer. Returns once every [`AuditBatchSink`] clone is dropped
/// (channel closed), after flushing any remaining buffered records. Intended
/// to be `tokio::spawn`ed once at startup. Returns the total number of
/// records flushed.
pub async fn run_audit_batch_writer(
    pool: SqlitePool,
    mut rx: mpsc::Receiver<AuditEventRecord>,
    batch_size: usize,
    flush_interval: Duration,
    audit_writer_unhealthy: Arc<AtomicBool>,
) -> usize {
    let mut buf: Vec<AuditEventRecord> = Vec::with_capacity(batch_size);
    let mut interval = tokio::time::interval(flush_interval);
    interval.tick().await; // first tick fires immediately; consume it
    let mut total = 0;

    loop {
        tokio::select! {
            maybe_record = rx.recv() => {
                match maybe_record {
                    Some(record) => {
                        buf.push(record);
                        if buf.len() >= batch_size {
                            total += flush(&pool, &mut buf, &audit_writer_unhealthy).await;
                        }
                    }
                    None => {
                        total += flush(&pool, &mut buf, &audit_writer_unhealthy).await;
                        break;
                    }
                }
            }
            _ = interval.tick() => {
                total += flush(&pool, &mut buf, &audit_writer_unhealthy).await;
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use chrono::Utc;
    use uuid::Uuid;

    async fn setup_pool(test_name: &str) -> SqlitePool {
        std::fs::create_dir_all("target").unwrap();
        let db_url = format!(
            "sqlite://target/{}_{}.db",
            test_name,
            Uuid::new_v4().simple()
        );
        db::init_db(&db_url).await.unwrap()
    }

    fn make_audit_event(id: &str, tenant_id: &str) -> AuditEventRecord {
        AuditEventRecord {
            id: id.to_string(),
            tenant_id: tenant_id.to_string(),
            event_type: "decision".to_string(),
            agent_id: Some("agent_1".to_string()),
            user_id: None,
            run_id: None,
            trace_id: None,
            span_id: None,
            skill: None,
            action: Some("read".to_string()),
            resource: Some("repo".to_string()),
            event_json: "{}".to_string(),
            input_hash: None,
            output_hash: None,
            decision_id: None,
            approval_id: None,
            created_at: Utc::now(),
        }
    }

    async fn count_audit_rows(pool: &SqlitePool, tenant_id: &str) -> i64 {
        db::get_all_audit_events(pool, tenant_id, None)
            .await
            .unwrap()
            .len() as i64
    }

    /// #1315 AC1: the buffer flushes as soon as it reaches `batch_size`,
    /// without waiting for the flush-interval timer.
    #[tokio::test]
    async fn flushes_when_batch_size_reached() {
        let pool = setup_pool("audit_batch_size").await;
        db::register_tenant(&pool, "tenant_size", "Size Tenant", "developer")
            .await
            .unwrap();

        let (sink, rx) = AuditBatchSink::channel(DEFAULT_CAPACITY);
        let unhealthy = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn(run_audit_batch_writer(
            pool.clone(),
            rx,
            2,
            Duration::from_secs(60), // long enough that the timer never fires
            unhealthy.clone(),
        ));

        sink.emit(&pool, make_audit_event("evt_0", "tenant_size"))
            .await
            .unwrap();
        sink.emit(&pool, make_audit_event("evt_1", "tenant_size"))
            .await
            .unwrap();

        // Give the writer task a moment to process the size-triggered flush.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(count_audit_rows(&pool, "tenant_size").await, 2);
        assert!(!unhealthy.load(Ordering::Relaxed));

        drop(sink);
        handle.await.unwrap();
    }

    /// #1315 AC1: a buffer below `batch_size` flushes once `flush_interval`
    /// elapses.
    #[tokio::test]
    async fn flushes_on_timer_when_below_batch_size() {
        let pool = setup_pool("audit_batch_timer").await;
        db::register_tenant(&pool, "tenant_timer", "Timer Tenant", "developer")
            .await
            .unwrap();

        let (sink, rx) = AuditBatchSink::channel(DEFAULT_CAPACITY);
        let unhealthy = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn(run_audit_batch_writer(
            pool.clone(),
            rx,
            100, // never reached by a single event
            Duration::from_millis(50),
            unhealthy.clone(),
        ));

        sink.emit(&pool, make_audit_event("evt_0", "tenant_timer"))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(count_audit_rows(&pool, "tenant_timer").await, 1);

        drop(sink);
        handle.await.unwrap();
    }

    /// #1315 AC2: dropping every sink clone closes the channel; the writer
    /// flushes whatever remains buffered before returning (no event loss on
    /// graceful shutdown).
    #[tokio::test]
    async fn flushes_remaining_buffer_on_shutdown() {
        let pool = setup_pool("audit_batch_shutdown").await;
        db::register_tenant(&pool, "tenant_shutdown", "Shutdown Tenant", "developer")
            .await
            .unwrap();

        let (sink, rx) = AuditBatchSink::channel(DEFAULT_CAPACITY);
        let unhealthy = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn(run_audit_batch_writer(
            pool.clone(),
            rx,
            100,
            Duration::from_secs(60), // never fires before shutdown
            unhealthy.clone(),
        ));

        sink.emit(&pool, make_audit_event("evt_0", "tenant_shutdown"))
            .await
            .unwrap();
        sink.emit(&pool, make_audit_event("evt_1", "tenant_shutdown"))
            .await
            .unwrap();

        drop(sink);
        let total = handle.await.unwrap();
        assert_eq!(total, 2);
        assert_eq!(count_audit_rows(&pool, "tenant_shutdown").await, 2);
    }

    /// #1315 AC3: when the channel is full, `emit` falls back to a
    /// synchronous insert rather than dropping the event.
    #[tokio::test]
    async fn emit_falls_back_to_sync_insert_when_channel_full() {
        let pool = setup_pool("audit_batch_full").await;
        db::register_tenant(&pool, "tenant_full", "Full Tenant", "developer")
            .await
            .unwrap();

        // Capacity 1, no writer task draining — the channel fills immediately.
        let (sink, _rx) = AuditBatchSink::channel(1);

        sink.emit(&pool, make_audit_event("evt_0", "tenant_full"))
            .await
            .unwrap();
        // Channel is now full; this one must fall back to a direct insert.
        sink.emit(&pool, make_audit_event("evt_1", "tenant_full"))
            .await
            .unwrap();

        // Only the synchronous fallback (evt_1) is persisted; evt_0 sits
        // unflushed in the channel buffer.
        let rows = db::get_all_audit_events(&pool, "tenant_full", None)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "evt_1");
    }
}
