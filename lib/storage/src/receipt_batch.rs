//! #904 — receipt-chain write batching.
//!
//! The `/v1/authorize` hot path emits one `action_receipts` row per decision
//! (best-effort, deferred). Under sustained load, one `BEGIN IMMEDIATE` +
//! single-row `INSERT` per receipt dominates write throughput. [`ReceiptBatchSink`]
//! lets the hot path hand off non-durable receipts to a background task
//! ([`run_receipt_batch_writer`]) that accumulates them and flushes with
//! [`db::append_action_receipts_batch_atomic`] once `batch_size` rows are
//! buffered or `flush_interval` elapses, whichever comes first.
//!
//! Protected decisions that require durable evidence before success still
//! bypass this sink and call [`db::append_action_receipt_atomic`] synchronously
//! — see `emit_action_receipt_durable` in `authorize_receipts.rs`.
//!
//! Failure modes:
//! - A full channel falls back to a synchronous
//!   [`db::append_action_receipt_atomic`] in [`ReceiptBatchSink::emit`] so a
//!   receipt is never silently dropped.
//! - A failed batch flush retries each pending receipt individually via the
//!   atomic single-row appender.
//! - On shutdown, dropping every [`ReceiptBatchSink`] clone closes the channel;
//!   [`run_receipt_batch_writer`] flushes any remaining buffered rows before
//!   returning, mirroring the audit-batch graceful-shutdown pattern (#1315).

use crate::db;
use crate::db::DbPool;
use aegis_api::models::ActionReceiptRecord;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, warn};

/// Default number of buffered receipts that triggers an immediate flush.
/// Overridable via `AEGIS_RECEIPT_BATCH_SIZE`.
pub const DEFAULT_BATCH_SIZE: usize = 50;

/// Default time between timer-driven flushes (milliseconds). Overridable via
/// `AEGIS_RECEIPT_BATCH_FLUSH_MS`.
pub const DEFAULT_FLUSH_INTERVAL_MS: u64 = 500;

/// Default channel capacity for the batch sink.
pub const DEFAULT_CAPACITY: usize = 1024;

/// Read `AEGIS_RECEIPT_BATCH_SIZE`, falling back to [`DEFAULT_BATCH_SIZE`].
pub fn batch_size_from_env() -> usize {
    std::env::var("AEGIS_RECEIPT_BATCH_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &usize| n > 0)
        .unwrap_or(DEFAULT_BATCH_SIZE)
}

/// Read `AEGIS_RECEIPT_BATCH_FLUSH_MS`, falling back to [`DEFAULT_FLUSH_INTERVAL_MS`].
pub fn flush_interval_from_env() -> Duration {
    let ms = std::env::var("AEGIS_RECEIPT_BATCH_FLUSH_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &u64| n > 0)
        .unwrap_or(DEFAULT_FLUSH_INTERVAL_MS);
    Duration::from_millis(ms)
}

#[derive(Clone, Debug)]
pub struct PendingReceipt {
    pub tenant_id: String,
    pub record: ActionReceiptRecord,
}

/// Non-blocking handle the authorize hot path holds to enqueue best-effort
/// receipt rows. Cloneable so it can live on `AppState`.
#[derive(Clone)]
pub struct ReceiptBatchSink {
    tx: mpsc::Sender<PendingReceipt>,
}

impl ReceiptBatchSink {
    /// Build a sink and its receiver. Production spawns
    /// [`run_receipt_batch_writer`] on the receiver.
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<PendingReceipt>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self { tx }, rx)
    }

    /// Enqueue `record` for batched chain append. If the channel is full or the
    /// writer task has shut down, falls back to a synchronous
    /// [`db::append_action_receipt_atomic`] so the row is never silently dropped.
    pub async fn emit(
        &self,
        pool: &DbPool,
        tenant_id: &str,
        record: ActionReceiptRecord,
    ) -> Result<(), sqlx::Error> {
        let pending = PendingReceipt {
            tenant_id: tenant_id.to_string(),
            record,
        };
        match self.tx.try_send(pending) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(pending)) => {
                warn!(
                    receipt_id = %pending.record.id,
                    tenant_id = %pending.tenant_id,
                    "receipt batch channel full — writing synchronously"
                );
                db::append_action_receipt_atomic(pool, &pending.tenant_id, |prev| {
                    let mut record = pending.record;
                    db::finalize_receipt_link(&mut record, prev);
                    record
                })
                .await?;
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(pending)) => {
                warn!(
                    receipt_id = %pending.record.id,
                    tenant_id = %pending.tenant_id,
                    "receipt batch writer stopped — writing synchronously"
                );
                db::append_action_receipt_atomic(pool, &pending.tenant_id, |prev| {
                    let mut record = pending.record;
                    db::finalize_receipt_link(&mut record, prev);
                    record
                })
                .await?;
                Ok(())
            }
        }
    }
}

async fn flush_fallback_individual(pool: &DbPool, buf: &[PendingReceipt]) {
    for pending in buf {
        if let Err(e) = db::append_action_receipt_atomic(pool, &pending.tenant_id, |prev| {
            let mut record = pending.record.clone();
            db::finalize_receipt_link(&mut record, prev);
            record
        })
        .await
        {
            error!(
                receipt_id = %pending.record.id,
                tenant_id = %pending.tenant_id,
                "receipt batch fallback append failed: {:?}",
                e
            );
        }
    }
}

/// Flush `buf` via [`db::append_action_receipts_batch_atomic`], falling back
/// to per-row atomic appends on failure. Clears `buf` either way.
async fn flush(pool: &DbPool, buf: &mut Vec<PendingReceipt>) -> usize {
    if buf.is_empty() {
        return 0;
    }
    let n = buf.len();
    let batch: Vec<db::PendingReceiptAppend> = buf
        .iter()
        .map(|p| db::PendingReceiptAppend {
            tenant_id: p.tenant_id.clone(),
            record: p.record.clone(),
        })
        .collect();
    if let Err(e) = db::append_action_receipts_batch_atomic(pool, &batch).await {
        error!(
            "receipt batch flush failed, falling back to single-row appends: {:?}",
            e
        );
        flush_fallback_individual(pool, buf).await;
    }
    buf.clear();
    n
}

/// Drain `rx`, batching records into [`db::append_action_receipts_batch_atomic`]
/// calls of up to `batch_size`, flushing early if `flush_interval` elapses with
/// a non-empty buffer. Returns once every [`ReceiptBatchSink`] clone is dropped
/// (channel closed), after flushing any remaining buffered records. Intended
/// to be `tokio::spawn`ed once at startup. Returns the total number of receipts
/// flushed.
pub async fn run_receipt_batch_writer(
    pool: DbPool,
    mut rx: mpsc::Receiver<PendingReceipt>,
    batch_size: usize,
    flush_interval: Duration,
) -> usize {
    let mut buf: Vec<PendingReceipt> = Vec::with_capacity(batch_size);
    let mut interval = tokio::time::interval(flush_interval);
    interval.tick().await;
    let mut total = 0;

    loop {
        tokio::select! {
            maybe_receipt = rx.recv() => {
                match maybe_receipt {
                    Some(record) => {
                        buf.push(record);
                        if buf.len() >= batch_size {
                            total += flush(&pool, &mut buf).await;
                        }
                    }
                    None => {
                        total += flush(&pool, &mut buf).await;
                        break;
                    }
                }
            }
            _ = interval.tick() => {
                total += flush(&pool, &mut buf).await;
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

    async fn setup_pool(test_name: &str) -> DbPool {
        std::fs::create_dir_all("target").unwrap();
        let db_url = format!(
            "sqlite://target/{}_{}.db",
            test_name,
            Uuid::new_v4().simple()
        );
        db::init_db(&db_url).await.unwrap()
    }

    fn bare_receipt(tenant_id: &str) -> ActionReceiptRecord {
        ActionReceiptRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            decision_id: None,
            ts: Utc::now().to_rfc3339(),
            agent_id: None,
            user_id: None,
            run_id: None,
            trace_id: None,
            tool: Some("filesystem".to_string()),
            action: Some("read_file".to_string()),
            resource: None,
            source_trust: "trusted_internal_signed".to_string(),
            decision: "allow".to_string(),
            approver: None,
            action_hash: Some("sha256:dead".to_string()),
            prev_receipt_hash: String::new(),
            receipt_hash: String::new(),
            canon_version: "aegis-jcs-1".to_string(),
            signature: None,
            signer_public_key: None,
            signer_key_id: None,
            created_at: Utc::now(),
        }
    }

    async fn count_receipt_rows(pool: &DbPool, tenant_id: &str) -> i64 {
        db::count_receipts(pool, tenant_id).await.unwrap()
    }

    #[tokio::test]
    async fn flushes_when_batch_size_reached() {
        let pool = setup_pool("receipt_batch_size").await;
        db::register_tenant(&pool, "tenant_size", "Size Tenant", "developer")
            .await
            .unwrap();

        let (sink, rx) = ReceiptBatchSink::channel(DEFAULT_CAPACITY);
        let handle = tokio::spawn(run_receipt_batch_writer(
            pool.clone(),
            rx,
            2,
            Duration::from_secs(60),
        ));

        sink.emit(&pool, "tenant_size", bare_receipt("tenant_size"))
            .await
            .unwrap();
        sink.emit(&pool, "tenant_size", bare_receipt("tenant_size"))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(count_receipt_rows(&pool, "tenant_size").await, 2);

        drop(sink);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn flushes_on_timer_when_below_batch_size() {
        let pool = setup_pool("receipt_batch_timer").await;
        db::register_tenant(&pool, "tenant_timer", "Timer Tenant", "developer")
            .await
            .unwrap();

        let (sink, rx) = ReceiptBatchSink::channel(DEFAULT_CAPACITY);
        let handle = tokio::spawn(run_receipt_batch_writer(
            pool.clone(),
            rx,
            100,
            Duration::from_millis(50),
        ));

        sink.emit(&pool, "tenant_timer", bare_receipt("tenant_timer"))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(count_receipt_rows(&pool, "tenant_timer").await, 1);

        drop(sink);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn flushes_remaining_buffer_on_shutdown() {
        let pool = setup_pool("receipt_batch_shutdown").await;
        db::register_tenant(&pool, "tenant_shutdown", "Shutdown Tenant", "developer")
            .await
            .unwrap();

        let (sink, rx) = ReceiptBatchSink::channel(DEFAULT_CAPACITY);
        let handle = tokio::spawn(run_receipt_batch_writer(
            pool.clone(),
            rx,
            100,
            Duration::from_secs(60),
        ));

        sink.emit(&pool, "tenant_shutdown", bare_receipt("tenant_shutdown"))
            .await
            .unwrap();
        sink.emit(&pool, "tenant_shutdown", bare_receipt("tenant_shutdown"))
            .await
            .unwrap();

        drop(sink);
        let total = handle.await.unwrap();
        assert_eq!(total, 2);
        assert_eq!(count_receipt_rows(&pool, "tenant_shutdown").await, 2);
    }

    #[tokio::test]
    async fn emit_falls_back_to_sync_append_when_channel_full() {
        let pool = setup_pool("receipt_batch_full").await;
        db::register_tenant(&pool, "tenant_full", "Full Tenant", "developer")
            .await
            .unwrap();

        let (sink, _rx) = ReceiptBatchSink::channel(1);

        sink.emit(&pool, "tenant_full", bare_receipt("tenant_full"))
            .await
            .unwrap();
        sink.emit(&pool, "tenant_full", bare_receipt("tenant_full"))
            .await
            .unwrap();

        assert_eq!(count_receipt_rows(&pool, "tenant_full").await, 1);
    }
}
