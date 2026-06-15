# Title: Audit Event Write Batching (#1315)

## 0. Scope decision (read first)

`insert_audit_event` is called from ~17 sites in `gateway/src/routes.rs` plus
one in `gateway/src/events.rs` (Phase 4 SOC response audit). Batching all of
them would mean threading a new `AuditBatchSink` through every handler and
every test `AppState` constructor — large surface area for little benefit,
since most of those sites are low-frequency, human-triggered admin/approval
actions.

**MVP scope: batch only the hot path** — the `audit_events` insert inside
`write_decision_and_audit` (`routes.rs:1236-1338`), which fires on every
`/v1/authorize` call and is the only path where "sustained event bursts"
actually occur. All other call sites (`events.rs` SOC response audit, policy
CRUD, approval lifecycle, agent lifecycle, etc.) are left as direct
synchronous `db::insert_audit_event` calls — no behavior change, no added
risk.

This keeps the **`decisions` table insert** (`db::insert_decision`, the
authoritative "this decision was made" record used by `/v1/decisions`,
approvals, and receipts) fully synchronous and unchanged — the core
fail-closed guarantee ("a mutating action is not executed unless its decision
is durably recorded") is preserved untouched. Batching applies only to the
secondary `audit_events` log row that mirrors the decision for
`/v1/audit/events` and `/v1/runs/:id/timeline`.

## 1. Architectural Scope & Impact

- **Files touched:**
  - `gateway/src/audit_batch.rs` (new) — `AuditBatchSink`, background flush task.
  - `gateway/src/db.rs` — add `insert_audit_events_batch(pool, &[AuditEventRecord]) -> Result<(), sqlx::Error>`.
  - `gateway/src/routes.rs` — `AppState` gains `audit_batch: AuditBatchSink`; `write_decision_and_audit` sends non-critical events to the batcher instead of calling `db::insert_audit_event` directly.
  - `gateway/src/main.rs` — construct the channel + spawn the flush task alongside the existing `events::EventSink` / `drain_handle` setup; join it during graceful shutdown using the same `AEGIS_DRAIN_TIMEOUT_SECS` pattern.
  - `gateway/benches/` — new criterion benchmark comparing N sequential `insert_audit_event` calls vs. the batch path.
- **Data layer:** no schema migration. `audit_events` table (`db.rs` ~line 349) and `AuditEventRecord` (`models.rs:507`) are unchanged. `insert_audit_events_batch` performs the same per-row column set inside a single `tx.begin()/commit()`, using a repeated fixed `(?, ?, ..., ?)` placeholder group per row (17 columns) — no string-built values, just placeholder repetition, same as `INSERT ... VALUES (?,...), (?,...)`.
- **Dependencies:** none new (uses existing `sqlx`, `tokio::sync::mpsc`, `tokio::time`).

## 2. Step-by-Step Execution Phases

- **Phase 1: Database Migration** — N/A. No schema change; `insert_audit_events_batch` targets the existing `audit_events` table.

- **Phase 2: Gateway Implementation**
  1. `gateway/src/db.rs`: add `insert_audit_events_batch(pool: &SqlitePool, records: &[AuditEventRecord]) -> Result<(), sqlx::Error>`. Empty slice → `Ok(())` immediately (no-op). Otherwise open a transaction, build the INSERT with `records.len()` repeated `(?, ... 17 placeholders ...)` groups, bind every row's 17 columns in the same order/format as `insert_audit_event` (including the `"%F %T%.6f"` `created_at` formatting — extract that formatting into a small shared helper used by both functions so ordering guarantees stay identical), execute, commit.
  2. New module `gateway/src/audit_batch.rs`:
     - `pub const DEFAULT_BATCH_SIZE: usize = 100;` and `pub const DEFAULT_FLUSH_INTERVAL_MS: u64 = 500;`, both overridable via `AEGIS_AUDIT_BATCH_SIZE` / `AEGIS_AUDIT_BATCH_FLUSH_MS`.
     - `pub struct AuditBatchSink { tx: mpsc::Sender<AuditEventRecord> }` — `Clone`, mirrors `EventSink`'s shape.
     - `impl AuditBatchSink { pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<AuditEventRecord>) ...; pub fn emit(&self, record: AuditEventRecord) { let _ = self.tx.try_send(record); /* non-blocking; on full channel, fall back to logging a warn + the caller writes synchronously (see step 3) */ } }`.
     - `pub async fn run_audit_batch_writer(pool: SqlitePool, mut rx: mpsc::Receiver<AuditEventRecord>, batch_size: usize, flush_interval: Duration, audit_writer_unhealthy: Arc<AtomicBool>) -> usize` (returns total flushed count, mirroring `events::drain`'s return type for the shutdown log line):
       - Loop with `tokio::select!` between `rx.recv()` (push to `Vec`, flush immediately if `buf.len() >= batch_size`) and `interval.tick()` (flush if `!buf.is_empty()`).
       - `flush(&pool, &mut buf, &audit_writer_unhealthy)`: calls `db::insert_audit_events_batch`; on `Err`, sets `audit_writer_unhealthy.store(true, Relaxed)` and logs `error!`; on `Ok`, clears the flag the same way the existing synchronous path does today, and clears `buf`.
       - When `rx.recv()` returns `None` (all senders dropped — shutdown), flush any remaining buffered events once more and return.
  3. `gateway/src/routes.rs`:
     - `AppState` gains `pub audit_batch: audit_batch::AuditBatchSink`.
     - In `write_decision_and_audit`, after building `audit_record`: if the decision is **critical** (`decision == "deny" && risk_level_for_score(risk_score) == "critical"`, reusing the existing `risk_level_for_score` helper at `routes.rs:547`), call `db::insert_audit_event(pool, &audit_record).await?` directly (unchanged, synchronous, sets `audit_writer_unhealthy` via the existing `?` propagation path). Otherwise, call `state.audit_batch.emit(audit_record)` (non-blocking).
     - `try_send` failure (channel full) inside `emit` falls back to a synchronous `db::insert_audit_event` call so a saturated channel never silently drops an audit row — it just degrades to the pre-batching latency for that one event.
  4. `gateway/src/main.rs`: construct `audit_batch::AuditBatchSink::channel(...)`, `tokio::spawn(audit_batch::run_audit_batch_writer(pool.clone(), rx, batch_size, flush_interval, audit_writer_unhealthy_arc))`, store the join handle alongside `drain_handle`, and `tokio::time::timeout(Duration::from_secs(drain_timeout), audit_batch_handle).await` in the same shutdown block that already drains `drain_handle`. `audit_writer_unhealthy` currently lives on `AppState` as a plain `AtomicBool` (not `Arc`) — wrap it in `Arc<AtomicBool>` (or add a second `Arc<AtomicBool>` shared between `AppState` and the batch writer task) so both the request path and the background flush task can set/observe it.

- **Phase 3: Policy Integration** — N/A, no Cedar changes.

- **Phase 4: Client SDK/Decorator Updates** — N/A, server-internal only.

## 3. Verification & Testing Targets

- `gateway/src/audit_batch.rs` unit tests (`#[tokio::test]`, in-memory SQLite via the existing `setup_pool` pattern from `jobs.rs`):
  - flush triggers at `batch_size` events without waiting for the timer.
  - flush triggers on the timer interval when fewer than `batch_size` events arrive.
  - dropping the sender (simulating shutdown) flushes any remaining buffered events before the task returns.
  - `insert_audit_events_batch` with N records produces identical rows (same columns, same `created_at` formatting) to N sequential `insert_audit_event` calls.
- `gateway/src/routes.rs`: extend the existing `/v1/authorize` integration test(s) to assert that a non-critical decision's audit row eventually appears (poll/flush via a short test flush interval) and that a critical deny's audit row appears immediately (no batching).
- `gateway/benches/audit_batch_benchmark.rs` (new, criterion): N=1000 events via `insert_audit_event` in a loop vs. via `insert_audit_events_batch` in chunks of 100 — document the measured speedup in the PR description (target ~10x per AC).
- `cargo test --manifest-path gateway/Cargo.toml`, `cargo fmt -- --check`, `cargo clippy -- -D warnings`.

## 4. Security Audit Checklist

- [ ] `insert_audit_events_batch` uses only `?` placeholders, repeated per row — no `format!`/concatenation of row data into SQL text (CWE-89).
- [ ] Every batched `AuditEventRecord` already carries `tenant_id` from the originating request; batch insert binds it per row exactly as the single-row path does — no cross-tenant mixing risk (rows are independent, no shared WHERE clause).
- [ ] `audit_writer_unhealthy` is set on **both** the synchronous critical-event path and the async batch-flush failure path, and is shared via `Arc` so `/readyz` reflects either.
- [ ] Critical (`deny` + `critical` risk) audit rows remain synchronous — the highest-severity events are never delayed or at risk of being lost in an unflushed buffer.
- [ ] Graceful shutdown flushes the batch buffer (bounded by `AEGIS_DRAIN_TIMEOUT_SECS`, same as the existing SOC event drain) so no audit rows are silently dropped on normal shutdown.
- [ ] Channel-full fallback (`try_send` failure → synchronous insert) means a saturated batcher degrades gracefully instead of dropping events.
