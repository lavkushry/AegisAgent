#![allow(unused_imports)]
use crate::error::StatusError;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{error, info, warn};
use unicode_normalization::UnicodeNormalization;
use utoipa::OpenApi;
use uuid::Uuid;

use crate::db;
use crate::events::{AseEvent, EventSink};
use crate::mcp_inspect;
use crate::metrics::{is_untrusted_provenance, SecurityMetrics};
use crate::models::*;
use crate::policy::PolicyEngine;
use crate::sign;
use aegis_storage::traits::StorageBackend;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::Instant;

// Domain Sub-modules
pub mod agents;
pub mod approval;
pub mod authorize;
pub mod authorize_canon;
pub mod authorize_decision;
pub mod authorize_receipts;
pub mod dashboard;
pub mod graph;
pub mod mcp;
pub mod openapi;
pub mod policy;
pub mod receipts;
pub mod soc;
pub mod tenant;
pub mod webhooks;

// Re-export all handlers & types to maintain flat namespace
pub use agents::*;
pub use approval::*;
pub use authorize::*;
pub use authorize_canon::*;
pub use authorize_decision::*;
pub use authorize_receipts::*;
pub use dashboard::*;
pub use graph::*;
pub use mcp::*;
pub use openapi::*;
pub use policy::*;
pub use receipts::*;
pub use soc::*;
pub use tenant::*;
pub use webhooks::*;
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_refreshed: Instant,
}

#[derive(Debug)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, TokenBucket>>,
    pub capacity: f64,
    pub refill_rate: f64,
}

impl RateLimiter {
    pub fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            capacity,
            refill_rate,
        }
    }

    pub fn check_rate_limit(&self, tenant_id: &str) -> bool {
        if self.capacity <= 0.0 || self.refill_rate <= 0.0 {
            return true;
        }

        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        let bucket = buckets
            .entry(tenant_id.to_string())
            .or_insert_with(|| TokenBucket {
                tokens: self.capacity,
                last_refreshed: now,
            });

        let elapsed = now.duration_since(bucket.last_refreshed).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_rate).min(self.capacity);
        bucket.last_refreshed = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct QuotaManager {
    quotas: Mutex<HashMap<String, (u64, Instant)>>,
    pub limit: u64,
    pub window_secs: u64,
}

impl QuotaManager {
    pub fn new(limit: u64, window_secs: u64) -> Self {
        Self {
            quotas: Mutex::new(HashMap::new()),
            limit,
            window_secs,
        }
    }

    pub fn check_quota(&self, tenant_id: &str) -> bool {
        if self.limit == 0 {
            return true;
        }

        let mut quotas = self.quotas.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        let (count, window_start) = quotas
            .entry(tenant_id.to_string())
            .or_insert_with(|| (0, now));

        if now.duration_since(*window_start).as_secs() >= self.window_secs {
            *count = 0;
            *window_start = now;
        }

        if *count < self.limit {
            *count += 1;
            true
        } else {
            false
        }
    }
}

/// Per-`approval_id` failed-attempt tracker (#1307, AC#2): brute-forcing
/// approval IDs against `POST /v1/approvals/:id/{approve,reject,edit}`
/// produces a stream of 404 (unknown id) or 409 (already-decided/expired)
/// responses for the *same* `approval_id`. This counts only those failure
/// outcomes (never successful 200s) in a fixed window and fails closed with
/// 429 once the limit is reached, independent of the per-IP limiter (an
/// attacker rotating source IPs cannot bypass this).
#[derive(Debug)]
pub struct ApprovalAttemptTracker {
    attempts: Mutex<HashMap<String, (u64, Instant)>>,
    pub limit: u64,
    pub window_secs: u64,
}

impl ApprovalAttemptTracker {
    pub fn new(limit: u64, window_secs: u64) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            limit,
            window_secs,
        }
    }

    /// Returns `true` if `approval_id` has already accumulated `limit` or
    /// more failed attempts within the current window (i.e. the caller
    /// should respond 429 without performing any DB work). Does not mutate
    /// state — call [`record_failure`](Self::record_failure) separately
    /// once an attempt is determined to have failed.
    pub fn is_blocked(&self, approval_id: &str) -> bool {
        if self.limit == 0 {
            return false;
        }

        let mut attempts = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        match attempts.get_mut(approval_id) {
            Some((count, window_start)) => {
                if now.duration_since(*window_start).as_secs() >= self.window_secs {
                    *count = 0;
                    *window_start = now;
                    false
                } else {
                    *count >= self.limit
                }
            }
            None => false,
        }
    }

    /// Records a failed (4xx) approval-decision attempt for `approval_id`.
    pub fn record_failure(&self, approval_id: &str) {
        if self.limit == 0 {
            return;
        }

        let mut attempts = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        let entry = attempts
            .entry(approval_id.to_string())
            .or_insert_with(|| (0, now));

        if now.duration_since(entry.1).as_secs() >= self.window_secs {
            entry.0 = 0;
            entry.1 = now;
        }

        entry.0 += 1;
    }
}

/// The static registration metadata a `skill_actions` row contributes to a
/// decision: `(risk, mutates_state, approval_required, default_decision)`.
pub type SkillActionMeta = (String, bool, bool, String);

/// Bounded, tenant-keyed LRU cache for `db::get_skill_action` lookups on the
/// authorize hot path (#899). This caches **only static registration metadata**
/// that changes solely when a tool/MCP action is (re-)registered — and every such
/// write invalidates the key (see `register_tool` / `discover_mcp_tools`). The
/// Cedar decision itself is **never** cached: this only avoids a DB JOIN per
/// authorize, so it cannot change a decision. Fail-closed by construction —
/// only *positive* hits are stored; an unknown action keeps missing to the DB,
/// and a stale entry can never outlive the registration that would loosen it.
pub struct SkillActionCache {
    inner: Mutex<SkillActionCacheInner>,
    capacity: usize,
}

#[derive(Default)]
struct SkillActionCacheInner {
    map: HashMap<String, SkillActionMeta>,
    /// Recency order, least-recent at the front.
    order: VecDeque<String>,
}

impl SkillActionCache {
    /// `capacity == 0` disables the cache (every lookup misses, nothing stored).
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(SkillActionCacheInner::default()),
            capacity,
        }
    }

    pub fn cache_key(tenant_id: &str, skill_key: &str, action_key: &str) -> String {
        // \x1f (unit separator) cannot appear in these identifiers, so the join
        // is unambiguous across the three tenant-scoped components.
        format!("{tenant_id}\x1f{skill_key}\x1f{action_key}")
    }

    fn touch(order: &mut VecDeque<String>, key: &str) {
        if let Some(pos) = order.iter().position(|k| k == key) {
            order.remove(pos);
        }
        order.push_back(key.to_string());
    }

    /// Return a cached positive hit, marking it most-recently-used.
    pub fn get(&self, key: &str) -> Option<SkillActionMeta> {
        if self.capacity == 0 {
            return None;
        }
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let val = inner.map.get(key).cloned();
        if val.is_some() {
            Self::touch(&mut inner.order, key);
        }
        val
    }

    /// Store a positive lookup result, evicting the least-recent entry if full.
    pub fn insert(&self, key: String, value: SkillActionMeta) {
        if self.capacity == 0 {
            return;
        }
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        inner.map.insert(key.clone(), value);
        Self::touch(&mut inner.order, &key);
        while inner.map.len() > self.capacity {
            if let Some(evict) = inner.order.pop_front() {
                inner.map.remove(&evict);
            } else {
                break;
            }
        }
    }

    /// Drop a key so the next lookup re-reads the DB (called on every
    /// registration write that could change the action's settings).
    pub fn invalidate(&self, key: &str) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        inner.map.remove(key);
        if let Some(pos) = inner.order.iter().position(|k| k == key) {
            inner.order.remove(pos);
        }
    }
}

/// In-memory, bounded LRU dedup cache for `/v1/authorize` replay-protection
/// nonces (#1306, opt-in). Keyed on `(tenant_id, agent_id, nonce)` so two
/// different agents (or tenants) can independently use the same nonce
/// string without colliding — replay protection is a per-agent guarantee,
/// not a global one.
///
/// This is intentionally **not** a strict 5-minute time-bounded cache: it is
/// a capacity-bounded LRU, so an entry can in principle be evicted before 5
/// minutes elapse under very high request volume for that tenant/agent, or
/// persist in memory slightly longer than 5 minutes under low volume. The
/// AC's "5-minute window" is *approximated* by the combination of:
///   1. This LRU (catches the common case: duplicate nonce arriving while
///      still "hot" in memory), and
///   2. The `timestamp` staleness check in `authorize_action`, which
///      independently rejects any request whose `timestamp` is more than 5
///      minutes old — bounding how long a captured request remains
///      "replayable" even if its nonce has aged out of this cache.
///
/// This mirrors the documented approximation style of #1305/#1313. A
/// strict, durable replay window would require a DB-backed or
/// timestamp-bucketed store, which is explicitly out of scope per the issue
/// ("nonce deduplication via in-memory LRU cache, not DB — hot path").
pub struct ReplayNonceCache {
    inner: Mutex<ReplayNonceCacheInner>,
    capacity: usize,
}

#[derive(Default)]
struct ReplayNonceCacheInner {
    seen: HashMap<String, DateTime<Utc>>,
    /// Recency order, least-recent at the front.
    order: VecDeque<String>,
}

impl ReplayNonceCache {
    /// `capacity == 0` disables the cache (every nonce is treated as unseen).
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(ReplayNonceCacheInner::default()),
            capacity,
        }
    }

    /// Build the composite cache key for a `(tenant, agent, nonce)` triple.
    /// `\x1f` (unit separator) cannot appear in tenant/agent identifiers, so
    /// the join is unambiguous.
    pub fn cache_key(tenant_id: &str, agent_id: &str, nonce: &str) -> String {
        format!("{tenant_id}\x1f{agent_id}\x1f{nonce}")
    }

    /// Atomically check-and-insert: returns `true` if `key` was already
    /// present (replay), or `false` if this is the first time it has been
    /// seen (and records it as seen now), evicting the least-recently-used
    /// entry if the cache is at capacity.
    pub fn check_and_insert(&self, key: &str, now: DateTime<Utc>) -> bool {
        if self.capacity == 0 {
            return false;
        }
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if inner.seen.contains_key(key) {
            if let Some(pos) = inner.order.iter().position(|k| k == key) {
                inner.order.remove(pos);
            }
            inner.order.push_back(key.to_string());
            return true;
        }
        inner.seen.insert(key.to_string(), now);
        inner.order.push_back(key.to_string());
        while inner.seen.len() > self.capacity {
            if let Some(evict) = inner.order.pop_front() {
                inner.seen.remove(&evict);
            } else {
                break;
            }
        }
        false
    }
}

/// #1513: per-tenant TTL cache for [`crate::risk::RiskWeights`]. Risk weights
/// are operator-configured (`PUT /v1/tenants/risk-weights`) and change only
/// rarely, yet `db::get_risk_weights` was previously re-read from SQLite on
/// every single `/v1/authorize` call inside `write_decision_and_audit`. A
/// plain TTL cache (not an LRU like [`SkillActionCache`]) is sufficient here:
/// the per-tenant key space is small and bounded by the number of registered
/// tenants, so unbounded growth isn't a practical concern.
///
/// `get`/`insert` take an explicit `now: Instant` (mirroring
/// [`ReplayNonceCache::check_and_insert`]'s explicit `now` parameter) so TTL
/// expiry can be tested deterministically without real sleeps.
pub struct RiskWeightsCache {
    inner: Mutex<HashMap<String, (crate::risk::RiskWeights, Instant)>>,
    ttl: std::time::Duration,
}

/// Default cache TTL: risk weights are operator-configured and change only
/// rarely, so a 60-second staleness window is an acceptable tradeoff against
/// eliminating a DB read on (effectively) every `/v1/authorize` call.
pub const DEFAULT_RISK_WEIGHTS_CACHE_TTL_SECS: u64 = 60;

impl RiskWeightsCache {
    pub fn new(ttl: std::time::Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Return a cached value for `tenant_id` if present and not yet stale as
    /// of `now`. A miss (absent, or older than `ttl`) returns `None` — the
    /// caller is expected to fall through to `db::get_risk_weights` and
    /// `insert` the fresh result.
    pub fn get(&self, tenant_id: &str, now: Instant) -> Option<crate::risk::RiskWeights> {
        let inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        inner.get(tenant_id).and_then(|(weights, cached_at)| {
            if now.saturating_duration_since(*cached_at) < self.ttl {
                Some(*weights)
            } else {
                None
            }
        })
    }

    pub fn insert(&self, tenant_id: &str, weights: crate::risk::RiskWeights, now: Instant) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        inner.insert(tenant_id.to_string(), (weights, now));
    }

    /// Drop a tenant's cached entry so the next lookup re-reads the DB.
    /// Called from `PUT /v1/tenants/risk-weights` so an operator-issued
    /// override takes effect immediately rather than waiting out the TTL.
    pub fn invalidate(&self, tenant_id: &str) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        inner.remove(tenant_id);
    }
}

/// #1512: tracks in-flight "fire-and-forget" background writes spawned off
/// the `/v1/authorize` hot path — the historical risk-score sample
/// (`StorageBackend::insert_agent_risk_score`) and the verifiable receipt
/// write (`StorageBackend::append_action_receipt_atomic`). Both are
/// best-effort and have always been allowed to fail without affecting the
/// returned decision; the only change is *when* they run. Previously they
/// were `.await`ed inline, competing for the SQLite WAL write lock with the
/// real decision write on every single request. Now they're spawned onto a
/// tracked background task instead, so the response returns as soon as the
/// decision/audit row lands.
///
/// Mirrors the [`HeartbeatDebouncer`] pattern below: an `Arc`-shared counter
/// the hot path touches without blocking, drained by a slower path (test
/// assertions, or graceful shutdown) on a bounded timeout — so a deferred
/// write is observable/waitable, never silently dropped.
#[derive(Default)]
pub struct DeferredWriteTracker {
    in_flight: std::sync::atomic::AtomicUsize,
}

/// RAII guard decrementing [`DeferredWriteTracker::in_flight`] on drop. Fires
/// whether the tracked future completes normally OR panics, so a panicking
/// deferred write can never permanently wedge [`DeferredWriteTracker::drain`].
struct InFlightGuard {
    tracker: Arc<DeferredWriteTracker>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.tracker
            .in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl DeferredWriteTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current number of in-flight deferred writes. Test/diagnostic use only.
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Spawn `fut` as a tracked background task: increments the in-flight
    /// counter before spawning, decrements it when `fut` completes (or
    /// panics) via [`InFlightGuard`]'s `Drop`. Never awaited by the caller —
    /// this is the whole point, the hot path returns immediately.
    pub fn spawn_tracked<F>(self: &Arc<Self>, fut: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        self.in_flight
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let guard = InFlightGuard {
            tracker: Arc::clone(self),
        };
        tokio::spawn(async move {
            fut.await;
            drop(guard);
        });
    }

    /// Poll until every tracked write has completed, or `timeout` elapses.
    /// Returns `true` if drained cleanly, `false` on timeout. Used at
    /// graceful shutdown (so a deferred write is never silently lost when the
    /// process exits) and in tests asserting that a deferred write has
    /// landed before checking its effect.
    pub async fn drain(&self, timeout: std::time::Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        while self.in_flight_count() > 0 {
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        true
    }
}

/// Run a `StorageBackend` write, retrying up to `max_retries` additional
/// times with exponential backoff (1ms, 2ms, 4ms, ...) if it fails with a
/// transient `SQLITE_BUSY`/`SQLITE_LOCKED` error — mirrors
/// `aegis_storage::db::retry_on_busy`, but operates on `AegisError` since
/// `StorageBackend` trait methods return that rather than a raw
/// `sqlx::Error`. Needed for the #1512 deferred writes
/// (`insert_agent_risk_score`, `append_action_receipt_atomic`), whose
/// `SqliteStorage` impls don't retry internally themselves (unlike
/// `insert_decision`, which already retries inside the trait impl).
pub(crate) async fn retry_storage_write_on_busy<F, Fut, T>(
    max_retries: u32,
    mut f: F,
) -> Result<T, aegis_common::errors::AegisError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, aegis_common::errors::AegisError>>,
{
    fn is_retryable(err: &aegis_common::errors::AegisError) -> bool {
        matches!(
            err,
            aegis_common::errors::AegisError::Database(sqlx::Error::Database(db_err))
                if matches!(db_err.code().as_deref(), Some("5") | Some("6"))
        )
    }

    let mut attempt = 0;
    loop {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) if attempt < max_retries && is_retryable(&e) => {
                let delay_ms = 1u64 << attempt;
                tracing::debug!(
                    "retrying deferred write after SQLITE_BUSY/LOCKED (attempt {}/{}, backoff {}ms): {}",
                    attempt + 1,
                    max_retries,
                    delay_ms,
                    e
                );
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod deferred_write_tracker_tests {
    use super::DeferredWriteTracker;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn deferred_write_tracker_tracks_in_flight_and_drains() {
        let tracker = Arc::new(DeferredWriteTracker::new());
        assert_eq!(tracker.in_flight_count(), 0);

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tracker.spawn_tracked(async move {
            let _ = rx.await;
        });
        assert_eq!(tracker.in_flight_count(), 1);

        // Nothing has released the in-flight task yet — drain should time
        // out rather than report a false "drained".
        let drained_too_early = tracker.drain(Duration::from_millis(50)).await;
        assert!(!drained_too_early);
        assert_eq!(tracker.in_flight_count(), 1);

        // Release the task; drain should now observe it complete.
        let _ = tx.send(());
        let drained = tracker.drain(Duration::from_secs(5)).await;
        assert!(drained);
        assert_eq!(tracker.in_flight_count(), 0);
    }

    #[tokio::test]
    async fn deferred_write_tracker_decrements_on_panic() {
        let tracker = Arc::new(DeferredWriteTracker::new());
        tracker.spawn_tracked(async move {
            panic!("simulated deferred-write panic");
        });

        // The InFlightGuard's Drop runs even when the tracked future panics
        // (tokio isolates the panic to the spawned task), so drain must not
        // wedge forever waiting on a task that already died.
        let drained = tracker.drain(Duration::from_secs(5)).await;
        assert!(drained);
        assert_eq!(tracker.in_flight_count(), 0);
    }
}

/// #1511: debounces `db::touch_agent_last_seen` writes off the `/v1/authorize`
/// hot path. That write previously ran inline on every single call, competing
/// for the SQLite WAL write lock with the real decision write
/// (`insert_decision`) on every request. The heartbeat doesn't need
/// millisecond precision, so `touch` just records *that* `(tenant_id,
/// agent_id)` was active — non-blocking, in-memory, no DB I/O — and a
/// periodic background job (`jobs::run_heartbeat_flush_job`) drains the set
/// and issues the real `last_seen_at` writes on a fixed interval (default
/// 30s). `last_seen_at` accuracy degrades from real-time to roughly that
/// interval, which is an explicitly accepted tradeoff.
///
/// Unlike the `is_leader`-gated maintenance jobs (vacuum, archival, etc.),
/// flushing is **not** leader-gated: heartbeats are inherently
/// per-instance-observed activity (each gateway instance only ever sees the
/// touches from requests it personally handled), and the write itself is
/// idempotent/commutative — whichever instance's flush lands last simply
/// reflects the most recent observed activity, with no conflict between
/// instances sharing one DB.
#[derive(Default)]
pub struct HeartbeatDebouncer {
    dirty: Mutex<HashSet<(String, String)>>,
}

impl HeartbeatDebouncer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `(tenant_id, agent_id)` was active "now". Non-blocking:
    /// only touches an in-memory set, never the database.
    pub fn touch(&self, tenant_id: &str, agent_id: &str) {
        let mut dirty = match self.dirty.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        dirty.insert((tenant_id.to_string(), agent_id.to_string()));
    }

    /// Atomically remove and return every pending `(tenant_id, agent_id)`
    /// pair. Draining (rather than just reading) means a `touch` that lands
    /// concurrently with a flush is preserved for the *next* flush instead
    /// of being lost.
    pub fn drain(&self) -> Vec<(String, String)> {
        let mut dirty = match self.dirty.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        std::mem::take(&mut *dirty).into_iter().collect()
    }

    /// Number of distinct agents with a pending (not-yet-flushed) heartbeat.
    /// Test/diagnostic use only.
    pub fn pending_count(&self) -> usize {
        let dirty = match self.dirty.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        dirty.len()
    }
}

// Shared app state containing DB pool, Cedar policy engine, and the async SOC
// event sink (Phase 0): the authorize hot path emits decisions onto it.
pub struct AppState {
    pub pool: sqlx::SqlitePool,
    pub storage: Arc<dyn StorageBackend>,
    pub policy_engine: PolicyEngine,
    pub events: EventSink,
    /// Process-wide security counters exposed on GET /metrics. Shared
    /// (`Arc`) with the [`EventSink`] and the out-of-band `drain` task so
    /// alert/incident/event counters can be incremented out-of-band.
    pub metrics: Arc<SecurityMetrics>,
    /// Approval time-to-live in seconds. Configurable via AEGIS_APPROVAL_TTL_SECS
    /// environment variable (default: 1800 = 30 minutes).
    pub approval_ttl_secs: i64,
    pub rate_limiter: RateLimiter,
    pub quota_manager: QuotaManager,
    /// Per-source-IP rate limiter for approval-decision callbacks (#1307,
    /// AC#1): `POST /v1/approvals/:id/{approve,reject,edit}`. Capacity 10,
    /// refilling at 10/min — independent of the per-tenant `rate_limiter`
    /// above (which guards `/v1/authorize`).
    pub approval_callback_ip_limiter: RateLimiter,
    /// Per-`approval_id` failed-attempt tracker for approval-decision
    /// callbacks (#1307, AC#2). See [`ApprovalAttemptTracker`].
    pub approval_attempt_tracker: ApprovalAttemptTracker,
    /// Read-through cache for registered-action metadata (#899).
    pub skill_cache: SkillActionCache,
    /// Opt-in replay-protection nonce dedup cache (#1306). See
    /// [`ReplayNonceCache`] for the LRU + timestamp-window approximation.
    pub replay_nonce_cache: ReplayNonceCache,
    /// TTL cache for per-tenant composite-risk-score weights (#1513). See
    /// [`RiskWeightsCache`].
    pub risk_weight_cache: RiskWeightsCache,
    /// Debounces `last_seen_at` heartbeat writes off the `/v1/authorize` hot
    /// path (#1511). `Arc`-shared with `jobs::run_heartbeat_flush_job`
    /// (mirrors how `audit_writer_unhealthy` is shared with the audit-batch
    /// writer task) so the periodic flush job can drain the same in-memory
    /// set the request handlers write into. See [`HeartbeatDebouncer`].
    pub heartbeat_debouncer: Arc<HeartbeatDebouncer>,
    /// Tracks in-flight fire-and-forget background writes spawned off the
    /// `/v1/authorize` hot path (#1512: risk-score sample, verifiable
    /// receipt). See [`DeferredWriteTracker`].
    pub deferred_write_tracker: Arc<DeferredWriteTracker>,
    /// Set to `true` once startup initialization (DB pool, migrations, policy
    /// engine, background jobs) has completed. Backs `GET /startupz` (#1208)
    /// so orchestrators can distinguish "still starting" from "ready".
    pub startup_complete: std::sync::atomic::AtomicBool,
    /// Set to `true` when the most recent attempt to persist a decision/audit
    /// record to SQLite failed. Cleared back to `false` on the next successful
    /// write. Backs the `audit_writer` field on `GET /readyz` (#1299). Shared
    /// (`Arc`) with the audit-batch writer task (#1315) so a failed batch
    /// flush surfaces the same readiness signal as a failed synchronous write.
    pub audit_writer_unhealthy: Arc<std::sync::atomic::AtomicBool>,
    /// Non-blocking sink for batched `audit_events` writes (#1315). The
    /// `/v1/authorize` hot path hands non-critical audit rows to this sink
    /// instead of inserting them one at a time; a background task
    /// ([`crate::audit_batch::run_audit_batch_writer`]) flushes them in
    /// bulk. Critical events (deny on critical risk) bypass this sink and
    /// are written synchronously.
    pub audit_batch: crate::audit_batch::AuditBatchSink,
    /// Opt-in HMAC-SHA256 secret for verifying `X-Hub-Signature-256` on
    /// `POST /v1/ingest` requests with `source: "github_webhook"` (#1339).
    /// Configured via `AEGIS_GITHUB_WEBHOOK_SECRET`. When `None` (the
    /// default), signature verification is skipped entirely, preserving
    /// pre-#1339 behavior.
    pub github_webhook_secret: Option<String>,
    /// HMAC-SHA256 signing secret for verifying `X-Slack-Signature` on
    /// `POST /v1/callbacks/slack` (#1276). Configured via
    /// `AEGIS_SLACK_SIGNING_SECRET`. When `None`, the endpoint refuses every
    /// request with `404` — fail closed, since an unconfigured secret means
    /// no valid signature can ever be verified.
    pub slack_signing_secret: Option<String>,
    /// Optional GitHub App PR commenter (#1382). When `Some`, a background
    /// task posts a deny comment on GitHub PRs when an agent's PR-related
    /// action is denied. Configured via `AEGIS_GITHUB_APP_TOKEN`. When
    /// `None`, PR comments are silently skipped.
    pub github_pr_commenter: Option<std::sync::Arc<crate::gh_comment::GhPrCommenter>>,
    /// Optional GitHub Checks API client (#1383). When `Some`, every decision
    /// on a PR-related GitHub action updates an "Aegis Security Gate" check
    /// run on the PR's head commit. Configured via `AEGIS_GITHUB_APP_TOKEN`
    /// (same token as [`Self::github_pr_commenter`]). When `None`, check runs
    /// are silently skipped.
    pub github_checks_client: Option<std::sync::Arc<crate::gh_checks::GhChecksClient>>,
    /// Optional Qdrant exporter for semantic audit log vector indexing.
    pub qdrant_exporter: Option<Arc<crate::qdrant::QdrantExporter>>,
    /// Optional pre-authorize admission webhook (#1143, API-004). When
    /// `Some`, every `/v1/authorize` call is sent to the configured
    /// `AEGIS_ADMISSION_WEBHOOK_URL` before Cedar evaluation, which may pass,
    /// reject, or mutate the request's `tool_call.parameters`. `None` (the
    /// default) makes `/v1/authorize` byte-for-byte unchanged from
    /// pre-#1143 behavior — no extra network call at all.
    pub admission_webhook: Option<Arc<crate::admission::AdmissionWebhookClient>>,
    /// Abort handles for fire-and-forget background tasks (event drain,
    /// audit-batch writer, periodic jobs) (#1152). `AbortHandle::is_finished()`
    /// is a zero-I/O signal that a task panicked and permanently stopped
    /// running, backing the `background_tasks` field on `GET /readyz`. Each
    /// handle is cloned from its task's `JoinHandle` at spawn time via
    /// `JoinHandle::abort_handle()` — this never aborts the task itself (only
    /// calling `.abort()` does), so the original `JoinHandle` can still be
    /// owned and awaited elsewhere (e.g. graceful shutdown draining the event
    /// channel). Empty in tests, which never spawn the real background tasks.
    pub background_task_handles: std::sync::Mutex<Vec<(&'static str, tokio::task::AbortHandle)>>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Claims {
    sub: String,
    tenant_id: Option<String>,
    exp: usize,
}

/// Splits `AEGIS_JWT_SECRET` on `,` for zero-downtime rotation (#1211): during
/// a rotation window, operators set the value to `"new_secret,old_secret"` so
/// tokens signed with either are still accepted, then drop the old entry once
/// every outstanding token has expired or been reissued. A bare single-secret
/// value (the pre-#1211 format) is just a one-element list, so this stays
/// backward-compatible. Filters out empty/`"default_secret"` entries so a
/// stray trailing comma or the documented disable-sentinel doesn't become a
/// silently-accepted decoding key.
/// `pub` (not `pub(crate)`) so `main.rs`'s binary target — a separate crate
/// from this lib, per `lib.rs`'s doc comment — can reuse the same filtering
/// logic for its startup JWT-secret validation instead of duplicating it.
pub fn jwt_secret_candidates(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "default_secret")
        .map(str::to_string)
        .collect()
}

pub(crate) fn validate_jwt(token: &str) -> Option<String> {
    let raw_secret = std::env::var("AEGIS_JWT_SECRET").ok()?;
    let candidates = jwt_secret_candidates(&raw_secret);
    let validation = jsonwebtoken::Validation::default();
    candidates.iter().find_map(|secret| {
        let key = jsonwebtoken::DecodingKey::from_secret(secret.as_bytes());
        jsonwebtoken::decode::<Claims>(token, &key, &validation)
            .map(|data| data.claims.tenant_id.unwrap_or(data.claims.sub))
            .ok()
    })
}

// Extractor helper to get tenant_id from Bearer token
#[derive(Debug, Clone)]
pub struct TenantId(pub String);

#[axum::async_trait]
impl<S> axum::extract::FromRequestParts<S> for TenantId
where
    S: Send + Sync,
    Arc<AppState>: axum::extract::FromRef<S>,
{
    type Rejection = StatusError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .ok_or(StatusError::unauthorized("Missing Authorization header"))?;

        if !auth_header.starts_with("Bearer ") {
            return Err(StatusError::unauthorized("Invalid Authorization format"));
        }

        let token = &auth_header["Bearer ".len()..];

        // Try proper JWT validation first
        let tenant_id = if let Some(t_id) = validate_jwt(token) {
            t_id
        } else {
            // Check if JWT validation is strictly required
            if std::env::var("AEGIS_JWT_REQUIRED")
                .map(|v| v == "true")
                .unwrap_or(false)
            {
                return Err(StatusError::unauthorized("Invalid or expired JWT token"));
            }

            // Fallback to old heuristic
            if token.starts_with("tenant_") {
                token.to_string()
            } else {
                return Err(StatusError::unauthorized("Invalid token. Bearer token must start with 'tenant_' when JWT is not required"));
            }
        };

        // Extract AppState to verify tenant existence in DB
        let app_state = <Arc<AppState> as axum::extract::FromRef<S>>::from_ref(state);

        match app_state.storage.get_tenant_by_id(&tenant_id).await {
            Ok(Some(_)) => Ok(TenantId(tenant_id)),
            Ok(None) => Err(StatusError::not_found(format!(
                "Tenant '{}' not found",
                tenant_id
            ))),
            Err(e) => {
                error!("Database error checking tenant: {:?}", e);
                Err(StatusError::internal("Database error checking tenant"))
            }
        }
    }
}

pub(crate) fn get_runtime_tenant_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("X-Aegis-Tenant-ID")
        .or_else(|| headers.get("X-Tenant-ID"))
        .and_then(|h| h.to_str().ok())
        .filter(|tenant_id| !tenant_id.trim().is_empty())
        .map(str::to_string)
}

pub(crate) fn mcp_server_key_from_tool(tool: &str) -> Option<&str> {
    tool.strip_prefix("mcp:")
        .filter(|server_key| !server_key.is_empty())
}

/// TASK-XXXX (#1335): normalize a tool/action identifier before authorization
/// lookups (`mcp_server_key_from_tool`, `db::get_skill_action`,
/// `db::get_mcp_tool_by_key`) so that percent-encoding, Unicode normalization
/// form, or letter-case variation cannot be used to dodge the deny-by-default
/// "unknown tool" / "unknown MCP server" checks — e.g. `my_tool`, `My_Tool`,
/// and `my%5Ftool` must all resolve to the same registered identifier (or all
/// be denied as unknown). Percent-decodes, applies Unicode NFC, then
/// lowercases. The action_hash / canonicalized payload always uses the
/// original, un-normalized strings from `payload.tool_call` — only
/// authorization lookups use the normalized form.
pub(crate) fn normalize_tool_identifier(value: &str) -> String {
    let decoded = percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| value.to_string());
    // Trim surrounding whitespace BEFORE lowercasing so any Unicode
    // whitespace-lookalike at boundaries is removed regardless of case.
    decoded.nfc().collect::<String>().trim().to_lowercase()
}

/// Deterministic, order-independent hash of an MCP server's advertised tool
/// manifest. Re-discovery recomputes this and compares it to the value pinned on
/// the server row; a mismatch is tool-manifest drift (supply-chain / tool-hijack
/// signal — the threat the `mcp_manifest_drift` SOC rule surfaces).
///
/// This is a server-integrity hash, NOT the byte-parity-locked `aegis-jcs-1`
/// action/receipt hash, so it carries its own `mcp-manifest-1` scheme tag and is
/// not covered by the cross-language corpus. It hashes only the security-relevant
/// shape of each tool (key, name, description, risk, mutation, approval, input
/// schema) — never any call payload. Tools are sorted by `tool_key` so discovery
/// order never changes the hash.
pub(crate) fn compute_mcp_manifest_hash(tools: &[McpToolManifestItem]) -> String {
    let mut entries: Vec<Value> = tools
        .iter()
        .map(|t| {
            json!({
                "tool_key": t.tool_key,
                "name": t.name,
                "description": t.description,
                "risk": t.risk,
                "mutates_state": t.mutates_state,
                "approval_required": t.approval_required,
                "input_schema": t.input_schema,
            })
        })
        .collect();
    entries.sort_by(|a, b| {
        a.get("tool_key")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .cmp(
                b.get("tool_key")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            )
    });
    let canonical = canonical_value_string(&Value::Array(entries));
    format!("sha256:{}", sha256_hex(canonical.as_bytes()))
}

/// #1336: classify MCP manifest drift and describe what changed between the
/// previously discovered manifest (`old_tools`) and the newly discovered one
/// (`new_tools`), so a binary hash mismatch becomes an actionable, severity-aware
/// alert instead of a single generic "drift" signal.
///
/// Returns the highest-severity classification that applies, in precedence order:
///   - `tool_added` / `tool_removed` — a tool was added or removed (high)
///   - `tool_modified` — an existing tool's risk/mutation/approval/input_schema
///     changed, e.g. a new parameter was added (medium)
///   - `metadata_changed` — only a tool's name/description changed (low)
///
/// along with a human-readable, secret-free diff summary (tool keys only).
pub(crate) fn classify_manifest_drift(
    old_tools: &[McpToolManifestItem],
    new_tools: &[McpToolManifestItem],
) -> (&'static str, String) {
    let old_by_key: BTreeMap<&str, &McpToolManifestItem> =
        old_tools.iter().map(|t| (t.tool_key.as_str(), t)).collect();
    let new_by_key: BTreeMap<&str, &McpToolManifestItem> =
        new_tools.iter().map(|t| (t.tool_key.as_str(), t)).collect();

    let added: Vec<&str> = new_by_key
        .keys()
        .filter(|k| !old_by_key.contains_key(*k))
        .copied()
        .collect();
    let removed: Vec<&str> = old_by_key
        .keys()
        .filter(|k| !new_by_key.contains_key(*k))
        .copied()
        .collect();

    let mut modified: Vec<&str> = Vec::new();
    let mut metadata_changed: Vec<&str> = Vec::new();
    for (key, new_tool) in &new_by_key {
        if let Some(old_tool) = old_by_key.get(key) {
            if old_tool.risk != new_tool.risk
                || old_tool.mutates_state != new_tool.mutates_state
                || old_tool.approval_required != new_tool.approval_required
                || old_tool.input_schema != new_tool.input_schema
            {
                modified.push(key);
            } else if old_tool.name != new_tool.name || old_tool.description != new_tool.description
            {
                metadata_changed.push(key);
            }
        }
    }

    let mut diff_parts: Vec<String> = Vec::new();
    if !added.is_empty() {
        diff_parts.push(format!("tools added: {}", added.join(", ")));
    }
    if !removed.is_empty() {
        diff_parts.push(format!("tools removed: {}", removed.join(", ")));
    }
    if !modified.is_empty() {
        diff_parts.push(format!("tools modified: {}", modified.join(", ")));
    }
    if !metadata_changed.is_empty() {
        diff_parts.push(format!("metadata changed: {}", metadata_changed.join(", ")));
    }

    let classification = if !added.is_empty() {
        "tool_added"
    } else if !removed.is_empty() {
        "tool_removed"
    } else if !modified.is_empty() {
        "tool_modified"
    } else if !metadata_changed.is_empty() {
        "metadata_changed"
    } else {
        // The manifest hash differs but no per-field diff was found (e.g. no prior
        // snapshot was available to diff against) — fail closed to the
        // medium-severity bucket rather than silently dropping the signal.
        "tool_modified"
    };

    let diff = if diff_parts.is_empty() {
        "manifest changed (no prior snapshot available to diff against)".to_string()
    } else {
        diff_parts.join("; ")
    };

    (classification, diff)
}

/// #1336: map a [`classify_manifest_drift`] classification to a SOC severity —
/// `tool_added`/`tool_removed` (a tool's presence changed) are `"high"`,
/// `tool_modified` (an existing tool's security-relevant shape changed, e.g. a
/// new parameter) is `"medium"`, and `metadata_changed` (cosmetic-only) is
/// `"low"`.
pub(crate) fn severity_for_manifest_drift(classification: &str) -> &'static str {
    match classification {
        "tool_added" | "tool_removed" => "high",
        "tool_modified" => "medium",
        _ => "low",
    }
}

/// Canonical (scheme `aegis-jcs-1`) string for an arbitrary JSON value. Used for
/// action-receipt hashing; MUST match the SDK's `canonicalize()` byte-for-byte
/// (see `docs/action-receipt-spec.md` and `tests/receipt_chain_vectors.json`).
pub(crate) fn canonical_value_string(value: &Value) -> String {
    serde_json::to_string(&canonicalize_json(value.clone())).unwrap_or_default()
}

/// The hashed body of an action receipt: every semantic field plus the chain
/// link, excluding `receipt_hash` and the volatile DB `created_at`. Built
/// identically at emit time and verify time so the hash is reproducible. All
/// fields are strings/null (no round-trip drift). Scheme aegis-jcs-1.
pub(crate) fn receipt_body_value(rec: &ActionReceiptRecord) -> Value {
    json!({
        "event_id": rec.id,
        "ts": rec.ts,
        "agent_id": rec.agent_id,
        "user_id": rec.user_id,
        "run_id": rec.run_id,
        "trace_id": rec.trace_id,
        "tool": rec.tool,
        "action": rec.action,
        "resource": rec.resource,
        "source_trust": rec.source_trust,
        "decision": rec.decision,
        "approver": rec.approver,
        "action_hash": rec.action_hash,
        "prev_receipt_hash": rec.prev_receipt_hash,
    })
}

/// `pub` (not `pub(crate)`) so `benches/receipt_hash_benchmark.rs` (#1165,
/// TEST-005) can exercise the real receipt-hashing code path in-process,
/// matching the established pattern from `benches/authorize_benchmark.rs`
/// (TASK-1313)'s `lib.rs` re-export.
pub fn compute_receipt_hash(rec: &ActionReceiptRecord) -> String {
    sha256_hex(canonical_value_string(&receipt_body_value(rec)).as_bytes())
}

/// #1312: the hashed body of a `policy_audit_log` entry — every semantic field
/// plus the chain link, excluding `entry_hash` and the volatile DB
/// `created_at`. Mirrors [`receipt_body_value`]'s shape for the policy
/// transparency log. Scheme aegis-jcs-1.
pub(crate) fn policy_audit_log_entry_value(rec: &PolicyAuditLogRecord) -> Value {
    json!({
        "id": rec.id,
        "tenant_id": rec.tenant_id,
        "policy_id": rec.policy_id,
        "policy_key": rec.policy_key,
        "action": rec.action,
        "changed_by": rec.changed_by,
        "body_hash": rec.body_hash,
        "diff_summary": rec.diff_summary,
        "prev_hash": rec.prev_hash,
    })
}

pub(crate) fn compute_policy_audit_log_entry_hash(rec: &PolicyAuditLogRecord) -> String {
    sha256_hex(canonical_value_string(&policy_audit_log_entry_value(rec)).as_bytes())
}

// ── SOC Phase 5: Indexer Query API ───────────────────────────────────────────

/// Parse a `?limit=` / `?offset=` query string with sane defaults and hard caps.
/// Avoids extracting `axum::extract::Query<HashMap<…>>` to keep the code simple;
/// falls back to the default on any parse error.
pub(crate) fn parse_pagination(query: Option<&str>) -> (i64, i64) {
    let mut limit = db::SOC_DEFAULT_LIMIT;
    let mut offset = 0i64;

    if let Some(q) = query {
        for pair in q.split('&') {
            let mut kv = pair.splitn(2, '=');
            match (kv.next(), kv.next()) {
                (Some("limit"), Some(v)) => {
                    if let Ok(n) = v.parse::<i64>() {
                        limit = n;
                    }
                }
                (Some("offset"), Some(v)) => {
                    if let Ok(n) = v.parse::<i64>() {
                        offset = n.max(0);
                    }
                }
                _ => {}
            }
        }
    }
    (limit.clamp(1, db::SOC_MAX_LIMIT), offset)
}

/// Parse an optional equality filter value from a raw query string.
/// Returns `Some(value)` only when the key is present and non-empty; combined
/// with the `(? IS NULL OR col = ?)` SQL pattern this keeps all SQL strings
/// STATIC and avoids any concatenation (CWE-89 safe).
pub(crate) fn parse_filter(query: Option<&str>, key: &str) -> Option<String> {
    query?.split('&').find_map(|pair| {
        let mut kv = pair.splitn(2, '=');
        match (kv.next(), kv.next()) {
            (Some(k), Some(v)) if k == key && !v.is_empty() => Some(v.to_string()),
            _ => None,
        }
    })
}

/// #1157: a couple of destructive/state-changing admin endpoints
/// (`delete_agent`, `revoke_agent_tool_permission`) wrote no audit trail at
/// all — unlike their siblings (`freeze_agent`, `quarantine_mcp_server`,
/// `close_incident`, etc.), which already insert an operation-specific
/// `event_type` (e.g. `agent_frozen`, `mcp_server_quarantined`,
/// `incident_closed`) and are left unchanged here to avoid a breaking
/// rename. This helper gives the previously-uncovered endpoints a single,
/// filterable `event_type: "admin_action"`, with `action` distinguishing
/// the specific operation (`GET /v1/audit/events?event_type=admin_action`).
/// Deliberately excludes `delete_tenant`: a GDPR right-to-erasure delete
/// that wipes the tenant's own `audit_events` rows can't usefully audit
/// itself away.
/// Best-effort (errors are logged, never propagated) — matching every other
/// audit-write call site in this codebase, since a failed audit write must
/// never block the admin action it's describing.
pub(crate) async fn write_admin_action_audit_event(
    storage: &dyn StorageBackend,
    tenant_id: &str,
    action: &str,
    agent_id: Option<&str>,
    resource: Option<&str>,
    details: Value,
) {
    let audit = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.to_string(),
        event_type: "admin_action".to_string(),
        agent_id: agent_id.map(|s| s.to_string()),
        user_id: None,
        run_id: None,
        trace_id: None,
        span_id: None,
        skill: None,
        action: Some(action.to_string()),
        resource: resource.map(|s| s.to_string()),
        event_json: serde_json::to_string(&details).unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        decision_id: None,
        approval_id: None,
        created_at: Utc::now(),
    };
    if let Err(e) = storage.insert_audit_event(&audit).await {
        error!("Failed to write admin_action audit event ({action}): {e:?}");
    }
}

/// #1450: turns a raw `?q=` value into a safe SQLite FTS5 MATCH expression
/// for `GET /v1/decisions` / `GET /v1/audit/events` keyword search. Strips
/// every FTS5 query-syntax metacharacter (quotes, colons, parens, hyphens,
/// carets, asterisks, `%`/`+` from un-decoded URL encoding) so arbitrary
/// user input can never produce an FTS5 syntax error or be interpreted as a
/// column filter/boolean operator — only alphanumerics, underscores, and
/// whitespace survive. Appends a trailing `*` so the last token
/// prefix-matches (e.g. `?q=mer` matches `merge_pull_request`). Returns
/// `None` for an empty/all-stripped query (no filter applied, never an
/// unfiltered full scan in disguise). The result is only ever bound as a
/// parameter to a static `MATCH ?` SQL string (CWE-89 safe) — never
/// concatenated.
pub(crate) fn sanitize_fts5_query(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace() || *c == '_')
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(format!("{trimmed}*"))
    }
}

/// #1142: encodes a `rowid` into the opaque `?cursor=`/`X-Next-Cursor` token.
/// Hex rather than a new base64 dependency — opacity here is an API
/// ergonomics convention (discourage clients from relying on the cursor's
/// internal structure), not a security boundary, so trivial reversibility
/// is fine.
pub(crate) fn encode_cursor(rowid: i64) -> String {
    hex::encode(rowid.to_string())
}

/// Inverse of [`encode_cursor`]. Returns `None` for anything that doesn't
/// decode to a plain non-negative integer — callers treat that as a client
/// error (400), not a silently-ignored bad cursor, so a typo in a cursor
/// value doesn't quietly restart pagination from the top.
pub(crate) fn decode_cursor(cursor: &str) -> Option<i64> {
    let bytes = hex::decode(cursor).ok()?;
    let s = String::from_utf8(bytes).ok()?;
    s.parse::<i64>().ok().filter(|n| *n >= 0)
}

/// #1142: parses the optional `?cursor=` query param. `Ok(None)` when
/// absent (existing OFFSET-based behavior, unchanged); `Ok(Some(rowid))`
/// when present and valid; `Err(response)` — a 400 — when present but
/// malformed, so a typo'd cursor fails loudly instead of silently
/// restarting pagination from the top.
pub(crate) fn parse_cursor(
    query: Option<&str>,
) -> Result<Option<i64>, Box<axum::response::Response>> {
    match parse_filter(query, "cursor") {
        None => Ok(None),
        Some(raw) => decode_cursor(&raw)
            .map(Some)
            .ok_or_else(|| Box::new(StatusError::bad_request("Invalid cursor").into_response())),
    }
}

/// Builds the standard `(200, Json(items))` response for a cursor-paginated
/// list endpoint, adding `X-Next-Cursor` only when `next_cursor` is `Some`
/// (#1142). The response body shape (a bare JSON array) is unchanged from
/// before cursor pagination existed — deliberately, since the Python/Go/TS
/// SDKs already parse these endpoints as bare arrays; the cursor token
/// rides on a header instead of a body envelope so existing clients are
/// unaffected.
pub(crate) fn paginated_response<T: serde::Serialize>(
    items: &[T],
    next_cursor: Option<i64>,
) -> axum::response::Response {
    let mut response = (StatusCode::OK, Json(items)).into_response();
    if let Some(rowid) = next_cursor {
        if let Ok(val) = axum::http::HeaderValue::from_str(&encode_cursor(rowid)) {
            response.headers_mut().insert("x-next-cursor", val);
        }
    }
    response
}

pub async fn get_openapi_spec() -> impl IntoResponse {
    let spec = openapi::ApiDoc::openapi();
    (StatusCode::OK, Json(spec))
}

/// Test/benchmark-only helpers for constructing a real [`AppState`] backed by
/// a real SQLite pool with migrations applied (TASK-1313).
///
/// This mirrors the `setup_state_with_events_capacity` helper in
/// `mod tests` below, but is `pub` so the criterion benchmark in
/// `benches/authorize_benchmark.rs` can build an end-to-end harness for
/// `authorize_action` without duplicating the seeding logic. Kept out of
/// `#[cfg(test)]` so it is compiled for `cargo bench` (which builds with
/// `--release` and without `cfg(test)`), but it is not part of the gateway's
/// public HTTP API or invariants — it exists purely to exercise the real
/// handler in benchmarks.
pub mod benchutil {
    use super::*;
    use crate::events::EventSink;
    use crate::policy::PolicyEngine;

    /// Build a fresh [`AppState`] against a tempfile SQLite DB with
    /// migrations applied, a registered tenant, and a registered agent whose
    /// plaintext token is returned alongside the tenant id.
    ///
    /// `db_path` should be a unique filesystem path (e.g. under a tempdir)
    /// so repeated benchmark setups don't collide.
    pub async fn setup_bench_state(
        db_path: &str,
    ) -> Result<(Arc<AppState>, String, String), sqlx::Error> {
        let db_url = format!("sqlite://{}", db_path);
        let pool = db::init_db(&db_url).await?;

        let tenant_id = "tenant_bench".to_string();
        db::register_tenant(&pool, &tenant_id, "Bench Tenant", "developer").await?;

        let agent_id = Uuid::new_v4().to_string();
        let agent_token = format!("agent_tok_{}", Uuid::new_v4().simple());
        let agent = AgentRecord {
            id: agent_id,
            tenant_id: tenant_id.clone(),
            agent_key: "bench-agent".to_string(),
            agent_token: db::hash_token(&agent_token),
            name: "Bench Agent".to_string(),
            owner_team: Some("platform".to_string()),
            owner_email: None,
            environment: "production".to_string(),
            framework: None,
            model_provider: None,
            model_name: None,
            purpose: None,
            risk_tier: "high".to_string(),
            status: "active".to_string(),
            last_seen_at: None,
            frozen_reason: None,
            force_approval: false,
            quarantined_at: None,
            signing_key: None,
            allowed_environments: None,
            mtls_cn: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db::insert_agent(&pool, &agent).await?;

        let policy_engine = PolicyEngine::init("policies.cedar")
            .await
            .map_err(|e| sqlx::Error::Configuration(format!("{:?}", e).into()))?;
        // Use a generously-sized channel and never drain it in the benchmark —
        // SOC event emission is fire-and-forget (`try_send`, non-blocking) per
        // the gateway's design, so an undrained channel does not slow down
        // `authorize_action` until it fills. 100k is far larger than any
        // single benchmark run's iteration count needs to be accurate.
        let metrics = Arc::new(crate::metrics::SecurityMetrics::new());
        let (events, _events_rx) = EventSink::channel(100_000, metrics.clone());

        let state = Arc::new(AppState {
            pool: pool.clone(),
            storage: Arc::new(aegis_storage::sqlite::SqliteStorage::new(pool)),
            policy_engine,
            events,
            metrics,
            approval_ttl_secs: 1800,
            rate_limiter: RateLimiter::new(1_000_000.0, 1_000_000.0),
            quota_manager: QuotaManager::new(0, 86400), // 0 == quota disabled
            approval_callback_ip_limiter: RateLimiter::new(10.0, 10.0 / 60.0),
            approval_attempt_tracker: ApprovalAttemptTracker::new(5, 3600),
            skill_cache: SkillActionCache::new(1024),
            risk_weight_cache: RiskWeightsCache::new(std::time::Duration::from_secs(60)),
            heartbeat_debouncer: Arc::new(HeartbeatDebouncer::new()),
            deferred_write_tracker: Arc::new(DeferredWriteTracker::new()),
            replay_nonce_cache: ReplayNonceCache::new(10_000),
            startup_complete: std::sync::atomic::AtomicBool::new(true),
            audit_writer_unhealthy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            audit_batch: crate::audit_batch::AuditBatchSink::channel(1024).0,
            github_webhook_secret: None,
            slack_signing_secret: None,
            github_pr_commenter: None,
            github_checks_client: None,
            qdrant_exporter: None,
            admission_webhook: None,
            background_task_handles: std::sync::Mutex::new(Vec::new()),
        });

        Ok((state, tenant_id, agent_token))
    }

    /// Register `n` additional agents in `tenant_id` (TASK-1313 seed data:
    /// 100 agents). These agents are not used directly by the hot-path
    /// benchmark request (which always authenticates as the primary bench
    /// agent from [`setup_bench_state`]), but their presence in the `agents`
    /// table makes the agent lookup query representative of a populated
    /// tenant rather than a near-empty table.
    pub async fn seed_extra_agents(
        pool: &sqlx::SqlitePool,
        tenant_id: &str,
        n: usize,
    ) -> Result<(), sqlx::Error> {
        for i in 0..n {
            let agent = AgentRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.to_string(),
                agent_key: format!("bench-seed-agent-{}", i),
                agent_token: db::hash_token(&format!("seed_tok_{}", Uuid::new_v4().simple())),
                name: format!("Bench Seed Agent {}", i),
                owner_team: Some("platform".to_string()),
                owner_email: None,
                environment: "production".to_string(),
                framework: None,
                model_provider: None,
                model_name: None,
                purpose: None,
                risk_tier: "low".to_string(),
                status: "active".to_string(),
                last_seen_at: None,
                frozen_reason: None,
                force_approval: false,
                quarantined_at: None,
                signing_key: None,
                allowed_environments: None,
                mtls_cn: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            db::insert_agent(pool, &agent).await?;
        }
        Ok(())
    }

    /// Insert `n` historical decision rows for `agent_id` in `tenant_id`
    /// (TASK-1313 seed data: 1000 prior decisions), so the `decisions` table
    /// is representative of a tenant with real history. The hot-path
    /// `/v1/authorize` query doesn't read this table directly, but a
    /// populated table is more representative for any future benchmarks that
    /// touch `GET /v1/decisions` or audit endpoints, and exercises realistic
    /// SQLite file sizes/indexes.
    pub async fn seed_decisions(
        pool: &sqlx::SqlitePool,
        tenant_id: &str,
        agent_id: &str,
        n: usize,
    ) -> Result<(), sqlx::Error> {
        for i in 0..n {
            let record = DecisionRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.to_string(),
                agent_id: agent_id.to_string(),
                user_id: None,
                run_id: Some(format!("run_seed_{}", i)),
                trace_id: Some(format!("trace_seed_{}", i)),
                skill: "filesystem".to_string(),
                action: "read_file".to_string(),
                resource: Some(format!("file_{}.txt", i)),
                input_json: "{}".to_string(),
                decision: "allow".to_string(),
                risk_score: Some(1),
                reason: Some("seed".to_string()),
                matched_policy_ids: None,
                request_id: None,
                latency_ms: Some(1),
                composite_risk_score: Some(1),
                root_trust_level: None,
                parent_run_id: None,
                created_at: Utc::now(),
            };
            db::insert_decision(pool, &record).await?;
        }
        Ok(())
    }

    /// Build headers for an authenticated `/v1/authorize` call.
    pub fn agent_headers(agent_token: &str, tenant_id: &str) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", agent_token)
                .parse()
                .expect("valid header value"),
        );
        headers.insert(
            "X-Aegis-Tenant-ID",
            tenant_id.parse().expect("valid header value"),
        );
        headers
    }

    /// Build a steady-state `AuthorizeRequest` for the read-only
    /// `filesystem.read_file` action — `mutates_state: false` with
    /// `trust_level: trusted_internal_signed`, which the default policy pack
    /// permits instantly (`allow`, no approval). This is the common-case hot
    /// path TASK-1313 targets.
    pub fn allow_authorize_request() -> AuthorizeRequest {
        AuthorizeRequest {
            request_id: None,
            callback: None,
            dry_run: None,
            agent: AuthorizeAgentContext {
                id: "bench-agent".to_string(),
                environment: "production".to_string(),
            },
            user: None,
            tool_call: AuthorizeToolCall {
                tool: "filesystem".to_string(),
                action: "read_file".to_string(),
                resource: Some("bench.txt".to_string()),
                mutates_state: false,
                parameters: serde_json::json!({}),
            },
            context: AuthorizeDynamicContext {
                source_trust: "trusted_internal_signed".to_string(),
                contains_sensitive_data: false,
            },
            trace: Some(AuthorizeTraceContext {
                run_id: "run_bench".to_string(),
                trace_id: "trace_bench".to_string(),
                parent_run_id: None,
                root_trust_level: None,
            }),
            nonce: None,
            timestamp: None,
        }
    }
}

/// Middleware to append standard Deprecation and Sunset headers to all v1 API responses.
pub async fn deprecation_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> impl axum::response::IntoResponse {
    let mut response = next.run(request).await;
    if let Ok(deprecation_val) = axum::http::HeaderValue::from_str("true") {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("deprecation"),
            deprecation_val,
        );
    }
    if let Ok(sunset_val) = axum::http::HeaderValue::from_str("Wed, 31 Dec 2026 23:59:59 GMT") {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("sunset"),
            sunset_val,
        );
    }
    response
}

#[cfg(test)]
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) mod test_helpers {
    use super::*;
    use crate::events;
    use crate::models::*;
    use crate::policy::PolicyEngine;
    use axum::body::{to_bytes, Bytes};
    use axum::http::HeaderMap;
    use chrono::{DateTime, Utc};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use uuid::Uuid;
    pub(crate) static ENV_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
        std::sync::OnceLock::new();

    pub(crate) fn get_env_lock() -> &'static tokio::sync::Mutex<()> {
        ENV_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    /// Default `ConnectInfo` for tests that don't exercise the per-IP
    /// approval-callback rate limiter (#1307) and just need a placeholder
    /// source address.
    pub(crate) fn test_conn_info() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 0))
    }

    /// Build a `ConnectInfo` for a distinct synthetic client IP, for tests
    /// that need to isolate per-IP rate limiting (#1307, AC#1) from one
    /// another.
    pub(crate) fn conn_info_for_ip(octet: u8) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, octet], 0))
    }

    /// Like [`setup_state`], but returns an [`AppState`] with
    /// `github_webhook_secret` set to `Some(secret)`, for testing the
    /// `X-Hub-Signature-256` verification on `POST /v1/ingest` (#1339).
    pub(crate) async fn setup_state_with_github_secret(
        test_name: &str,
        secret: &str,
    ) -> (Arc<AppState>, String, String) {
        let (state_raw, tenant_id, agent_token, events_rx) =
            setup_state_with_events(test_name).await;
        tokio::spawn(events::drain(
            events_rx,
            state_raw.pool.clone(),
            state_raw.metrics.clone(),
            None,
        ));

        let policy_engine = PolicyEngine::init("policies.cedar").await.unwrap();
        let state = Arc::new(AppState {
            pool: state_raw.pool.clone(),
            storage: state_raw.storage.clone(),
            policy_engine,
            events: state_raw.events.clone(),
            metrics: state_raw.metrics.clone(),
            approval_ttl_secs: 1800,
            rate_limiter: RateLimiter::new(1000.0, 1000.0),
            quota_manager: QuotaManager::new(0, 86400),
            approval_callback_ip_limiter: RateLimiter::new(10.0, 10.0 / 60.0),
            approval_attempt_tracker: ApprovalAttemptTracker::new(5, 3600),
            skill_cache: SkillActionCache::new(1024),
            risk_weight_cache: RiskWeightsCache::new(std::time::Duration::from_secs(60)),
            heartbeat_debouncer: Arc::new(HeartbeatDebouncer::new()),
            deferred_write_tracker: Arc::new(DeferredWriteTracker::new()),
            replay_nonce_cache: ReplayNonceCache::new(10_000),
            startup_complete: std::sync::atomic::AtomicBool::new(true),
            audit_writer_unhealthy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            audit_batch: crate::audit_batch::AuditBatchSink::channel(1024).0,
            github_webhook_secret: Some(secret.to_string()),
            slack_signing_secret: None,
            github_pr_commenter: None,
            github_checks_client: None,
            qdrant_exporter: None,
            admission_webhook: None,
            background_task_handles: std::sync::Mutex::new(Vec::new()),
        });

        (state, tenant_id, agent_token)
    }

    /// Like [`setup_state`], but returns an [`AppState`] with
    /// `admission_webhook` set to a real [`crate::admission::AdmissionWebhookClient`]
    /// pointed at `url`, for testing the #1143 pre-authorize hook end-to-end
    /// through `authorize_action`.
    pub(crate) async fn setup_state_with_admission_webhook(
        test_name: &str,
        url: &str,
        fail_open: bool,
    ) -> (Arc<AppState>, String, String) {
        let (state_raw, tenant_id, agent_token, events_rx) =
            setup_state_with_events(test_name).await;
        tokio::spawn(events::drain(
            events_rx,
            state_raw.pool.clone(),
            state_raw.metrics.clone(),
            None,
        ));

        let policy_engine = PolicyEngine::init("policies.cedar").await.unwrap();
        let state = Arc::new(AppState {
            pool: state_raw.pool.clone(),
            storage: state_raw.storage.clone(),
            policy_engine,
            events: state_raw.events.clone(),
            metrics: state_raw.metrics.clone(),
            approval_ttl_secs: 1800,
            rate_limiter: RateLimiter::new(1000.0, 1000.0),
            quota_manager: QuotaManager::new(0, 86400),
            approval_callback_ip_limiter: RateLimiter::new(10.0, 10.0 / 60.0),
            approval_attempt_tracker: ApprovalAttemptTracker::new(5, 3600),
            skill_cache: SkillActionCache::new(1024),
            risk_weight_cache: RiskWeightsCache::new(std::time::Duration::from_secs(60)),
            heartbeat_debouncer: Arc::new(HeartbeatDebouncer::new()),
            deferred_write_tracker: Arc::new(DeferredWriteTracker::new()),
            replay_nonce_cache: ReplayNonceCache::new(10_000),
            startup_complete: std::sync::atomic::AtomicBool::new(true),
            audit_writer_unhealthy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            audit_batch: crate::audit_batch::AuditBatchSink::channel(1024).0,
            github_webhook_secret: None,
            slack_signing_secret: None,
            github_pr_commenter: None,
            github_checks_client: None,
            qdrant_exporter: None,
            admission_webhook: Some(Arc::new(crate::admission::AdmissionWebhookClient::new(
                url.to_string(),
                5,
                fail_open,
            ))),
            background_task_handles: std::sync::Mutex::new(Vec::new()),
        });

        (state, tenant_id, agent_token)
    }

    /// Like [`setup_state`], but returns an [`AppState`] with
    /// `slack_signing_secret` set to `Some(secret)`, for testing the
    /// `X-Slack-Signature` verification on `POST /v1/callbacks/slack` (#1276).
    pub(crate) async fn setup_state_with_slack_secret(
        test_name: &str,
        secret: &str,
    ) -> (Arc<AppState>, String, String) {
        let (state_raw, tenant_id, agent_token, events_rx) =
            setup_state_with_events(test_name).await;
        tokio::spawn(events::drain(
            events_rx,
            state_raw.pool.clone(),
            state_raw.metrics.clone(),
            None,
        ));

        let policy_engine = PolicyEngine::init("policies.cedar").await.unwrap();
        let state = Arc::new(AppState {
            pool: state_raw.pool.clone(),
            storage: state_raw.storage.clone(),
            policy_engine,
            events: state_raw.events.clone(),
            metrics: state_raw.metrics.clone(),
            approval_ttl_secs: 1800,
            rate_limiter: RateLimiter::new(1000.0, 1000.0),
            quota_manager: QuotaManager::new(0, 86400),
            approval_callback_ip_limiter: RateLimiter::new(10.0, 10.0 / 60.0),
            approval_attempt_tracker: ApprovalAttemptTracker::new(5, 3600),
            skill_cache: SkillActionCache::new(1024),
            risk_weight_cache: RiskWeightsCache::new(std::time::Duration::from_secs(60)),
            heartbeat_debouncer: Arc::new(HeartbeatDebouncer::new()),
            deferred_write_tracker: Arc::new(DeferredWriteTracker::new()),
            replay_nonce_cache: ReplayNonceCache::new(10_000),
            startup_complete: std::sync::atomic::AtomicBool::new(true),
            audit_writer_unhealthy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            audit_batch: crate::audit_batch::AuditBatchSink::channel(1024).0,
            github_webhook_secret: None,
            slack_signing_secret: Some(secret.to_string()),
            github_pr_commenter: None,
            github_checks_client: None,
            qdrant_exporter: None,
            admission_webhook: None,
            background_task_handles: std::sync::Mutex::new(Vec::new()),
        });

        (state, tenant_id, agent_token)
    }

    pub(crate) async fn setup_state(test_name: &str) -> (Arc<AppState>, String, String) {
        let (state, tenant_id, agent_token, events_rx) = setup_state_with_events(test_name).await;
        // Drain in the background so existing tests are unaffected by the stream.
        // Phase 5: pass pool.clone() so the drain can persist alerts + incidents.
        tokio::spawn(events::drain(
            events_rx,
            state.pool.clone(),
            state.metrics.clone(),
            None,
        ));
        (state, tenant_id, agent_token)
    }

    pub(crate) async fn setup_state_with_events(
        test_name: &str,
    ) -> (Arc<AppState>, String, String, mpsc::Receiver<AseEvent>) {
        setup_state_with_events_capacity(test_name, events::DEFAULT_CAPACITY).await
    }

    /// Like [`setup_state_with_events`] but allows overriding the SOC event
    /// channel capacity. Used by #1305 to construct a small-capacity
    /// broadcast channel so a slow WebSocket consumer can be made to lag
    /// deterministically without emitting thousands of events.
    pub(crate) async fn setup_state_with_events_capacity(
        test_name: &str,
        capacity: usize,
    ) -> (Arc<AppState>, String, String, mpsc::Receiver<AseEvent>) {
        std::fs::create_dir_all("target").unwrap();
        let db_url = format!(
            "sqlite://target/routes_{}_{}.db",
            test_name,
            Uuid::new_v4().simple()
        );
        let pool = db::init_db(&db_url).await.unwrap();
        let tenant_id = "tenant_routes".to_string();
        db::register_tenant(&pool, &tenant_id, "Routes Tenant", "developer")
            .await
            .unwrap();

        let agent_id = Uuid::new_v4().to_string();
        let agent_token = format!("agent_tok_{}", Uuid::new_v4().simple());
        let agent = AgentRecord {
            id: agent_id,
            tenant_id: tenant_id.clone(),
            agent_key: "routes-agent".to_string(),
            agent_token: db::hash_token(&agent_token),
            name: "Routes Agent".to_string(),
            owner_team: Some("platform".to_string()),
            owner_email: None,
            environment: "production".to_string(),
            framework: None,
            model_provider: None,
            model_name: None,
            purpose: None,
            risk_tier: "high".to_string(),
            status: "active".to_string(),
            last_seen_at: None,
            frozen_reason: None,
            force_approval: false,
            quarantined_at: None,
            signing_key: None,
            allowed_environments: None,
            mtls_cn: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db::insert_agent(&pool, &agent).await.unwrap();

        let policy_engine = PolicyEngine::init("policies.cedar").await.unwrap();
        let metrics = Arc::new(crate::metrics::SecurityMetrics::new());
        let (events, events_rx) = EventSink::channel(capacity, metrics.clone());
        let state = Arc::new(AppState {
            pool: pool.clone(),
            storage: Arc::new(aegis_storage::sqlite::SqliteStorage::new(pool)),
            policy_engine,
            events,
            metrics,
            approval_ttl_secs: 1800,
            rate_limiter: RateLimiter::new(1000.0, 1000.0),
            quota_manager: QuotaManager::new(0, 86400),
            approval_callback_ip_limiter: RateLimiter::new(10.0, 10.0 / 60.0),
            approval_attempt_tracker: ApprovalAttemptTracker::new(5, 3600),
            skill_cache: SkillActionCache::new(1024),
            risk_weight_cache: RiskWeightsCache::new(std::time::Duration::from_secs(60)),
            heartbeat_debouncer: Arc::new(HeartbeatDebouncer::new()),
            deferred_write_tracker: Arc::new(DeferredWriteTracker::new()),
            replay_nonce_cache: ReplayNonceCache::new(10_000),
            startup_complete: std::sync::atomic::AtomicBool::new(true),
            audit_writer_unhealthy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            audit_batch: crate::audit_batch::AuditBatchSink::channel(1024).0,

            github_webhook_secret: None,
            slack_signing_secret: None,
            github_pr_commenter: None,
            github_checks_client: None,
            qdrant_exporter: None,
            admission_webhook: None,
            background_task_handles: std::sync::Mutex::new(Vec::new()),
        });

        (state, tenant_id, agent_token, events_rx)
    }

    /// Like [`setup_state`], but `audit_batch` is backed by a real channel
    /// drained by a spawned [`crate::audit_batch::run_audit_batch_writer`]
    /// (#1315), so batching behavior can be observed end-to-end.
    pub(crate) async fn setup_state_with_audit_batch_writer(
        test_name: &str,
        batch_size: usize,
        flush_interval: std::time::Duration,
    ) -> (Arc<AppState>, String, String) {
        let (state_raw, tenant_id, agent_token, events_rx) =
            setup_state_with_events(test_name).await;
        tokio::spawn(events::drain(
            events_rx,
            state_raw.pool.clone(),
            state_raw.metrics.clone(),
            None,
        ));

        let (audit_batch, audit_batch_rx) =
            crate::audit_batch::AuditBatchSink::channel(crate::audit_batch::DEFAULT_CAPACITY);
        tokio::spawn(crate::audit_batch::run_audit_batch_writer(
            state_raw.pool.clone(),
            audit_batch_rx,
            batch_size,
            flush_interval,
            state_raw.audit_writer_unhealthy.clone(),
        ));

        let policy_engine = PolicyEngine::init("policies.cedar").await.unwrap();
        let state = Arc::new(AppState {
            pool: state_raw.pool.clone(),
            storage: state_raw.storage.clone(),
            policy_engine,
            events: state_raw.events.clone(),
            metrics: state_raw.metrics.clone(),
            approval_ttl_secs: 1800,
            rate_limiter: RateLimiter::new(1000.0, 1000.0),
            quota_manager: QuotaManager::new(0, 86400),
            approval_callback_ip_limiter: RateLimiter::new(10.0, 10.0 / 60.0),
            approval_attempt_tracker: ApprovalAttemptTracker::new(5, 3600),
            skill_cache: SkillActionCache::new(1024),
            risk_weight_cache: RiskWeightsCache::new(std::time::Duration::from_secs(60)),
            heartbeat_debouncer: Arc::new(HeartbeatDebouncer::new()),
            deferred_write_tracker: Arc::new(DeferredWriteTracker::new()),
            replay_nonce_cache: ReplayNonceCache::new(10_000),
            startup_complete: std::sync::atomic::AtomicBool::new(true),
            audit_writer_unhealthy: state_raw.audit_writer_unhealthy.clone(),
            audit_batch,
            github_webhook_secret: None,
            slack_signing_secret: None,
            github_pr_commenter: None,
            github_checks_client: None,
            qdrant_exporter: None,
            admission_webhook: None,
            background_task_handles: std::sync::Mutex::new(Vec::new()),
        });

        (state, tenant_id, agent_token)
    }

    pub(crate) fn agent_headers(agent_token: &str, tenant_id: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", agent_token).parse().unwrap(),
        );
        headers.insert("X-Aegis-Tenant-ID", tenant_id.parse().unwrap());
        headers
    }

    /// Like [`agent_headers`], but authenticates via the mTLS Subject-CN
    /// header instead of a bearer token (#1310). Mirrors exactly what the
    /// TLS accept loop in `main.rs` sets on a request after a verified
    /// client-cert handshake, so `authorize_action`'s mTLS branch can be
    /// exercised without standing up a real TCP/TLS listener in tests.
    pub(crate) fn mtls_headers(cn: &str, tenant_id: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(crate::mtls::MTLS_CN_HEADER, cn.parse().unwrap());
        headers.insert("X-Aegis-Tenant-ID", tenant_id.parse().unwrap());
        headers
    }

    pub(crate) fn mcp_authorize_request(tool: &str, action: &str) -> AuthorizeRequest {
        AuthorizeRequest {
            request_id: None,
            callback: None,
            dry_run: None,
            nonce: None,
            timestamp: None,
            agent: AuthorizeAgentContext {
                id: "routes-agent".to_string(),
                environment: "production".to_string(),
            },
            user: None,
            tool_call: AuthorizeToolCall {
                tool: tool.to_string(),
                action: action.to_string(),
                resource: None,
                mutates_state: false,
                parameters: serde_json::json!({}),
            },
            context: AuthorizeDynamicContext {
                source_trust: "trusted_internal_signed".to_string(),
                contains_sensitive_data: false,
            },
            trace: Some(AuthorizeTraceContext {
                run_id: "run_routes".to_string(),
                trace_id: "trace_routes".to_string(),
                parent_run_id: None,
                root_trust_level: None,
            }),
        }
    }

    pub(crate) async fn call_authorize(
        state: Arc<AppState>,
        tenant_id: &str,
        agent_token: &str,
        request: AuthorizeRequest,
    ) -> AuthorizeResponse {
        let response = authorize_action(
            State(state),
            agent_headers(agent_token, tenant_id),
            Bytes::from(serde_json::to_vec(&request).unwrap()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    pub(crate) fn make_test_approval(
        expires_at: Option<chrono::DateTime<Utc>>,
        status: &str,
    ) -> ApprovalRecord {
        ApprovalRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: "t".to_string(),
            decision_id: Uuid::new_v4().to_string(),
            status: status.to_string(),
            approver_group: None,
            approver_user_id: None,
            reason: None,
            original_skill_call: "{}".to_string(),
            original_call_hash: "x".to_string(),
            edited_skill_call: None,
            expires_at,
            decided_at: None,
            callback_url: None,
            callback_secret_hash: None,
            created_at: Utc::now(),
        }
    }

    /// Shared helper for the approval-lifecycle tests below: triggers a
    /// require_approval decision (a production GitHub merge) and returns its
    /// approval id plus the bound `action_hash`.
    pub(crate) async fn create_pending_approval(
        state: &Arc<AppState>,
        tenant_id: &str,
        agent_token: &str,
        pr_number: &str,
    ) -> (Uuid, String) {
        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some(format!("repo/example/pull/{pr_number}"));
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), tenant_id, agent_token, request).await;
        let approval = response.approval.expect("approval created");
        (approval.approval_id, approval.action_hash)
    }

    pub(crate) fn unsigned_receipt_template(tenant_id: &str) -> ActionReceiptRecord {
        ActionReceiptRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            decision_id: Some(Uuid::new_v4().to_string()),
            ts: Utc::now().to_rfc3339(),
            agent_id: Some("signing-agent".to_string()),
            user_id: None,
            run_id: None,
            trace_id: None,
            tool: Some("github".to_string()),
            action: Some("merge_pull_request".to_string()),
            resource: Some("payments#1".to_string()),
            source_trust: "trusted_internal_signed".to_string(),
            decision: "allow".to_string(),
            approver: None,
            action_hash: Some("aaaa".to_string()),
            prev_receipt_hash: String::new(),
            receipt_hash: String::new(),
            canon_version: CANON_VERSION.to_string(),
            signature: None,
            signer_public_key: None,
            signer_key_id: None,
            created_at: Utc::now(),
        }
    }

    /// Helper: close an incident via the route handler and parse the JSON body.
    pub(crate) async fn do_close(
        state: Arc<AppState>,
        tenant_id: &str,
        incident_id: &str,
    ) -> (StatusCode, serde_json::Value) {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", tenant_id).parse().unwrap(),
        );
        let response = close_incident(
            State(state),
            TenantId(tenant_id.to_string()),
            Path(incident_id.to_string()),
        )
        .await
        .into_response();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        (status, json)
    }

    /// Helper: call GET /v1/incidents/:id and return (status, json body).
    pub(crate) async fn do_get_incident(
        state: Arc<AppState>,
        tenant_id: &str,
        incident_id: &str,
    ) -> (StatusCode, serde_json::Value) {
        let response = get_incident(
            State(state),
            TenantId(tenant_id.to_string()),
            Path(incident_id.to_string()),
        )
        .await
        .into_response();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        (status, json)
    }

    pub(crate) fn register_agent_router(state: Arc<AppState>) -> axum::Router {
        use axum::routing::post;
        axum::Router::new()
            .route("/v1/agents/register", post(register_agent))
            .with_state(state)
    }

    pub(crate) fn register_agent_payload(agent_key: &str) -> serde_json::Value {
        json!({
            "agent_key": agent_key,
            "name": "Test Agent",
            "owner_team": "platform",
            "environment": "staging",
            "framework": "langchain",
            "model_provider": "anthropic",
            "model_name": "claude",
            "risk_tier": "medium",
            "purpose": "testing"
        })
    }

    pub(crate) fn register_tool_router(state: Arc<AppState>) -> axum::Router {
        use axum::routing::post;
        axum::Router::new()
            .route("/v1/tools", post(register_tool))
            .with_state(state)
    }

    pub(crate) fn register_tool_payload(skill_key: &str, risk: &str) -> serde_json::Value {
        json!({
            "skill_key": skill_key,
            "name": "Deployer",
            "type": "static",
            "auth_type": null,
            "owner_team": "platform",
            "default_risk": "medium",
            "actions": [
                {
                    "action_key": "ship",
                    "description": "Ship a release",
                    "risk": risk,
                    "mutates_state": true,
                    "data_access": "write",
                    "approval_required": false,
                    "default_decision": "policy"
                }
            ]
        })
    }
}
