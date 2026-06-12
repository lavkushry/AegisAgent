use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::sync::Arc;
use tracing::{error, info};
use uuid::Uuid;

use crate::db;
use crate::events::{AseEvent, EventSink};
use crate::metrics::{is_untrusted_provenance, SecurityMetrics};
use crate::models::*;
use crate::policy::PolicyEngine;
use crate::sign;

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Instant;

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

// Shared app state containing DB pool, Cedar policy engine, and the async SOC
// event sink (Phase 0): the authorize hot path emits decisions onto it.
pub struct AppState {
    pub pool: sqlx::SqlitePool,
    pub policy_engine: PolicyEngine,
    pub events: EventSink,
    /// Process-wide security counters exposed on GET /metrics.
    pub metrics: SecurityMetrics,
    /// Approval time-to-live in seconds. Configurable via AEGIS_APPROVAL_TTL_SECS
    /// environment variable (default: 1800 = 30 minutes).
    pub approval_ttl_secs: i64,
    pub rate_limiter: RateLimiter,
    pub quota_manager: QuotaManager,
    /// Read-through cache for registered-action metadata (#899).
    pub skill_cache: SkillActionCache,
    /// Set to `true` once startup initialization (DB pool, migrations, policy
    /// engine, background jobs) has completed. Backs `GET /startupz` (#1208)
    /// so orchestrators can distinguish "still starting" from "ready".
    pub startup_complete: std::sync::atomic::AtomicBool,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Claims {
    sub: String,
    tenant_id: Option<String>,
    exp: usize,
}

fn validate_jwt(token: &str) -> Option<String> {
    let secret = std::env::var("AEGIS_JWT_SECRET").ok()?;
    if secret.trim().is_empty() || secret == "default_secret" {
        return None;
    }
    let key = jsonwebtoken::DecodingKey::from_secret(secret.as_bytes());
    let validation = jsonwebtoken::Validation::default();
    jsonwebtoken::decode::<Claims>(token, &key, &validation)
        .map(|data| data.claims.tenant_id.unwrap_or(data.claims.sub))
        .ok()
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
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .ok_or((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing Authorization header"})),
            ))?;

        if !auth_header.starts_with("Bearer ") {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid Authorization format"})),
            ));
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
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "Invalid or expired JWT token"})),
                ));
            }

            // Fallback to old heuristic
            if token.starts_with("tenant_") {
                token.to_string()
            } else {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(
                        json!({"error": "Invalid token. Bearer token must start with 'tenant_' when JWT is not required"}),
                    ),
                ));
            }
        };

        // Extract AppState to verify tenant existence in DB
        let app_state = <Arc<AppState> as axum::extract::FromRef<S>>::from_ref(state);

        match db::get_tenant_by_id(&app_state.pool, &tenant_id).await {
            Ok(Some(_)) => Ok(TenantId(tenant_id)),
            Ok(None) => Err((
                StatusCode::NOT_FOUND,
                Json(json!({"error": format!("Tenant '{}' not found", tenant_id)})),
            )),
            Err(e) => {
                error!("Database error checking tenant: {:?}", e);
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Database error checking tenant"})),
                ))
            }
        }
    }
}

fn get_runtime_tenant_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("X-Aegis-Tenant-ID")
        .or_else(|| headers.get("X-Tenant-ID"))
        .and_then(|h| h.to_str().ok())
        .filter(|tenant_id| !tenant_id.trim().is_empty())
        .map(str::to_string)
}

fn risk_score_for_level(risk_level: &str) -> i32 {
    match risk_level {
        "low" => 10,
        "medium" => 40,
        "high" => 75,
        "critical" => 95,
        _ => 10,
    }
}

/// Inverse of [`risk_score_for_level`] — used to reconstruct `risk_level` for an
/// idempotent replay (#0072), where only `risk_score` was persisted on the
/// original [`DecisionRecord`]. Bucketed by threshold so it tolerates any score
/// `risk_score_for_level` could have produced.
fn risk_level_for_score(risk_score: i32) -> String {
    match risk_score {
        s if s >= 95 => "critical",
        s if s >= 75 => "high",
        s if s >= 40 => "medium",
        _ => "low",
    }
    .to_string()
}

/// Idempotent replay (#0072): rebuild the `AuthorizeResponse` for a previously
/// recorded decision instead of re-evaluating Cedar / writing duplicate audit
/// events, approvals, or receipts. For `require_approval` decisions, the
/// associated approval (if any) is looked up so the caller still sees its
/// current `status` (e.g. an approval created by the first call may since have
/// been approved/rejected).
async fn idempotent_replay_response(
    state: &Arc<AppState>,
    tenant_id: &str,
    record: DecisionRecord,
) -> axum::response::Response {
    let decision_id = match Uuid::parse_str(&record.id) {
        Ok(id) => id,
        Err(_) => Uuid::nil(),
    };
    let risk_score = record.risk_score.unwrap_or(0);
    let matched_policies: Vec<String> = record
        .matched_policy_ids
        .as_deref()
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    let mut approval = None;
    if record.decision == "require_approval" {
        if let Ok(Some(app)) =
            db::get_approval_by_decision_id(&state.pool, tenant_id, &record.id).await
        {
            approval = Some(ApprovalResponseInfo {
                approval_id: Uuid::parse_str(&app.id).unwrap_or(Uuid::nil()),
                status: app.status,
                approver_group: app.approver_group,
                expires_at: app.expires_at.unwrap_or(record.created_at),
                action_hash: app.original_call_hash,
            });
        }
    }

    (
        StatusCode::OK,
        Json(AuthorizeResponse {
            decision_id,
            decision: record.decision,
            risk_score,
            risk_level: risk_level_for_score(risk_score),
            reason: record.reason.unwrap_or_default(),
            matched_policies,
            approval,
        }),
    )
        .into_response()
}

fn mcp_server_key_from_tool(tool: &str) -> Option<&str> {
    tool.strip_prefix("mcp:")
        .filter(|server_key| !server_key.is_empty())
}

/// Recursively sort JSON object keys by Unicode code point (`aegis-jcs-1`).
/// Delegates to `aegis_canon` (TEST-002, #1162) so the fuzz targets in
/// `fuzz/` exercise the exact same implementation as the gateway.
fn canonicalize_json(value: Value) -> Value {
    aegis_canon::canonicalize_json(value)
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{:02x}", byte)).collect()
}

/// Canonicalization scheme version. MUST stay byte-identical with the SDKs
/// (see `tests/canonical_action_vectors.json` and `aegisagent.decorator.CANON_VERSION`).
/// Scheme "aegis-jcs-1": keys sorted by Unicode code point, compact separators,
/// raw UTF-8 (serde_json does not escape non-ASCII), null for absent resource.
// Referenced by the cross-language corpus tests; unused in the non-test binary build.
#[allow(dead_code)]
pub const CANON_VERSION: &str = "aegis-jcs-1";

/// Deterministic canonical string for a tool call. The SDK hashes the exact same
/// string; byte-equality here is the foundation of the fail-closed approval guarantee.
fn canonical_action_string(tool_call: &AuthorizeToolCall) -> String {
    aegis_canon::canonical_value_string(tool_call)
}

fn hash_tool_call(tool_call: &AuthorizeToolCall) -> String {
    sha256_hex(canonical_action_string(tool_call).as_bytes())
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
fn compute_mcp_manifest_hash(tools: &[McpToolManifestItem]) -> String {
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

pub(crate) fn compute_receipt_hash(rec: &ActionReceiptRecord) -> String {
    sha256_hex(canonical_value_string(&receipt_body_value(rec)).as_bytes())
}

/// Optionally attach an Ed25519 signature OVER the already-computed `receipt_hash`.
///
/// This runs AFTER `compute_receipt_hash` and never feeds back into the hash: the
/// signature and signer public key are additive metadata stored alongside the
/// receipt, so the byte-parity-locked `aegis-jcs-1` chain is untouched. When no
/// signer is configured (`global_signer() == None`), both fields stay NULL and
/// the receipt is emitted unsigned (hermetic default). We sign the hash, never a
/// payload (redaction preserved).
fn apply_receipt_signature(receipt: &mut ActionReceiptRecord) {
    if let Some(signer) = sign::global_signer() {
        receipt.signature = Some(signer.sign_hash(&receipt.receipt_hash));
        receipt.signer_public_key = Some(signer.public_key_hex());
    }
}

/// Emit a hash-chained, verifiable receipt for a finalized decision. Non-fatal:
/// a receipt write failure is logged but does not change the authorization result.
async fn emit_action_receipt(
    pool: &sqlx::SqlitePool,
    tenant_id: &str,
    agent_id: &str,
    payload: &AuthorizeRequest,
    decision_id: Uuid,
    decision: &str,
) {
    // Build the head-referencing receipt inside one atomic transaction (T-D
    // hardening): the chain head is read and the new link inserted under a single
    // write lock, so concurrent authorizes for this tenant cannot fork the chain.
    let result = db::append_action_receipt_atomic(pool, tenant_id, |prev_receipt_hash| {
        let mut receipt = ActionReceiptRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            decision_id: Some(decision_id.to_string()),
            ts: Utc::now().to_rfc3339(),
            agent_id: Some(agent_id.to_string()),
            user_id: payload.user.as_ref().map(|u| u.id.clone()),
            run_id: payload.trace.as_ref().map(|t| t.run_id.clone()),
            trace_id: payload.trace.as_ref().map(|t| t.trace_id.clone()),
            tool: Some(payload.tool_call.tool.clone()),
            action: Some(payload.tool_call.action.clone()),
            resource: payload.tool_call.resource.clone(),
            source_trust: payload.context.source_trust.clone(),
            decision: decision.to_string(),
            approver: None,
            action_hash: Some(hash_tool_call(&payload.tool_call)),
            prev_receipt_hash,
            receipt_hash: String::new(),
            // Self-describing scheme tag; additive, not folded into receipt_hash.
            canon_version: CANON_VERSION.to_string(),
            signature: None,
            signer_public_key: None,
            created_at: Utc::now(),
        };
        // Hash FIRST (byte-parity-locked), then optionally sign OVER the hash.
        receipt.receipt_hash = compute_receipt_hash(&receipt);
        apply_receipt_signature(&mut receipt);
        receipt
    })
    .await;

    if let Err(e) = result {
        error!("Failed to write action receipt: {:?}", e);
    }
}

/// Decision label for a receipt recording a detected integrity violation (T-D:
/// attacks on the evidence chain). A tamper-attempt receipt is appended to the same
/// hash chain as normal decisions so the chain itself records the attack — storing
/// ONLY hashes, never payloads.
const TAMPER_DECISION: &str = "tamper_attempt";

/// Append a tamper-attempt record to a tenant's receipt chain when the gateway
/// detects an integrity violation (an approval `action_hash` mismatch, or a consume
/// of an already-used / expired approval). Reuses the atomic, hash-chained receipt
/// machinery so the attack is tamper-evidently recorded. `kind` is a short, stable
/// tag for the violation; `action_hash` is the bound hash (never a payload). Also
/// mirrors the event into the audit log. Best-effort: a write failure is logged and
/// does not change the caller's response.
async fn emit_tamper_attempt_receipt(
    pool: &sqlx::SqlitePool,
    events: &EventSink,
    tenant_id: &str,
    agent_id: Option<&str>,
    kind: &str,
    approval_id: &str,
    action_hash: Option<String>,
) {
    let kind_owned = kind.to_string();
    let action_hash_for_receipt = action_hash.clone();
    let result = db::append_action_receipt_atomic(pool, tenant_id, |prev_receipt_hash| {
        let mut receipt = ActionReceiptRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            decision_id: None,
            ts: Utc::now().to_rfc3339(),
            agent_id: None,
            user_id: None,
            run_id: None,
            trace_id: None,
            // `tool`/`resource` carry only the violation tag + approval id (no payload).
            tool: Some(kind_owned.clone()),
            action: Some(TAMPER_DECISION.to_string()),
            resource: Some(format!("approval:{}", approval_id)),
            source_trust: "malicious_suspected".to_string(),
            decision: TAMPER_DECISION.to_string(),
            approver: None,
            action_hash: action_hash_for_receipt,
            prev_receipt_hash,
            receipt_hash: String::new(),
            canon_version: CANON_VERSION.to_string(),
            signature: None,
            signer_public_key: None,
            created_at: Utc::now(),
        };
        // Hash FIRST (byte-parity-locked), then optionally sign OVER the hash.
        receipt.receipt_hash = compute_receipt_hash(&receipt);
        apply_receipt_signature(&mut receipt);
        receipt
    })
    .await;

    if let Err(e) = result {
        error!("Failed to write tamper-attempt receipt: {:?}", e);
        return;
    }

    // Mirror to the audit log (hashes only — never payloads).
    let audit_record = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.to_string(),
        event_type: "tamper_attempt".to_string(),
        agent_id: None,
        user_id: None,
        run_id: None,
        trace_id: None,
        span_id: None,
        skill: None,
        action: Some(kind.to_string()),
        resource: Some(format!("approval:{}", approval_id)),
        event_json: serde_json::to_string(&json!({
            "kind": kind,
            "approval_id": approval_id,
            "action_hash": action_hash,
        }))
        .unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        created_at: Utc::now(),
    };
    if let Err(e) = db::insert_audit_event(pool, &audit_record).await {
        error!("Failed to write tamper-attempt audit event: {:?}", e);
    }

    // Integrity→SOC loop: the tamper-evident receipt now also surfaces on the async
    // SOC stream as a `replay_attempt` AseEvent so the detector raises a HIGH alert
    // (visible in `GET /v1/alerts`), not only in the receipt chain. STRICTLY
    // ADDITIVE: this runs only after the receipt write above succeeded, and the
    // emit is NON-BLOCKING (`try_send`) — a full/closed channel is dropped and never
    // affects the caller's 409/CONFLICT response. Carries ids + the violation tag
    // only (no payloads); tenant-scoped.
    events.emit(AseEvent {
        event_id: Uuid::new_v4().to_string(),
        occurred_at: Utc::now().to_rfc3339(),
        tenant_id: tenant_id.to_string(),
        kind: "replay_attempt".to_string(),
        agent_id: agent_id.unwrap_or("unknown").to_string(),
        decision: "deny".to_string(),
        tool: kind.to_string(),
        action: TAMPER_DECISION.to_string(),
        resource: Some(format!("approval:{}", approval_id)),
        risk_score: 0,
        reason: format!(
            "approval-integrity violation: {} (approval:{})",
            kind, approval_id
        ),
        run_id: None,
        trace_id: None,
        matched_policies: Vec::new(),
    });
}

/// True if the approval window has passed. Defense-in-depth alongside the SDK's
/// client-side expiry check: the gateway must not hand out, or grant, an approval
/// whose `expires_at` is in the past.
fn approval_is_expired(app: &ApprovalRecord) -> bool {
    app.expires_at.map(|e| e < Utc::now()).unwrap_or(false)
}

#[allow(clippy::too_many_arguments)]
async fn write_decision_and_audit(
    pool: &sqlx::SqlitePool,
    events: &EventSink,
    metrics: &SecurityMetrics,
    tenant_id: &str,
    agent_id: &str,
    payload: &AuthorizeRequest,
    decision_id: Uuid,
    decision: &str,
    risk_score: i32,
    reason: &str,
    matched_policies: &[String],
    audit_event_type: &str,
    started_at: std::time::Instant,
) -> Result<(), sqlx::Error> {
    // OBS-001 (#1154): record the inline /v1/authorize latency on the
    // Prometheus histogram. Recorded here (once per decision write) rather
    // than as middleware, so it shares the exact `started_at` already used
    // for `decision_record.latency_ms`.
    metrics.authorize_duration.observe(started_at.elapsed());

    let decision_record = DecisionRecord {
        id: decision_id.to_string(),
        tenant_id: tenant_id.to_string(),
        agent_id: agent_id.to_string(),
        user_id: payload.user.as_ref().map(|u| u.id.clone()),
        run_id: payload.trace.as_ref().map(|t| t.run_id.clone()),
        trace_id: payload.trace.as_ref().map(|t| t.trace_id.clone()),
        skill: payload.tool_call.tool.clone(),
        action: payload.tool_call.action.clone(),
        resource: payload.tool_call.resource.clone(),
        input_json: serde_json::to_string(&payload.tool_call.parameters).unwrap_or_default(),
        decision: decision.to_string(),
        risk_score: Some(risk_score),
        reason: Some(reason.to_string()),
        matched_policy_ids: Some(matched_policies.join(",")),
        request_id: payload.request_id.clone(),
        latency_ms: Some(started_at.elapsed().as_millis() as i64),
        created_at: Utc::now(),
    };

    db::insert_decision(pool, &decision_record).await?;

    let audit_record = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.to_string(),
        event_type: audit_event_type.to_string(),
        agent_id: Some(agent_id.to_string()),
        user_id: payload.user.as_ref().map(|u| u.id.clone()),
        run_id: payload.trace.as_ref().map(|t| t.run_id.clone()),
        trace_id: payload.trace.as_ref().map(|t| t.trace_id.clone()),
        span_id: None,
        skill: Some(payload.tool_call.tool.clone()),
        action: Some(payload.tool_call.action.clone()),
        resource: payload.tool_call.resource.clone(),
        event_json: serde_json::to_string(&decision_record).unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        created_at: Utc::now(),
    };
    db::insert_audit_event(pool, &audit_record).await?;

    // Phase 0 keystone: feed the async SOC stream. Non-blocking — the inline
    // decision has already been recorded above; emission never delays the caller.
    events.emit(AseEvent {
        event_id: Uuid::new_v4().to_string(),
        occurred_at: Utc::now().to_rfc3339(),
        tenant_id: tenant_id.to_string(),
        kind: "authorize_decision".to_string(),
        agent_id: agent_id.to_string(),
        decision: decision.to_string(),
        tool: payload.tool_call.tool.clone(),
        action: payload.tool_call.action.clone(),
        resource: payload.tool_call.resource.clone(),
        risk_score,
        reason: reason.to_string(),
        run_id: payload.trace.as_ref().map(|t| t.run_id.clone()),
        trace_id: payload.trace.as_ref().map(|t| t.trace_id.clone()),
        matched_policies: matched_policies.to_vec(),
    });

    Ok(())
}

pub async fn register_agent(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(payload): Json<RegisterAgentRequest>,
) -> impl IntoResponse {
    // Check if agent already exists
    match db::get_agent_by_key(&state.pool, &tenant_id, &payload.agent_key).await {
        Ok(Some(agent)) => {
            info!("Agent already registered: {}", payload.agent_key);
            let id = match Uuid::parse_str(&agent.id) {
                Ok(id) => id,
                Err(e) => {
                    error!("Stored agent id is not a valid UUID: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "Database error"})),
                    )
                        .into_response();
                }
            };
            return (
                StatusCode::OK,
                Json(RegisterAgentResponse {
                    id,
                    agent_key: agent.agent_key,
                    agent_token: "[REDACTED]".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
        _ => {}
    }

    // Generate a secure agent token
    let agent_token = format!("agent_tok_{}", Uuid::new_v4().simple());
    let hashed_token = db::hash_token(&agent_token);

    let agent_id = Uuid::new_v4();

    let agent_record = AgentRecord {
        id: agent_id.to_string(),
        tenant_id: tenant_id.clone(),
        agent_key: payload.agent_key,
        agent_token: hashed_token,
        name: payload.name,
        owner_team: payload.owner_team,
        owner_email: None,
        environment: payload.environment,
        framework: payload.framework,
        model_provider: payload.model_provider,
        model_name: payload.model_name,
        purpose: payload.purpose,
        risk_tier: payload.risk_tier,
        status: "active".to_string(),
        last_seen_at: None,
        frozen_reason: None,
        force_approval: false,
        quarantined_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    if let Err(e) = db::insert_agent(&state.pool, &agent_record).await {
        error!("Failed to insert agent: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Database insert failed"})),
        )
            .into_response();
    }

    // Log audit event
    let audit_id = Uuid::new_v4().to_string();
    let audit_record = AuditEventRecord {
        id: audit_id,
        tenant_id,
        event_type: "agent_registered".to_string(),
        agent_id: Some(agent_id.to_string()),
        user_id: None,
        run_id: None,
        trace_id: None,
        span_id: None,
        skill: None,
        action: None,
        resource: None,
        event_json: serde_json::to_string(&agent_record).unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        created_at: Utc::now(),
    };
    let _ = db::insert_audit_event(&state.pool, &audit_record).await;

    (
        StatusCode::CREATED,
        Json(RegisterAgentResponse {
            id: agent_id,
            agent_key: agent_record.agent_key,
            agent_token,
        }),
    )
        .into_response()
}

pub async fn list_agents(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let (limit, offset) = parse_pagination(raw_query.as_deref());

    match db::list_agents(&state.pool, &tenant_id, limit, offset).await {
        Ok(agents) => (StatusCode::OK, Json(agents)).into_response(),
        Err(e) => {
            error!("Failed to list agents: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

pub async fn get_agent(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match db::get_agent_by_id(&state.pool, &tenant_id, &id).await {
        Ok(Some(agent)) => (StatusCode::OK, Json(agent)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Agent not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to get agent detail: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

pub async fn patch_agent(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
    Json(payload): Json<PatchAgentRequest>,
) -> impl IntoResponse {
    let mut agent = match db::get_agent_by_id(&state.pool, &tenant_id, &id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Agent not found"})),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to lookup agent for patch: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    if let Some(name) = payload.name {
        agent.name = name;
    }
    if let Some(owner_team) = payload.owner_team {
        agent.owner_team = Some(owner_team);
    }
    if let Some(owner_email) = payload.owner_email {
        agent.owner_email = Some(owner_email);
    }
    if let Some(environment) = payload.environment {
        agent.environment = environment;
    }
    if let Some(framework) = payload.framework {
        agent.framework = Some(framework);
    }
    if let Some(model_provider) = payload.model_provider {
        agent.model_provider = Some(model_provider);
    }
    if let Some(model_name) = payload.model_name {
        agent.model_name = Some(model_name);
    }
    if let Some(purpose) = payload.purpose {
        agent.purpose = Some(purpose);
    }
    if let Some(risk_tier) = payload.risk_tier {
        agent.risk_tier = risk_tier;
    }
    if let Some(status) = payload.status {
        agent.status = status;
    }

    match db::update_agent(&state.pool, &agent).await {
        Ok(_) => (StatusCode::OK, Json(agent)).into_response(),
        Err(e) => {
            error!("Failed to update agent: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

pub async fn delete_agent(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match db::set_agent_status(&state.pool, &tenant_id, &id, "deleted").await {
        Ok(true) => (
            StatusCode::OK,
            Json(json!({"message": "Agent successfully deleted"})),
        )
            .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Agent not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to delete agent: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

// Register Static Tool Handler
pub async fn register_tool(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(payload): Json<RegisterToolRequest>,
) -> impl IntoResponse {
    // Insert skill
    let skill_id = match db::insert_skill(
        &state.pool,
        &tenant_id,
        &payload.skill_key,
        &payload.name,
        &payload.r#type,
        payload.auth_type.as_deref(),
        payload.owner_team.as_deref(),
        payload.default_risk.as_deref(),
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to register skill: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to register skill"})),
            )
                .into_response();
        }
    };

    // Insert skill actions
    for action in payload.actions {
        if let Err(e) = db::insert_skill_action(
            &state.pool,
            &skill_id,
            &action.action_key,
            action.description.as_deref(),
            &action.risk,
            action.mutates_state,
            action.data_access.as_deref(),
            action.approval_required,
            &action.default_decision,
        )
        .await
        {
            error!("Failed to register skill action: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to register skill action"})),
            )
                .into_response();
        }
        // #899: a (re-)registration may tighten this action's settings, so drop any
        // cached entry — the next authorize re-reads the fresh row (fail-closed).
        state.skill_cache.invalidate(&SkillActionCache::cache_key(
            &tenant_id,
            &payload.skill_key,
            &action.action_key,
        ));
    }

    (
        StatusCode::OK,
        Json(json!({"status": "success", "skill_id": skill_id})),
    )
        .into_response()
}

// Register MCP Server Handler
pub async fn register_mcp_server(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(payload): Json<RegisterMcpServerRequest>,
) -> impl IntoResponse {
    let server_id = match db::upsert_mcp_server(
        &state.pool,
        &tenant_id,
        &payload.server_key,
        &payload.name,
        payload.owner_team.as_deref(),
        &payload.transport,
        payload.source.as_deref(),
        &payload.trust_level,
        &payload.endpoint,
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to register MCP server: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    (
        StatusCode::CREATED,
        Json(RegisterMcpServerResponse {
            server_id,
            server_key: payload.server_key,
            status: "active".to_string(),
        }),
    )
        .into_response()
}

pub async fn discover_mcp_tools(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(server_key): Path<String>,
    Json(payload): Json<DiscoverMcpToolsRequest>,
) -> impl IntoResponse {
    let server = match db::get_mcp_server_by_key(&state.pool, &tenant_id, &server_key).await {
        Ok(Some(server)) => server,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "MCP server not found"})),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to look up MCP server: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    let skill_key = format!("mcp:{}", server_key);
    let skill_id = match db::insert_skill(
        &state.pool,
        &tenant_id,
        &skill_key,
        &server.name,
        "mcp",
        None,
        server.owner_team.as_deref(),
        None,
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to register MCP skill manifest: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to register MCP skill manifest"})),
            )
                .into_response();
        }
    };

    let mut registered = 0usize;
    for tool in &payload.tools {
        if let Err(e) = db::upsert_mcp_tool(&state.pool, &tenant_id, &server.id, tool).await {
            error!("Failed to upsert MCP tool manifest: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to register MCP tool manifest"})),
            )
                .into_response();
        }

        let default_decision = if tool.approval_required {
            "require_approval"
        } else {
            "policy"
        };
        if let Err(e) = db::insert_skill_action(
            &state.pool,
            &skill_id,
            &tool.tool_key,
            tool.description.as_deref(),
            &tool.risk,
            tool.mutates_state,
            None,
            tool.approval_required,
            default_decision,
        )
        .await
        {
            error!("Failed to upsert MCP skill action: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to register MCP skill action"})),
            )
                .into_response();
        }
        // #899: re-discovery may change this tool's settings — invalidate the cache.
        state.skill_cache.invalidate(&SkillActionCache::cache_key(
            &tenant_id,
            &skill_key,
            &tool.tool_key,
        ));

        let audit_record = AuditEventRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.clone(),
            event_type: "mcp_tool_discovered".to_string(),
            agent_id: None,
            user_id: None,
            run_id: None,
            trace_id: None,
            span_id: None,
            skill: Some(skill_key.clone()),
            action: Some(tool.tool_key.clone()),
            resource: Some(server_key.clone()),
            event_json: serde_json::to_string(tool).unwrap_or_default(),
            input_hash: None,
            output_hash: None,
            created_at: Utc::now(),
        };
        let _ = db::insert_audit_event(&state.pool, &audit_record).await;
        registered += 1;
    }

    // MCP tool-manifest drift detection (SOC `mcp_manifest_drift`). Pin the manifest
    // hash on first discovery; on a later discovery whose hash differs from the pin,
    // surface a drift event on the async SOC stream and re-pin to the new value (so
    // each distinct change alerts exactly once). STRICTLY ADDITIVE and best-effort:
    // any DB error here is logged and never blocks the discovery response, and the
    // SOC emit is non-blocking (`try_send`). Carries the server key + hashes only —
    // never any tool payload.
    let new_manifest_hash = compute_mcp_manifest_hash(&payload.tools);
    match db::get_mcp_server_manifest_hash(&state.pool, &tenant_id, &server_key).await {
        Ok(pinned) => {
            if !pinned.is_empty() && pinned != new_manifest_hash {
                state.events.emit(AseEvent {
                    event_id: Uuid::new_v4().to_string(),
                    occurred_at: Utc::now().to_rfc3339(),
                    tenant_id: tenant_id.clone(),
                    kind: "mcp_manifest_drift".to_string(),
                    agent_id: "system".to_string(),
                    // Not a deny — drift is a server-integrity flag, not an authorize
                    // decision (kept out of the deny-storm correlation, design law 1).
                    decision: "flag".to_string(),
                    tool: format!("mcp:{}", server_key),
                    action: "discover".to_string(),
                    resource: Some(server_key.clone()),
                    risk_score: 0,
                    reason: format!(
                        "MCP tool-manifest drift on server '{}': pinned {} != observed {}",
                        server_key, pinned, new_manifest_hash
                    ),
                    run_id: None,
                    trace_id: None,
                    matched_policies: Vec::new(),
                });

                // Fail-closed response (Phase 4): drift is a tool-hijack signal, so
                // auto-quarantine the server. The inline authorize gate above then
                // denies every tool call until an operator verifies the new manifest
                // out-of-band and explicitly restores the server. Best-effort: a DB
                // error is logged and never blocks the discovery response.
                if let Err(e) =
                    db::set_mcp_server_status(&state.pool, &tenant_id, &server_key, "quarantined")
                        .await
                {
                    error!("Failed to auto-quarantine drifted MCP server: {:?}", e);
                }
            }
            if pinned != new_manifest_hash {
                if let Err(e) = db::set_mcp_server_manifest_hash(
                    &state.pool,
                    &tenant_id,
                    &server_key,
                    &new_manifest_hash,
                )
                .await
                {
                    error!("Failed to pin MCP manifest hash: {:?}", e);
                }
            }
        }
        Err(e) => error!("Failed to read pinned MCP manifest hash: {:?}", e),
    }

    // DB-007 (#932): record discovery timestamp regardless of drift outcome.
    // Best-effort: a DB error here never blocks the discovery response.
    if let Err(e) = db::touch_mcp_server_discovery(&state.pool, &tenant_id, &server_key).await {
        error!("Failed to record MCP discovery timestamp: {:?}", e);
    }

    let tools = match db::list_mcp_tools(&state.pool, &tenant_id, &server_key).await {
        Ok(tools) => tools,
        Err(e) => {
            error!("Failed to list MCP tools after discovery: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "server_key": server_key,
            "tools_registered": registered,
            "tools": tools,
        })),
    )
        .into_response()
}

pub async fn get_mcp_tool_manifest(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(server_key): Path<String>,
) -> impl IntoResponse {
    match db::get_mcp_server_by_key(&state.pool, &tenant_id, &server_key).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "MCP server not found"})),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to look up MCP server: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    }

    match db::list_mcp_tools(&state.pool, &tenant_id, &server_key).await {
        Ok(tools) => (
            StatusCode::OK,
            Json(json!({"server_key": server_key, "tools": tools})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to list MCP tools: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

pub async fn approve_mcp_tool(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path((server_key, tool_key)): Path<(String, String)>,
) -> impl IntoResponse {
    update_mcp_tool_status(state, tenant_id, server_key, tool_key, "approved").await
}

pub async fn disable_mcp_tool(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path((server_key, tool_key)): Path<(String, String)>,
) -> impl IntoResponse {
    update_mcp_tool_status(state, tenant_id, server_key, tool_key, "disabled").await
}

async fn update_mcp_tool_status(
    state: Arc<AppState>,
    tenant_id: String,
    server_key: String,
    tool_key: String,
    status: &str,
) -> axum::response::Response {
    match db::set_mcp_tool_status(&state.pool, &tenant_id, &server_key, &tool_key, status).await {
        Ok(true) => {
            let audit_record = AuditEventRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id,
                event_type: "mcp_tool_status_changed".to_string(),
                agent_id: None,
                user_id: None,
                run_id: None,
                trace_id: None,
                span_id: None,
                skill: Some(format!("mcp:{}", server_key)),
                action: Some(tool_key.clone()),
                resource: Some(server_key.clone()),
                event_json: serde_json::to_string(&json!({
                    "server_key": server_key,
                    "tool_key": tool_key,
                    "status": status,
                }))
                .unwrap_or_default(),
                input_hash: None,
                output_hash: None,
                created_at: Utc::now(),
            };
            let _ = db::insert_audit_event(&state.pool, &audit_record).await;

            (
                StatusCode::OK,
                Json(McpToolStatusResponse {
                    server_key,
                    tool_key,
                    status: status.to_string(),
                }),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "MCP tool not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to update MCP tool status: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

// Authorize Action Handler
pub async fn authorize_action(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<AuthorizeRequest>,
) -> impl IntoResponse {
    // #0081: wall-clock time for this evaluation, persisted on the decision row
    // for SOC/perf dashboards. Captured first so it covers agent resolution too.
    let started_at = std::time::Instant::now();
    // Resolve agent from Bearer agent_token
    let auth_header = match headers.get("Authorization").and_then(|h| h.to_str().ok()) {
        Some(h) if h.starts_with("Bearer ") => &h["Bearer ".len()..],
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing agent token"})),
            )
                .into_response()
        }
    };

    let runtime_tenant_id = match get_runtime_tenant_from_headers(&headers) {
        Some(tid) => tid,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Missing X-Aegis-Tenant-ID or X-Tenant-ID header"})),
            )
                .into_response()
        }
    };
    let agent = match db::get_agent_by_token(&state.pool, &runtime_tenant_id, auth_header).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid or quarantined agent token"})),
            )
                .into_response()
        }
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    let tenant_id = agent.tenant_id.clone();
    let agent_id = agent.id.clone();

    // Idempotency (#0072): a repeat call with the same request_id returns the
    // original decision unchanged instead of re-evaluating Cedar and writing
    // duplicate audit events / approvals / receipts.
    if let Some(request_id) = payload.request_id.as_deref().filter(|r| !r.is_empty()) {
        match db::get_decision_by_request_id(&state.pool, &tenant_id, &agent_id, request_id).await {
            Ok(Some(record)) => {
                return idempotent_replay_response(&state, &tenant_id, record).await;
            }
            Ok(None) => {}
            Err(e) => {
                error!("Idempotency lookup failed: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Database error"})),
                )
                    .into_response();
            }
        }
    }

    // Heartbeat (#0080): record this contact as the agent's most recent activity.
    // Best-effort — never fails the request.
    let _ = db::touch_agent_last_seen(&state.pool, &tenant_id, &agent_id).await;

    // Check Rate Limiting (TASK-0012)
    if !state.rate_limiter.check_rate_limit(&tenant_id) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "Too many requests. Rate limit exceeded."})),
        )
            .into_response();
    }

    // Check Request Quota (TASK-0013)
    if !state.quota_manager.check_quota(&tenant_id) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "Request quota exceeded."})),
        )
            .into_response();
    }

    // Check if the agent is frozen or revoked (TASK-0014)
    if agent.status == "frozen" || agent.status == "revoked" {
        let decision_id = Uuid::new_v4();
        let reason = format!(
            "Agent '{}' is {}; all tool calls are denied (fail-closed).",
            agent.agent_key, agent.status
        );
        let matched_policies = vec![format!("agent_{}", agent.status)];
        let risk_score = 100;
        let risk_level = "critical".to_string();

        let audit_event_type = if mcp_server_key_from_tool(&payload.tool_call.tool).is_some() {
            "mcp_tool_called"
        } else {
            "tool_call_intercepted"
        };

        if let Err(e) = write_decision_and_audit(
            &state.pool,
            &state.events,
            &state.metrics,
            &tenant_id,
            &agent_id,
            &payload,
            decision_id,
            "deny",
            risk_score,
            &reason,
            &matched_policies,
            audit_event_type,
            started_at,
        )
        .await
        {
            error!("Failed to write agent-frozen denial: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }

        return (
            StatusCode::OK,
            Json(AuthorizeResponse {
                decision_id,
                decision: "deny".to_string(),
                risk_score,
                risk_level,
                reason,
                matched_policies,
                approval: None,
            }),
        )
            .into_response();
    }

    // Map risk levels based on DB registered action, falling back to policy engine defaults.
    let mut risk_score = 10;
    let mut risk_level = "low".to_string();
    let mut action_approval_required = false;
    let mut action_default_decision = "policy".to_string();

    // Read-through cache (#899): registered-action metadata is static between
    // registrations, so serve it from the LRU and fall back to the DB on a miss.
    let skill_cache_key = SkillActionCache::cache_key(
        &tenant_id,
        &payload.tool_call.tool,
        &payload.tool_call.action,
    );
    let action_meta = match state.skill_cache.get(&skill_cache_key) {
        Some(meta) => Some(meta),
        None => match db::get_skill_action(
            &state.pool,
            &tenant_id,
            &payload.tool_call.tool,
            &payload.tool_call.action,
        )
        .await
        {
            Ok(Some(meta)) => {
                // Cache only positive hits; unknown actions keep missing to the DB.
                state
                    .skill_cache
                    .insert(skill_cache_key.clone(), meta.clone());
                Some(meta)
            }
            Ok(None) => None,
            Err(e) => {
                error!("Failed to look up registered action: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Database error"})),
                )
                    .into_response();
            }
        },
    };

    if let Some((risk, _, approval_required, default_decision)) = action_meta {
        risk_level = risk;
        risk_score = risk_score_for_level(&risk_level);
        action_approval_required = approval_required;
        action_default_decision = default_decision;
    }

    let mcp_server_key = mcp_server_key_from_tool(&payload.tool_call.tool).map(str::to_string);
    let is_mcp_call = mcp_server_key.is_some();

    if let Some(server_key) = mcp_server_key.as_deref() {
        // Fail-closed server-level gate (Phase 4 response enforcement). A
        // quarantined MCP server — whether quarantined by an operator or
        // auto-quarantined on tool-manifest drift — denies ALL of its tool calls
        // inline, regardless of any tool's prior approved status. Without this,
        // quarantine was recorded but never enforced on the authorize hot path.
        match db::get_mcp_server_by_key(&state.pool, &tenant_id, server_key).await {
            Ok(Some(server)) if server.status == "quarantined" => {
                let decision_id = Uuid::new_v4();
                let reason = format!(
                    "MCP server '{}' is quarantined; all tool calls are denied (fail-closed).",
                    server_key
                );
                let matched_policies = vec!["mcp_server_quarantined".to_string()];
                risk_level = "critical".to_string();
                risk_score = 100;

                if let Err(e) = write_decision_and_audit(
                    &state.pool,
                    &state.events,
                    &state.metrics,
                    &tenant_id,
                    &agent_id,
                    &payload,
                    decision_id,
                    "deny",
                    risk_score,
                    &reason,
                    &matched_policies,
                    "mcp_tool_called",
                    started_at,
                )
                .await
                {
                    error!("Failed to write quarantined-server denial: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "Database error"})),
                    )
                        .into_response();
                }

                return (
                    StatusCode::OK,
                    Json(AuthorizeResponse {
                        decision_id,
                        decision: "deny".to_string(),
                        risk_score,
                        risk_level,
                        reason,
                        matched_policies,
                        approval: None,
                    }),
                )
                    .into_response();
            }
            Ok(_) => {}
            Err(e) => {
                error!("Failed to look up MCP server status: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Database error"})),
                )
                    .into_response();
            }
        }

        match db::get_mcp_tool_by_key(
            &state.pool,
            &tenant_id,
            server_key,
            &payload.tool_call.action,
        )
        .await
        {
            Ok(Some(tool)) => {
                risk_level = tool.risk.clone();
                risk_score = risk_score_for_level(&risk_level);
                action_approval_required = action_approval_required || tool.approval_required;

                if tool.status != "approved" {
                    let decision_id = Uuid::new_v4();
                    let reason = format!(
                        "MCP tool '{}' on server '{}' is not approved (status: {}).",
                        payload.tool_call.action, server_key, tool.status
                    );
                    let matched_policies = vec!["mcp_tool_status".to_string()];

                    if let Err(e) = write_decision_and_audit(
                        &state.pool,
                        &state.events,
                        &state.metrics,
                        &tenant_id,
                        &agent_id,
                        &payload,
                        decision_id,
                        "deny",
                        risk_score,
                        &reason,
                        &matched_policies,
                        "mcp_tool_called",
                        started_at,
                    )
                    .await
                    {
                        error!("Failed to write MCP denial decision: {:?}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": "Database error"})),
                        )
                            .into_response();
                    }

                    return (
                        StatusCode::OK,
                        Json(AuthorizeResponse {
                            decision_id,
                            decision: "deny".to_string(),
                            risk_score,
                            risk_level,
                            reason,
                            matched_policies,
                            approval: None,
                        }),
                    )
                        .into_response();
                }
            }
            Ok(None) => {
                let decision_id = Uuid::new_v4();
                let reason = format!(
                    "Unknown MCP tool '{}' for server '{}' is denied by default.",
                    payload.tool_call.action, server_key
                );
                let matched_policies = vec!["mcp_unknown_tool".to_string()];
                risk_level = "critical".to_string();
                risk_score = 100;

                if let Err(e) = write_decision_and_audit(
                    &state.pool,
                    &state.events,
                    &state.metrics,
                    &tenant_id,
                    &agent_id,
                    &payload,
                    decision_id,
                    "deny",
                    risk_score,
                    &reason,
                    &matched_policies,
                    "mcp_tool_called",
                    started_at,
                )
                .await
                {
                    error!("Failed to write unknown MCP denial decision: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "Database error"})),
                    )
                        .into_response();
                }

                return (
                    StatusCode::OK,
                    Json(AuthorizeResponse {
                        decision_id,
                        decision: "deny".to_string(),
                        risk_score,
                        risk_level,
                        reason,
                        matched_policies,
                        approval: None,
                    }),
                )
                    .into_response();
            }
            Err(e) => {
                error!("Failed to look up MCP tool: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Database error"})),
                )
                    .into_response();
            }
        }
    }

    // Ensure policies for the tenant are loaded into the engine.
    if !state.policy_engine.has_tenant(&tenant_id) {
        let _ = state
            .policy_engine
            .reload_tenant_policies(&state.pool, &tenant_id)
            .await;
    }

    // Call policy engine to evaluate Cedar rules
    let policy_decision = match state.policy_engine.authorize(&tenant_id, &payload) {
        Ok(d) => d,
        Err(e) => {
            error!("Policy engine error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Policy engine failure: {}", e)})),
            )
                .into_response();
        }
    };

    let decision_id = Uuid::new_v4();
    let mut decision_str = policy_decision.decision.clone();
    let mut reason = policy_decision.reason.clone();
    let mut matched_policies = policy_decision.matched_policies.clone();

    // Security metric: provenance_denials_total — count Cedar-level denials driven by
    // untrusted/malicious/unknown provenance on a mutating action (anti-confused-deputy).
    if decision_str == "deny"
        && payload.tool_call.mutates_state
        && is_untrusted_provenance(&payload.context.source_trust)
    {
        state.metrics.inc_provenance_denial();
    }

    if decision_str == "allow" {
        if action_default_decision == "deny" {
            decision_str = "deny".to_string();
            reason = "Registered action default decision is deny.".to_string();
            matched_policies.push("registered_action_default_deny".to_string());
        } else if action_default_decision == "require_approval" || action_approval_required {
            decision_str = "require_approval".to_string();
            reason = "Registered action requires approval.".to_string();
            matched_policies.push("registered_action_approval_required".to_string());
        }
    }

    // Enforce secure defaults (fail-closed)
    // If decision returns allow but action risk is critical, enforce require_approval by default if not set otherwise.
    if decision_str == "allow" && risk_level == "critical" {
        decision_str = "require_approval".to_string();
        reason = "Critical-risk action requires approval by default.".to_string();
        matched_policies.push("critical_risk_requires_approval".to_string());
    }

    // SOC Response Engine (#1184, Phase 4): a prior trust_escalation incident
    // set agents.force_approval for this agent. Downgrade allow -> require_approval
    // for every subsequent action until an operator clears it.
    if decision_str == "allow" && agent.force_approval {
        decision_str = "require_approval".to_string();
        reason = "Agent requires approval for all actions following a trust escalation incident."
            .to_string();
        matched_policies.push("soc_response_force_approval".to_string());
    }

    let audit_event_type = if is_mcp_call {
        "mcp_tool_called"
    } else {
        "tool_call_intercepted"
    };

    if let Err(e) = write_decision_and_audit(
        &state.pool,
        &state.events,
        &state.metrics,
        &tenant_id,
        &agent_id,
        &payload,
        decision_id,
        &decision_str,
        risk_score,
        &reason,
        &matched_policies,
        audit_event_type,
        started_at,
    )
    .await
    {
        error!("Failed to write decision: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Database error"})),
        )
            .into_response();
    }

    // Emit a verifiable, hash-chained receipt for this decision (non-fatal).
    emit_action_receipt(
        &state.pool,
        &tenant_id,
        &agent_id,
        &payload,
        decision_id,
        &decision_str,
    )
    .await;

    let mut approval_info = None;

    if decision_str == "require_approval" {
        let approval_id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::seconds(state.approval_ttl_secs);
        let original_call_hash = hash_tool_call(&payload.tool_call);

        // #1187/TASK-0082-0083: optional approval-callback registration. The
        // plaintext secret is hashed immediately and never persisted
        // (redaction invariant) — only `callback_url` and
        // `sha256(secret)` are stored.
        let (callback_url, callback_secret_hash) = match &payload.callback {
            Some(cb) => (
                Some(cb.url.clone()),
                cb.secret.as_ref().map(|s| sha256_hex(s.as_bytes())),
            ),
            None => (None, None),
        };

        let approval_record = ApprovalRecord {
            id: approval_id.to_string(),
            tenant_id: tenant_id.clone(),
            decision_id: decision_id.to_string(),
            status: "created".to_string(),
            approver_group: policy_decision.approver_group.clone(),
            approver_user_id: None,
            reason: None,
            original_skill_call: serde_json::to_string(&payload.tool_call).unwrap_or_default(),
            original_call_hash: original_call_hash.clone(),
            edited_skill_call: None,
            expires_at: Some(expires_at),
            decided_at: None,
            callback_url,
            callback_secret_hash,
            created_at: Utc::now(),
        };

        if let Err(e) = db::insert_approval(&state.pool, &approval_record).await {
            error!("Failed to create approval request: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to create approval request"})),
            )
                .into_response();
        }

        // Write audit event for approval creation
        let audit_app_record = AuditEventRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.clone(),
            event_type: "approval_created".to_string(),
            agent_id: Some(agent_id.clone()),
            user_id: payload.user.as_ref().map(|u| u.id.clone()),
            run_id: payload.trace.as_ref().map(|t| t.run_id.clone()),
            trace_id: payload.trace.as_ref().map(|t| t.trace_id.clone()),
            span_id: None,
            skill: Some(payload.tool_call.tool.clone()),
            action: Some(payload.tool_call.action.clone()),
            resource: payload.tool_call.resource.clone(),
            event_json: serde_json::to_string(&approval_record).unwrap_or_default(),
            input_hash: Some(original_call_hash.clone()),
            output_hash: None,
            created_at: Utc::now(),
        };
        let _ = db::insert_audit_event(&state.pool, &audit_app_record).await;

        approval_info = Some(ApprovalResponseInfo {
            approval_id,
            status: "created".to_string(),
            approver_group: policy_decision.approver_group,
            expires_at,
            action_hash: original_call_hash,
        });
    }

    (
        StatusCode::OK,
        Json(AuthorizeResponse {
            decision_id,
            decision: decision_str,
            risk_score,
            risk_level,
            reason,
            matched_policies,
            approval: approval_info,
        }),
    )
        .into_response()
}

// Get Approval Status Handler
pub async fn get_approval(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(approval_id): Path<Uuid>,
) -> impl IntoResponse {
    match db::get_approval_by_id(&state.pool, &tenant_id, &approval_id.to_string()).await {
        Ok(Some(app)) => {
            let edited_call: Option<AuthorizeToolCall> = app
                .edited_skill_call
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok());
            // A still-pending approval past its window is dead: report EXPIRED so
            // any client (even a forked SDK) fails closed instead of waiting.
            let effective_status = if app.status == "created" && approval_is_expired(&app) {
                "EXPIRED".to_string()
            } else {
                app.status.clone()
            };
            (
                StatusCode::OK,
                Json(json!({
                    "approval_id": app.id,
                    "status": effective_status,
                    "approver_group": app.approver_group,
                    "approver_user_id": app.approver_user_id,
                    "reason": app.reason,
                    "action_hash": app.original_call_hash,
                    "edited_tool_call": edited_call,
                    "expires_at": app.expires_at,
                    "decided_at": app.decided_at,
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Approval request not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

/// Optional body for the consume endpoint. If `claimed_action_hash` is supplied,
/// the gateway validates it against the bound hash and increments
/// `approval_hash_mismatch_total` on a discrepancy (approve-then-swap defence).
#[derive(Debug, serde::Deserialize, Default)]
pub struct ConsumeApprovalBody {
    pub claimed_action_hash: Option<String>,
}

// Consume Handler: single-use, atomic consumption of an APPROVED approval.
// The SDK calls this before executing so an approval cannot be replayed/reused.
pub async fn consume_approval(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(approval_id): Path<Uuid>,
    // JSON body is optional; old callers that POST with no body still work.
    body: Option<Json<ConsumeApprovalBody>>,
) -> impl IntoResponse {
    let consumed =
        match db::consume_approval(&state.pool, &tenant_id, &approval_id.to_string()).await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to consume approval: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Database error"})),
                )
                    .into_response();
            }
        };

    if !consumed {
        // A consume of an already-used / expired / not-approved approval is an
        // attack on the evidence chain (replay / T-D): record it as a tamper-attempt
        // receipt so the chain itself captures the attempt. Hashes only, no payloads.
        let bound_hash = db::get_approval_by_id(&state.pool, &tenant_id, &approval_id.to_string())
            .await
            .ok()
            .flatten()
            .map(|a| a.original_call_hash);
        // The approval record does not carry the agent id; the SOC event uses the
        // "unknown" placeholder (the violation tag + approval id are the evidence).
        emit_tamper_attempt_receipt(
            &state.pool,
            &state.events,
            &tenant_id,
            None,
            "consume_not_consumable",
            &approval_id.to_string(),
            bound_hash,
        )
        .await;
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "Approval not consumable (already used, expired, or not approved)",
                "approval_id": approval_id,
            })),
        )
            .into_response();
    }

    // Return the bound action hash so the SDK can re-verify before executing.
    let action_hash = db::get_approval_by_id(&state.pool, &tenant_id, &approval_id.to_string())
        .await
        .ok()
        .flatten()
        .map(|a| a.original_call_hash)
        .unwrap_or_default();

    // Security metric: if the caller supplied a claimed_action_hash, compare it
    // against the bound hash. A mismatch means an approve-then-swap was attempted.
    if let Some(Json(ref b)) = body {
        if let Some(ref claimed) = b.claimed_action_hash {
            if *claimed != action_hash {
                state.metrics.inc_hash_mismatch();
                error!(
                    approval_id = %approval_id,
                    "approval_hash_mismatch: claimed hash does not match bound hash"
                );
                return (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": "Action hash mismatch: the action to be executed differs from the approved action",
                        "approval_id": approval_id,
                    })),
                )
                    .into_response();
            }
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "status": "consumed",
            "approval_id": approval_id,
            "action_hash": action_hash,
        })),
    )
        .into_response()
}

// Verify a stored action receipt by recomputing its hash from the canonical body.
pub async fn verify_receipt(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(receipt_id): Path<String>,
) -> impl IntoResponse {
    match db::get_action_receipt_by_id(&state.pool, &tenant_id, &receipt_id).await {
        Ok(Some(rec)) => {
            // Hash (chain) integrity — UNCHANGED. This is the byte-parity-locked check.
            let recomputed = compute_receipt_hash(&rec);
            let verified = recomputed == rec.receipt_hash;

            // Optional signature verification — ADDITIVE, never affects `verified`.
            // signed   -> signature_verified = true/false (Ed25519 over receipt_hash)
            // unsigned -> signature_verified = null (no signer was configured)
            let signature_verified = match (&rec.signature, &rec.signer_public_key) {
                (Some(sig), Some(pk)) => {
                    Value::Bool(sign::verify_signature(pk, &rec.receipt_hash, sig))
                }
                _ => Value::Null,
            };

            (
                StatusCode::OK,
                Json(json!({
                    "receipt_id": rec.id,
                    "verified": verified,
                    "receipt_hash": rec.receipt_hash,
                    "recomputed_hash": recomputed,
                    "prev_receipt_hash": rec.prev_receipt_hash,
                    "signed": rec.signature.is_some(),
                    "signature_verified": signature_verified,
                    "signer_public_key": rec.signer_public_key,
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Receipt not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

// Approve Handler
pub async fn approve_approval(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(approval_id): Path<Uuid>,
    Json(payload): Json<ApproveRequest>,
) -> impl IntoResponse {
    // Load the approval first so we can fail closed on stale or already-decided
    // requests instead of blindly transitioning to APPROVED.
    let approval =
        match db::get_approval_by_id(&state.pool, &tenant_id, &approval_id.to_string()).await {
            Ok(Some(app)) => app,
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "Approval request not found"})),
                )
                    .into_response();
            }
            Err(e) => {
                error!("Database lookup error: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Database error"})),
                )
                    .into_response();
            }
        };

    // Only a pending approval may be approved (no re-deciding an APPROVED/REJECTED/EDITED one).
    if approval.status != "created" {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "Approval already decided",
                "status": approval.status,
                "approval_id": approval_id,
            })),
        )
            .into_response();
    }

    // Fail closed if the approval window has already passed. Granting an expired
    // approval is an attack on the evidence chain (T-D); record the attempt as a
    // tamper-attempt receipt (hashes only) before refusing.
    if approval_is_expired(&approval) {
        emit_tamper_attempt_receipt(
            &state.pool,
            &state.events,
            &tenant_id,
            None,
            "approve_expired",
            &approval_id.to_string(),
            Some(approval.original_call_hash.clone()),
        )
        .await;
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "Approval has expired",
                "approval_id": approval_id,
            })),
        )
            .into_response();
    }

    // Update approval status to APPROVED
    if let Err(e) = db::update_approval_status(
        &state.pool,
        &tenant_id,
        &approval_id.to_string(),
        "APPROVED",
        &payload.approver_user_id,
        payload.reason.as_deref(),
        None,
    )
    .await
    {
        error!("Failed to approve request: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to approve request"})),
        )
            .into_response();
    }

    // Write audit event
    let audit_record = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id,
        event_type: "approval_decided".to_string(),
        agent_id: None,
        user_id: Some(payload.approver_user_id),
        run_id: None,
        trace_id: None,
        span_id: None,
        skill: None,
        action: None,
        resource: None,
        event_json: serde_json::to_string(&json!({
            "approval_id": approval_id,
            "status": "APPROVED",
            "reason": payload.reason
        }))
        .unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        created_at: Utc::now(),
    };
    let _ = db::insert_audit_event(&state.pool, &audit_record).await;

    (
        StatusCode::OK,
        Json(json!({"status": "success", "approval_id": approval_id})),
    )
        .into_response()
}

// Reject Handler
pub async fn reject_approval(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(approval_id): Path<Uuid>,
    Json(payload): Json<ApproveRequest>,
) -> impl IntoResponse {
    // Update approval status to REJECTED
    if let Err(e) = db::update_approval_status(
        &state.pool,
        &tenant_id,
        &approval_id.to_string(),
        "REJECTED",
        &payload.approver_user_id,
        payload.reason.as_deref(),
        None,
    )
    .await
    {
        error!("Failed to reject request: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to reject request"})),
        )
            .into_response();
    }

    // Write audit event
    let audit_record = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id,
        event_type: "approval_decided".to_string(),
        agent_id: None,
        user_id: Some(payload.approver_user_id),
        run_id: None,
        trace_id: None,
        span_id: None,
        skill: None,
        action: None,
        resource: None,
        event_json: serde_json::to_string(&json!({
            "approval_id": approval_id,
            "status": "REJECTED",
            "reason": payload.reason
        }))
        .unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        created_at: Utc::now(),
    };
    let _ = db::insert_audit_event(&state.pool, &audit_record).await;

    (
        StatusCode::OK,
        Json(json!({"status": "success", "approval_id": approval_id})),
    )
        .into_response()
}

// Edit parameters handler
pub async fn edit_approval(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(approval_id): Path<Uuid>,
    Json(payload): Json<EditApprovalRequest>,
) -> impl IntoResponse {
    // Load the approval first so we can fail closed on stale or already-decided
    // requests instead of blindly transitioning to EDITED (#0131).
    let approval =
        match db::get_approval_by_id(&state.pool, &tenant_id, &approval_id.to_string()).await {
            Ok(Some(app)) => app,
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "Approval request not found"})),
                )
                    .into_response();
            }
            Err(e) => {
                error!("Database lookup error: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Database error"})),
                )
                    .into_response();
            }
        };

    // Only a pending approval may be edited (no editing an APPROVED/REJECTED/
    // already-EDITED/consumed one).
    if approval.status != "created" {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "Approval already decided",
                "status": approval.status,
                "approval_id": approval_id,
            })),
        )
            .into_response();
    }

    let edited_call_str = serde_json::to_string(&payload.edited_tool_call).unwrap_or_default();
    // Re-hash the edited call (#0130): the approval is now bound to the edited
    // action, so a subsequent approve/consume re-verifies against this hash,
    // not the original.
    let new_action_hash = hash_tool_call(&payload.edited_tool_call);

    // Update approval status to EDITED, re-binding the action_hash.
    if let Err(e) = db::update_approval_edit(
        &state.pool,
        &tenant_id,
        &approval_id.to_string(),
        &payload.approver_user_id,
        payload.reason.as_deref(),
        &edited_call_str,
        &new_action_hash,
    )
    .await
    {
        error!("Failed to edit approval: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to edit request"})),
        )
            .into_response();
    }

    // Write audit event
    let audit_record = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id,
        event_type: "approval_decided".to_string(),
        agent_id: None,
        user_id: Some(payload.approver_user_id),
        run_id: None,
        trace_id: None,
        span_id: None,
        skill: None,
        action: None,
        resource: None,
        event_json: serde_json::to_string(&json!({
            "approval_id": approval_id,
            "status": "EDITED",
            "reason": payload.reason,
            "edited_tool_call": payload.edited_tool_call
        }))
        .unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        created_at: Utc::now(),
    };
    let _ = db::insert_audit_event(&state.pool, &audit_record).await;

    (
        StatusCode::OK,
        Json(json!({"status": "success", "approval_id": approval_id})),
    )
        .into_response()
}

// Get Investigation Run Timeline
pub async fn get_timeline(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(run_id): Path<String>,
) -> impl IntoResponse {
    match db::get_audit_events_by_run(&state.pool, &tenant_id, &run_id).await {
        Ok(events) => (StatusCode::OK, Json(events)).into_response(),
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

// Get All Audit Events Logs
pub async fn get_audit_events(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
) -> impl IntoResponse {
    match db::get_all_audit_events(&state.pool, &tenant_id).await {
        Ok(events) => (StatusCode::OK, Json(events)).into_response(),
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

// ── SOC Phase 5: Indexer Query API ───────────────────────────────────────────

/// Parse a `?limit=` / `?offset=` query string with sane defaults and hard caps.
/// Avoids extracting `axum::extract::Query<HashMap<…>>` to keep the code simple;
/// falls back to the default on any parse error.
fn parse_pagination(query: Option<&str>) -> (i64, i64) {
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
fn parse_filter(query: Option<&str>, key: &str) -> Option<String> {
    query?.split('&').find_map(|pair| {
        let mut kv = pair.splitn(2, '=');
        match (kv.next(), kv.next()) {
            (Some(k), Some(v)) if k == key && !v.is_empty() => Some(v.to_string()),
            _ => None,
        }
    })
}

/// GET /v1/decisions — list decisions for the authenticated tenant.
///
/// Query params:
///   `limit` (default 50, max 200), `offset` (default 0).
///   `agent_id` — optional equality filter.
///   `decision` — optional equality filter.
pub async fn list_decisions(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let (limit, offset) = parse_pagination(raw_query.as_deref());
    let agent_id = parse_filter(raw_query.as_deref(), "agent_id");
    let decision = parse_filter(raw_query.as_deref(), "decision");

    match db::list_decisions(
        &state.pool,
        &tenant_id,
        limit,
        offset,
        agent_id.as_deref(),
        decision.as_deref(),
    )
    .await
    {
        Ok(decisions) => (StatusCode::OK, Json(decisions)).into_response(),
        Err(e) => {
            error!("Failed to list decisions: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

/// GET /v1/decisions/:id — get a single decision detail for the authenticated tenant.
pub async fn get_decision(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match db::get_decision_by_id(&state.pool, &tenant_id, &id).await {
        Ok(Some(decision)) => (StatusCode::OK, Json(decision)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Decision not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to get decision: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

/// GET /v1/approvals — list pending approvals for the authenticated tenant.
///
/// Query params:
///   `limit` (default 50, max 200), `offset` (default 0).
pub async fn list_approvals(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let (limit, offset) = parse_pagination(raw_query.as_deref());

    match db::list_pending_approvals(&state.pool, &tenant_id, limit, offset).await {
        Ok(approvals) => {
            let mapped: Vec<serde_json::Value> = approvals
                .into_iter()
                .map(|app| {
                    let edited_call: Option<AuthorizeToolCall> = app
                        .edited_skill_call
                        .as_ref()
                        .and_then(|s| serde_json::from_str(s).ok());
                    let effective_status = if app.status == "created" && approval_is_expired(&app) {
                        "EXPIRED".to_string()
                    } else {
                        app.status.clone()
                    };
                    json!({
                        "approval_id": app.id,
                        "status": effective_status,
                        "approver_group": app.approver_group,
                        "approver_user_id": app.approver_user_id,
                        "reason": app.reason,
                        "action_hash": app.original_call_hash,
                        "edited_tool_call": edited_call,
                        "expires_at": app.expires_at,
                        "decided_at": app.decided_at,
                    })
                })
                .collect();
            (StatusCode::OK, Json(mapped)).into_response()
        }
        Err(e) => {
            error!("Failed to list pending approvals: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

/// GET /v1/receipts — list paginated action receipts for the authenticated tenant.
///
/// Query params:
///   `limit` (default 50, max 200), `offset` (default 0).
pub async fn list_receipts(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let (limit, offset) = parse_pagination(raw_query.as_deref());

    match db::list_action_receipts(&state.pool, &tenant_id, limit, offset).await {
        Ok(receipts) => (StatusCode::OK, Json(receipts)).into_response(),
        Err(e) => {
            error!("Failed to list receipts: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

/// GET /v1/receipts/:id — get a single action receipt for the authenticated tenant.
pub async fn get_receipt(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match db::get_action_receipt_by_id(&state.pool, &tenant_id, &id).await {
        Ok(Some(receipt)) => (StatusCode::OK, Json(receipt)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Receipt not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to get receipt: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct VerifyChainRequest {
    pub receipts: Vec<Value>,
}

pub async fn verify_receipt_chain(
    State(_state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(payload): Json<VerifyChainRequest>,
) -> impl IntoResponse {
    let receipts = &payload.receipts;
    if receipts.is_empty() {
        return (
            StatusCode::OK,
            Json(json!({
                "verified": true,
                "error": null
            })),
        )
            .into_response();
    }

    let mut prev = String::new();
    for (i, receipt) in receipts.iter().enumerate() {
        let obj = match receipt.as_object() {
            Some(o) => o,
            None => {
                return (
                    StatusCode::OK,
                    Json(json!({
                        "verified": false,
                        "error": format!("Receipt at index {} is not a valid JSON object", i)
                    })),
                )
                    .into_response();
            }
        };

        // 1. Tenant validation (CWE-284 isolation!)
        if let Some(tenant_in_receipt) = obj.get("tenant_id").and_then(|v| v.as_str()) {
            if tenant_in_receipt != tenant_id {
                return (
                    StatusCode::OK,
                    Json(json!({
                        "verified": false,
                        "error": format!("Tenant mismatch at index {}: receipt has tenant '{}' but request is for '{}'", i, tenant_in_receipt, tenant_id)
                    })),
                )
                    .into_response();
            }
        }

        // 2. Hash validation
        let stored = match obj.get("receipt_hash").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                return (
                    StatusCode::OK,
                    Json(json!({
                        "verified": false,
                        "error": format!("Missing receipt_hash at index {}", i)
                    })),
                )
                    .into_response();
            }
        };

        // Remove receipt_hash, signature, signer_public_key, and created_at to get canonical body
        let mut body = obj.clone();
        body.remove("receipt_hash");
        body.remove("signature");
        body.remove("signer_public_key");
        body.remove("created_at");

        let recomputed = sha256_hex(canonical_value_string(&Value::Object(body)).as_bytes());
        if recomputed != stored {
            return (
                StatusCode::OK,
                Json(json!({
                    "verified": false,
                    "error": format!("Hash mismatch at index {}: stored '{}', recomputed '{}'", i, stored, recomputed)
                })),
            )
                .into_response();
        }

        // 3. Linkage validation
        let prev_in_receipt = obj
            .get("prev_receipt_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if i == 0 {
            prev = prev_in_receipt.to_string();
        }
        if prev_in_receipt != prev {
            return (
                StatusCode::OK,
                Json(json!({
                    "verified": false,
                    "error": format!("Link broken at index {}: prev_receipt_hash '{}' does not match expected '{}'", i, prev_in_receipt, prev)
                })),
            )
                .into_response();
        }

        prev = stored.to_string();
    }

    (
        StatusCode::OK,
        Json(json!({
            "verified": true,
            "error": null
        })),
    )
        .into_response()
}

#[derive(Debug, serde::Deserialize)]
pub struct CreatePolicyRequest {
    pub policy_key: String,
    pub name: String,
    pub body: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdatePolicyRequest {
    pub policy_key: Option<String>,
    pub name: Option<String>,
    pub body: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct IngestRequest {
    /// One of [`crate::ingest::SUPPORTED_SOURCES`].
    pub source: String,
    /// The raw event payload from the external system, in that system's
    /// native shape (e.g. a GitHub webhook body, an OpenAI trace entry).
    pub payload: serde_json::Value,
}

/// `POST /v1/ingest` (SOC-004, #1187) — agentless event ingestion.
///
/// Tenant-scoped (via [`TenantId`]) and authenticated like every other
/// management endpoint. Normalizes `payload` per `source` (see
/// [`crate::ingest`]) and emits the result onto the same
/// [`crate::events::EventSink`] the inline `/v1/authorize` path uses, so it
/// flows through the identical detect -> correlate -> respond pipeline.
/// Never touches the authorize hot path itself (Law 3) — this is its own
/// request/response cycle.
pub async fn ingest_event(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(payload): Json<IngestRequest>,
) -> impl IntoResponse {
    match crate::ingest::normalize(&tenant_id, &payload.source, &payload.payload) {
        Err(()) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "unsupported ingest source '{}'; supported: {:?}",
                    payload.source,
                    crate::ingest::SUPPORTED_SOURCES
                )
            })),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "payload could not be normalized for this source"})),
        )
            .into_response(),
        Ok(Some(event)) => {
            let event_id = event.event_id.clone();
            state.events.emit(event);
            (
                StatusCode::ACCEPTED,
                Json(json!({"status": "accepted", "event_id": event_id})),
            )
                .into_response()
        }
    }
}

pub async fn list_policies(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
) -> impl IntoResponse {
    match db::list_policies(&state.pool, &tenant_id).await {
        Ok(policies) => (StatusCode::OK, Json(policies)).into_response(),
        Err(e) => {
            error!("Failed to list policies: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

pub async fn create_policy(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(payload): Json<CreatePolicyRequest>,
) -> impl IntoResponse {
    // Validate Cedar compilation
    if let Err(e) = cedar_policy::PolicySet::from_str(&payload.body) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("Cedar compilation error: {}", e)})),
        )
            .into_response();
    }

    let policy_id = Uuid::new_v4().to_string();
    let record = PolicyRecord {
        id: policy_id,
        tenant_id: tenant_id.clone(),
        policy_key: payload.policy_key,
        name: payload.name,
        language: "cedar".to_string(),
        body: payload.body,
        version: 1,
        status: "active".to_string(),
        created_by: None,
        created_at: Utc::now(),
    };

    match db::insert_policy(&state.pool, &record).await {
        Ok(_) => {
            // Trigger hot-reload
            if let Err(e) = state
                .policy_engine
                .reload_tenant_policies(&state.pool, &tenant_id)
                .await
            {
                error!("Failed to hot-reload policies after create: {:?}", e);
            }
            (StatusCode::CREATED, Json(record)).into_response()
        }
        Err(e) => {
            error!("Failed to create policy: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

pub async fn update_policy(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
    Json(payload): Json<UpdatePolicyRequest>,
) -> impl IntoResponse {
    let mut record = match db::get_policy_by_id(&state.pool, &tenant_id, &id).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Policy not found"})),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to lookup policy for update: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    if let Some(policy_key) = payload.policy_key {
        record.policy_key = policy_key;
    }
    if let Some(name) = payload.name {
        record.name = name;
    }
    if let Some(body) = payload.body {
        // Validate Cedar compilation
        if let Err(e) = cedar_policy::PolicySet::from_str(&body) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Cedar compilation error: {}", e)})),
            )
                .into_response();
        }
        record.body = body;
    }
    if let Some(status) = payload.status {
        record.status = status;
    }
    record.version += 1;

    match db::update_policy(&state.pool, &record).await {
        Ok(_) => {
            // Trigger hot-reload
            if let Err(e) = state
                .policy_engine
                .reload_tenant_policies(&state.pool, &tenant_id)
                .await
            {
                error!("Failed to hot-reload policies after update: {:?}", e);
            }
            (StatusCode::OK, Json(record)).into_response()
        }
        Err(e) => {
            error!("Failed to update policy: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

pub async fn delete_policy(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match db::delete_policy(&state.pool, &tenant_id, &id).await {
        Ok(true) => {
            // Trigger hot-reload
            if let Err(e) = state
                .policy_engine
                .reload_tenant_policies(&state.pool, &tenant_id)
                .await
            {
                error!("Failed to hot-reload policies after delete: {:?}", e);
            }
            (
                StatusCode::OK,
                Json(json!({"message": "Policy successfully deleted"})),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Policy not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to delete policy: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

pub async fn reload_global_policies(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let policy_path =
        std::env::var("CEDAR_POLICY_PATH").unwrap_or_else(|_| "policies.cedar".into());
    match state.policy_engine.reload_file(&policy_path).await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({"message": "Global policies successfully reloaded"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to reload global policy file: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to reload file: {}", e)})),
            )
                .into_response()
        }
    }
}

/// GET /v1/alerts — list SOC detection alerts for the authenticated tenant.
///
/// Query params:
///   `limit` (default 50, max 200), `offset` (default 0).
///   `severity` — optional equality filter (e.g. `?severity=high`).
///   `agent_id`  — optional equality filter (e.g. `?agent_id=abc`).
/// Returns a JSON array of [`SocAlertRecord`]s ordered newest-first.
/// Every result row is tenant-scoped via parameterized SQL — never leaks
/// another tenant's data.
pub async fn list_alerts(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let (limit, offset) = parse_pagination(raw_query.as_deref());
    let severity = parse_filter(raw_query.as_deref(), "severity");
    let agent_id = parse_filter(raw_query.as_deref(), "agent_id");

    match db::list_soc_alerts(
        &state.pool,
        &tenant_id,
        limit,
        offset,
        severity.as_deref(),
        agent_id.as_deref(),
    )
    .await
    {
        Ok(alerts) => (StatusCode::OK, Json(alerts)).into_response(),
        Err(e) => {
            error!("Failed to list SOC alerts: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

/// GET /v1/incidents — list SOC correlation incidents for the authenticated tenant.
///
/// Query params:
///   `limit` (default 50, max 200), `offset` (default 0).
///   `status`   — optional filter: `"open"` or `"closed"` (omit for all).
///   `severity` — optional equality filter (e.g. `?severity=high`).
///   `agent_id` — optional equality filter (e.g. `?agent_id=abc`).
/// Returns a JSON array of [`SocIncidentRecord`]s ordered newest-first.
/// Every result row is tenant-scoped via parameterized SQL — never leaks
/// another tenant's data.
pub async fn list_incidents(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let (limit, offset) = parse_pagination(raw_query.as_deref());
    let status_filter = parse_filter(raw_query.as_deref(), "status");
    let severity = parse_filter(raw_query.as_deref(), "severity");
    let agent_id = parse_filter(raw_query.as_deref(), "agent_id");

    match db::list_soc_incidents(
        &state.pool,
        &tenant_id,
        limit,
        offset,
        status_filter.as_deref(),
        severity.as_deref(),
        agent_id.as_deref(),
    )
    .await
    {
        Ok(incidents) => (StatusCode::OK, Json(incidents)).into_response(),
        Err(e) => {
            error!("Failed to list SOC incidents: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

// ── SOC query layer: incident detail + aggregate summary ─────────────────────

/// `GET /v1/incidents/:id` — single-incident detail, tenant-scoped.
///
/// Returns the full [`SocIncidentRecord`] for the given `id` when it belongs to
/// the authenticated tenant, or HTTP 404 when the `id` is unknown **or** belongs
/// to a different tenant (CWE-284: no information leakage across tenants).
/// Both DB binds (`tenant_id`, `incident_id`) are parameterized — no SQL
/// concatenation (CWE-89).
pub async fn get_incident(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(incident_id): Path<String>,
) -> impl IntoResponse {
    match db::get_soc_incident(&state.pool, &tenant_id, &incident_id).await {
        Ok(Some(incident)) => (StatusCode::OK, Json(incident)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Incident not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to fetch SOC incident {}: {:?}", incident_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

/// `GET /v1/soc/summary` — tenant-scoped SOC aggregate counts.
///
/// Returns `{ alerts_total, alerts_high, incidents_total, incidents_open,
/// incidents_closed }` derived from five parameterized COUNT queries, all
/// binding `tenant_id` (CWE-284).  `alerts_high` counts alerts with
/// `severity = 'high'`; open/closed split on the incident `status` column.
/// No SQL concatenation occurs (CWE-89).
pub async fn soc_summary(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
) -> impl IntoResponse {
    match db::soc_summary(&state.pool, &tenant_id).await {
        Ok(summary) => (StatusCode::OK, Json(summary)).into_response(),
        Err(e) => {
            error!("Failed to compute SOC summary: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

// ── SOC Phase 6: Incident lifecycle ──────────────────────────────────────────

/// `POST /v1/incidents/:id/close` — close an open SOC incident.
///
/// Transitions the incident from `"open"` to `"closed"`, stamps `closed_at`,
/// and writes an `"incident_closed"` audit event. Tenant-scoped: 404 if the
/// incident does not exist for this tenant. Idempotent on a second call: a
/// 200 response is returned with `"already_closed": true` so callers can
/// distinguish the first close from a repeat without erroring.
///
/// # Security invariants
/// * Two parameterized binds on every DB call (`tenant_id` + `id`).
/// * No payload fields in the audit event — only the incident id and new status.
/// * `close_soc_incident` uses `AND status != 'closed'` to make the UPDATE
///   idempotent at the DB level; concurrent closes are safe.
pub async fn close_incident(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(incident_id): Path<String>,
) -> impl IntoResponse {
    // First verify the incident exists for this tenant (provides a meaningful 404
    // rather than a silent no-op when the id is simply wrong or belongs to another
    // tenant — CWE-284 isolation).
    let incident = match db::get_soc_incident(&state.pool, &tenant_id, &incident_id).await {
        Ok(Some(inc)) => inc,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Incident not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to fetch incident for close: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    // If already closed, return a clear idempotent response (200 with a flag).
    if incident.status == "closed" {
        return (
            StatusCode::OK,
            Json(json!({
                "incident_id": incident.id,
                "status": "closed",
                "closed_at": incident.closed_at,
                "already_closed": true,
            })),
        )
            .into_response();
    }

    // Atomically flip status → 'closed' and stamp closed_at.
    let did_close = match db::close_soc_incident(&state.pool, &tenant_id, &incident_id).await {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to close incident {}: {:?}", incident_id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    if !did_close {
        // Race: incident was closed between the get and the update. Treat as
        // idempotent — re-fetch to return the correct closed_at.
        return match db::get_soc_incident(&state.pool, &tenant_id, &incident_id).await {
            Ok(Some(inc)) => (
                StatusCode::OK,
                Json(json!({
                    "incident_id": inc.id,
                    "status": "closed",
                    "closed_at": inc.closed_at,
                    "already_closed": true,
                })),
            )
                .into_response(),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response(),
        };
    }

    // Re-fetch to pick up the DB-stamped `closed_at` timestamp.
    let closed_at = match db::get_soc_incident(&state.pool, &tenant_id, &incident_id).await {
        Ok(Some(inc)) => inc.closed_at,
        Ok(None) => None,
        Err(e) => {
            error!("Failed to re-fetch incident after close: {:?}", e);
            None
        }
    };

    // Write audit event (hashes / ids only — no payloads, no raw evidence).
    let audit = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.clone(),
        event_type: "incident_closed".to_string(),
        agent_id: None,
        user_id: None,
        run_id: None,
        trace_id: None,
        span_id: None,
        skill: None,
        action: None,
        resource: Some(incident_id.clone()),
        event_json: serde_json::to_string(&json!({
            "incident_id": incident_id,
            "new_status": "closed",
        }))
        .unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        created_at: Utc::now(),
    };
    let _ = db::insert_audit_event(&state.pool, &audit).await;

    info!(incident_id = %incident_id, "SOC incident closed");

    (
        StatusCode::OK,
        Json(json!({
            "incident_id": incident_id,
            "status": "closed",
            "closed_at": closed_at,
            "already_closed": false,
        })),
    )
        .into_response()
}

// ── SOC Phase 6: RCA Narrator ────────────────────────────────────────────────

/// GET /v1/incidents/:id/narrate — on-demand RCA narrative for a closed incident.
///
/// # LAW-2 compliance
/// * On-demand only — never called from the authorize / drain hot paths.
/// * Tenant-scoped db fetch (two parameterized binds: tenant_id + id).
/// * 404 if the incident does not exist **or** belongs to a different tenant.
/// * The [`crate::narrate`] module builds the narrative from structured,
///   already-redacted fields only — never raw evidence or live telemetry.
/// * The narrator is constructed inside the handler (no AppState mutation).
pub async fn narrate_incident(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(incident_id): Path<String>,
) -> impl IntoResponse {
    let incident = match db::get_soc_incident(&state.pool, &tenant_id, &incident_id).await {
        Ok(Some(inc)) => inc,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Incident not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to fetch incident for narration: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    // Construct narrator from env — hermetic template by default, optional Claude.
    // Never touches AppState; no network call in the default path.
    let narrator = crate::narrate::from_env();
    let narrative = narrator.narrate(&incident);

    info!(incident_id = %incident_id, "RCA narrative generated");

    (
        StatusCode::OK,
        Json(json!({
            "incident_id": incident.id,
            "narrative": narrative,
        })),
    )
        .into_response()
}

// ── SOC Phase 4: Response API ─────────────────────────────────────────────────

/// Optional request body for `POST /v1/agents/:id/freeze` (#0079) — an
/// operator-supplied reason recorded on `agents.frozen_reason` and surfaced in
/// the audit trail / SOC UI. Omit the body (or `reason`) to freeze without one.
#[derive(Debug, serde::Deserialize, Default)]
pub struct FreezeAgentRequest {
    pub reason: Option<String>,
}

/// Freeze an agent: all subsequent /v1/authorize calls for this agent will be
/// denied immediately without Cedar evaluation. Reversible via /unfreeze.
pub async fn freeze_agent(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(agent_id): Path<String>,
    body: Option<Json<FreezeAgentRequest>>,
) -> impl IntoResponse {
    let reason = body.and_then(|Json(b)| b.reason);
    let resp =
        set_agent_operational_status(state.clone(), tenant_id.clone(), agent_id.clone(), "frozen")
            .await;
    if resp.status() == StatusCode::OK {
        let _ = db::set_agent_frozen_reason(&state.pool, &tenant_id, &agent_id, reason.as_deref())
            .await;
    }
    resp
}

/// Restore a frozen agent to active status.
pub async fn unfreeze_agent(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    set_agent_operational_status(state, tenant_id, agent_id, "active").await
}

/// Permanently revoke an agent — not reversible via API.
pub async fn revoke_agent(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    set_agent_operational_status(state, tenant_id, agent_id, "revoked").await
}

async fn set_agent_operational_status(
    state: Arc<AppState>,
    tenant_id: String,
    agent_id: String,
    status: &str,
) -> axum::response::Response {
    match db::set_agent_status(&state.pool, &tenant_id, &agent_id, status).await {
        Ok(true) => {
            let audit = AuditEventRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.clone(),
                event_type: format!("agent_{}", status),
                agent_id: Some(agent_id.clone()),
                user_id: None,
                run_id: None,
                trace_id: None,
                span_id: None,
                skill: None,
                action: None,
                resource: None,
                event_json: serde_json::to_string(&json!({
                    "agent_id": agent_id,
                    "new_status": status,
                }))
                .unwrap_or_default(),
                input_hash: None,
                output_hash: None,
                created_at: Utc::now(),
            };
            let _ = db::insert_audit_event(&state.pool, &audit).await;
            info!(agent_id = %agent_id, status = %status, "Agent status changed");
            (
                StatusCode::OK,
                Json(json!({ "agent_id": agent_id, "status": status })),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Agent not found" })),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to update agent status: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Database error" })),
            )
                .into_response()
        }
    }
}

/// Quarantine an MCP server — the gateway will deny all tool calls from this
/// server until it is restored. Tenant-scoped, parameterized, fail-closed.
pub async fn quarantine_mcp_server(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(server_key): Path<String>,
) -> impl IntoResponse {
    update_mcp_server_quarantine(state, tenant_id, server_key, "quarantined").await
}

/// Restore a quarantined MCP server to active status.
pub async fn restore_mcp_server(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(server_key): Path<String>,
) -> impl IntoResponse {
    update_mcp_server_quarantine(state, tenant_id, server_key, "active").await
}

async fn update_mcp_server_quarantine(
    state: Arc<AppState>,
    tenant_id: String,
    server_key: String,
    status: &str,
) -> axum::response::Response {
    match db::set_mcp_server_status(&state.pool, &tenant_id, &server_key, status).await {
        Ok(true) => {
            let audit = AuditEventRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.clone(),
                event_type: format!("mcp_server_{}", status),
                agent_id: None,
                user_id: None,
                run_id: None,
                trace_id: None,
                span_id: None,
                skill: Some(format!("mcp:{}", server_key)),
                action: None,
                resource: Some(server_key.clone()),
                event_json: serde_json::to_string(&json!({
                    "server_key": server_key,
                    "new_status": status,
                }))
                .unwrap_or_default(),
                input_hash: None,
                output_hash: None,
                created_at: Utc::now(),
            };
            let _ = db::insert_audit_event(&state.pool, &audit).await;
            info!(server_key = %server_key, status = %status, "MCP server status changed");
            (
                StatusCode::OK,
                Json(json!({ "server_key": server_key, "status": status })),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "MCP server not found" })),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to update MCP server status: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Database error" })),
            )
                .into_response()
        }
    }
}

pub async fn get_tenant(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if tenant_id != id {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Tenant not found"})),
        )
            .into_response();
    }

    match db::get_tenant_by_id(&state.pool, &tenant_id).await {
        Ok(Some(tenant)) => (StatusCode::OK, Json(tenant)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Tenant not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to get tenant: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

/// GET /v1/tenants/:id/export — GDPR data-portability (#946). Returns the full
/// tenant-scoped data bundle (agents, decisions, approvals, receipts, audit
/// events, MCP servers) as JSON. A caller may export ONLY its own tenant: a path
/// id that doesn't match the authenticated tenant returns 404 (same convention as
/// `get_tenant`, so tenant existence isn't leaked).
pub async fn export_tenant(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if tenant_id != id {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Tenant not found"})),
        )
            .into_response();
    }

    match db::export_tenant_data(&state.pool, &tenant_id).await {
        Ok(export) => (StatusCode::OK, Json(export)).into_response(),
        Err(e) => {
            error!("Failed to export tenant data: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

/// DELETE /v1/tenants/:id (#947, GDPR right to erasure): permanently delete
/// every row owned by the tenant, including the tenant itself. Irreversible —
/// callers should fetch `GET /v1/tenants/:id/export` first if a portability
/// copy is needed.
pub async fn delete_tenant(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if tenant_id != id {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Tenant not found"})),
        )
            .into_response();
    }

    match db::delete_tenant_data(&state.pool, &tenant_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            error!("Failed to delete tenant data: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

pub async fn create_tenant(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateTenantRequest>,
) -> impl IntoResponse {
    match db::get_tenant_by_id(&state.pool, &payload.id).await {
        Ok(Some(_)) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "Tenant already exists"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("Database error checking tenant existence: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
        _ => {}
    }

    match db::register_tenant(&state.pool, &payload.id, &payload.name, &payload.plan).await {
        Ok(()) => {
            let record = TenantRecord {
                id: payload.id.clone(),
                name: payload.name.clone(),
                plan: payload.plan.clone(),
                created_at: Utc::now(),
                auto_respond_enabled: true,
            };
            (StatusCode::CREATED, Json(record)).into_response()
        }
        Err(e) => {
            error!("Failed to register tenant: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

pub async fn list_mcp_servers(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let (limit, offset) = parse_pagination(raw_query.as_deref());

    match db::list_mcp_servers(&state.pool, &tenant_id, limit, offset).await {
        Ok(servers) => (StatusCode::OK, Json(servers)).into_response(),
        Err(e) => {
            error!("Failed to list MCP servers: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

pub async fn get_mcp_server(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(server_key): Path<String>,
) -> impl IntoResponse {
    match db::get_mcp_server_by_key(&state.pool, &tenant_id, &server_key).await {
        Ok(Some(server)) => (StatusCode::OK, Json(server)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "MCP server not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to get MCP server: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

pub async fn update_mcp_server(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(server_key): Path<String>,
    Json(payload): Json<UpdateMcpServerRequest>,
) -> impl IntoResponse {
    match db::get_mcp_server_by_key(&state.pool, &tenant_id, &server_key).await {
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "MCP server not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("Database error getting MCP server: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
        _ => {}
    }

    match db::update_mcp_server(
        &state.pool,
        &tenant_id,
        &server_key,
        payload.name.as_deref(),
        payload.owner_team.as_ref().map(|o| o.as_deref()),
        payload.transport.as_deref(),
        payload.source.as_ref().map(|o| o.as_deref()),
        payload.trust_level.as_deref(),
        payload.endpoint.as_deref(),
        payload.status.as_deref(),
    )
    .await
    {
        Ok(true) => match db::get_mcp_server_by_key(&state.pool, &tenant_id, &server_key).await {
            Ok(Some(server)) => (StatusCode::OK, Json(server)).into_response(),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to fetch updated server"})),
            )
                .into_response(),
        },
        Ok(false) => match db::get_mcp_server_by_key(&state.pool, &tenant_id, &server_key).await {
            Ok(Some(server)) => (StatusCode::OK, Json(server)).into_response(),
            _ => (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "MCP server not found"})),
            )
                .into_response(),
        },
        Err(e) => {
            error!("Failed to update MCP server: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

pub async fn ws_events(
    State(state): State<Arc<AppState>>,
    ws: WebSocketUpgrade,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant_id = if let Some(token) = params.get("token").or_else(|| params.get("jwt")) {
        if let Some(tid) = validate_jwt(token) {
            tid
        } else if std::env::var("AEGIS_JWT_REQUIRED")
            .map(|v| v == "true")
            .unwrap_or(false)
        {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid or expired JWT token"})),
            )
                .into_response();
        } else {
            if token.starts_with("tenant_") {
                token.to_string()
            } else {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "Invalid token. Query token must start with 'tenant_' when JWT is not required"})),
                )
                    .into_response();
            }
        }
    } else {
        let auth_header = headers.get("Authorization").and_then(|h| h.to_str().ok());
        if let Some(auth) = auth_header {
            if let Some(token) = auth.strip_prefix("Bearer ") {
                if let Some(tid) = validate_jwt(token) {
                    tid
                } else if std::env::var("AEGIS_JWT_REQUIRED")
                    .map(|v| v == "true")
                    .unwrap_or(false)
                {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({"error": "Invalid or expired JWT token"})),
                    )
                        .into_response();
                } else {
                    if token.starts_with("tenant_") {
                        token.to_string()
                    } else {
                        return (
                            StatusCode::UNAUTHORIZED,
                            Json(json!({"error": "Invalid token. Bearer token must start with 'tenant_' when JWT is not required"})),
                        )
                            .into_response();
                    }
                }
            } else {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "Invalid Authorization format"})),
                )
                    .into_response();
            }
        } else {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing authentication. A valid token or JWT must be provided."})),
            )
                .into_response();
        }
    };

    ws.on_upgrade(move |socket| handle_socket(socket, state, tenant_id))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>, tenant_id: String) {
    let mut rx = state.events.subscribe();

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(ev) => {
                        if ev.tenant_id == tenant_id {
                            if let Ok(msg) = serde_json::to_string(&ev) {
                                if socket.send(Message::Text(msg)).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => {
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}

pub async fn get_tenant_stats(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
) -> impl IntoResponse {
    match db::get_tenant_stats(&state.pool, &tenant_id).await {
        Ok(stats) => (StatusCode::OK, Json(stats)).into_response(),
        Err(e) => {
            error!("Failed to get tenant stats: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

/// GET /v1/admin/db-stats (#949, #950): operational, whole-database
/// monitoring snapshot — on-disk size and per-table row counts. Not
/// tenant-scoped (reflects the single SQLite file shared by all tenants);
/// intended for ops dashboards on the local-only gateway listener.
pub async fn get_db_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match db::get_db_stats(&state.pool).await {
        Ok(stats) => (StatusCode::OK, Json(stats)).into_response(),
        Err(e) => {
            error!("Failed to get db stats: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

/// POST /v1/admin/backup (#945): write a consistent point-in-time copy of the
/// database via `VACUUM INTO`. The destination filename is restricted to a
/// bare filename (no path separators or `..`) under `AEGIS_BACKUP_DIR`
/// (default `backups`), which is created if missing, to prevent path
/// traversal to arbitrary filesystem locations.
pub async fn create_db_backup(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateBackupRequest>,
) -> impl IntoResponse {
    let filename = std::path::Path::new(&payload.filename);
    if payload.filename.is_empty()
        || filename.file_name().map(|f| f.to_owned()) != Some(filename.as_os_str().to_owned())
        || payload.filename.contains("..")
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "filename must be a bare filename with no path separators"})),
        )
            .into_response();
    }

    let backup_dir = std::env::var("AEGIS_BACKUP_DIR").unwrap_or_else(|_| "backups".to_string());
    if let Err(e) = std::fs::create_dir_all(&backup_dir) {
        error!("Failed to create backup directory: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create backup directory"})),
        )
            .into_response();
    }

    let dest_path = std::path::Path::new(&backup_dir).join(&payload.filename);
    let dest_path_str = dest_path.to_string_lossy().to_string();

    // VACUUM INTO refuses to write to an already-existing file.
    if dest_path.exists() {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "Backup file already exists"})),
        )
            .into_response();
    }

    match db::backup_database_to(&state.pool, &dest_path_str).await {
        Ok(()) => {
            let size_bytes = std::fs::metadata(&dest_path)
                .map(|m| m.len() as i64)
                .unwrap_or(0);
            (
                StatusCode::OK,
                Json(CreateBackupResponse {
                    path: dest_path_str,
                    size_bytes,
                }),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to create db backup: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

pub async fn get_openapi_spec() -> impl IntoResponse {
    let spec = json!({
        "openapi": "3.1.0",
        "info": {
            "title": "AegisAgent Control Plane API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "API specification for AegisAgent Gateway - fail-closed approval integrity, deterministic trust-provenance gating, and verifiable action receipts."
        },
        "paths": {
            "/health": {
                "get": {
                    "summary": "Health status",
                    "responses": {
                        "200": { "description": "System is healthy" }
                    }
                }
            },
            "/v1/version": {
                "get": {
                    "summary": "Version information",
                    "responses": {
                        "200": { "description": "Version details" }
                    }
                }
            },
            "/v1/agents/register": {
                "post": {
                    "summary": "Register a new agent",
                    "responses": {
                        "201": { "description": "Agent registered successfully" }
                    }
                }
            },
            "/v1/agents": {
                "get": {
                    "summary": "List agents",
                    "responses": {
                        "200": { "description": "List of agents" }
                    }
                }
            },
            "/v1/agents/{id}": {
                "get": {
                    "summary": "Get agent details",
                    "responses": {
                        "200": { "description": "Agent details" }
                    }
                },
                "patch": {
                    "summary": "Update agent metadata",
                    "responses": {
                        "200": { "description": "Agent updated" }
                    }
                },
                "delete": {
                    "summary": "Delete an agent",
                    "responses": {
                        "200": { "description": "Agent deleted" }
                    }
                }
            },
            "/v1/agents/{id}/freeze": {
                "post": {
                    "summary": "Freeze an agent",
                    "responses": {
                        "200": { "description": "Agent frozen" }
                    }
                }
            },
            "/v1/agents/{id}/unfreeze": {
                "post": {
                    "summary": "Unfreeze an agent",
                    "responses": {
                        "200": { "description": "Agent unfrozen" }
                    }
                }
            },
            "/v1/agents/{id}/revoke": {
                "post": {
                    "summary": "Revoke an agent",
                    "responses": {
                        "200": { "description": "Agent revoked" }
                    }
                }
            },
            "/v1/tools": {
                "post": {
                    "summary": "Register a tool",
                    "responses": {
                        "200": { "description": "Tool registered" }
                    }
                }
            },
            "/v1/mcp/servers": {
                "get": {
                    "summary": "List MCP servers",
                    "responses": {
                        "200": { "description": "List of MCP servers" }
                    }
                },
                "post": {
                    "summary": "Register an MCP server",
                    "responses": {
                        "201": { "description": "MCP server registered" }
                    }
                }
            },
            "/v1/mcp/servers/{server_key}": {
                "get": {
                    "summary": "Get MCP server details",
                    "responses": {
                        "200": { "description": "MCP server details" }
                    }
                },
                "put": {
                    "summary": "Update MCP server metadata",
                    "responses": {
                        "200": { "description": "MCP server updated" }
                    }
                }
            },
            "/v1/mcp/servers/{server_key}/tools": {
                "get": {
                    "summary": "Get MCP tool manifest",
                    "responses": {
                        "200": { "description": "Tool manifest" }
                    }
                },
                "post": {
                    "summary": "Discover MCP tools",
                    "responses": {
                        "200": { "description": "Tools discovered" }
                    }
                }
            },
            "/v1/mcp/servers/{server_key}/tools/{tool_key}/approve": {
                "post": {
                    "summary": "Approve an MCP tool",
                    "responses": {
                        "200": { "description": "Tool approved" }
                    }
                }
            },
            "/v1/mcp/servers/{server_key}/tools/{tool_key}/disable": {
                "post": {
                    "summary": "Disable an MCP tool",
                    "responses": {
                        "200": { "description": "Tool disabled" }
                    }
                }
            },
            "/v1/mcp/servers/{server_key}/quarantine": {
                "post": {
                    "summary": "Quarantine MCP server",
                    "responses": {
                        "200": { "description": "Server quarantined" }
                    }
                }
            },
            "/v1/mcp/servers/{server_key}/restore": {
                "post": {
                    "summary": "Restore MCP server",
                    "responses": {
                        "200": { "description": "Server restored" }
                    }
                }
            },
            "/v1/authorize": {
                "post": {
                    "summary": "Authorize tool action",
                    "responses": {
                        "200": { "description": "Authorization decision" }
                    }
                }
            },
            "/v1/decisions": {
                "get": {
                    "summary": "List decisions",
                    "responses": {
                        "200": { "description": "List of decisions" }
                    }
                }
            },
            "/v1/decisions/{id}": {
                "get": {
                    "summary": "Get decision details",
                    "responses": {
                        "200": { "description": "Decision details" }
                    }
                }
            },
            "/v1/policies": {
                "get": {
                    "summary": "List custom policies",
                    "responses": {
                        "200": { "description": "List of custom policies" }
                    }
                },
                "post": {
                    "summary": "Create custom Cedar policy",
                    "responses": {
                        "201": { "description": "Policy created" }
                    }
                }
            },
            "/v1/policies/{id}": {
                "put": {
                    "summary": "Update Cedar policy",
                    "responses": {
                        "200": { "description": "Policy updated" }
                    }
                },
                "delete": {
                    "summary": "Delete custom policy",
                    "responses": {
                        "200": { "description": "Policy deleted" }
                    }
                }
            },
            "/v1/policies/reload": {
                "post": {
                    "summary": "Reload global policies",
                    "responses": {
                        "200": { "description": "Policies reloaded" }
                    }
                }
            },
            "/v1/approvals": {
                "get": {
                    "summary": "List approvals",
                    "responses": {
                        "200": { "description": "List of approvals" }
                    }
                }
            },
            "/v1/approvals/{id}": {
                "get": {
                    "summary": "Get approval details",
                    "responses": {
                        "200": { "description": "Approval details" }
                    }
                }
            },
            "/v1/approvals/{id}/approve": {
                "post": {
                    "summary": "Approve approval request",
                    "responses": {
                        "200": { "description": "Approved successfully" }
                    }
                }
            },
            "/v1/approvals/{id}/reject": {
                "post": {
                    "summary": "Reject approval request",
                    "responses": {
                        "200": { "description": "Rejected successfully" }
                    }
                }
            },
            "/v1/approvals/{id}/edit": {
                "post": {
                    "summary": "Edit parameters bound to approval",
                    "responses": {
                        "200": { "description": "Approval edited" }
                    }
                }
            },
            "/v1/approvals/{id}/consume": {
                "post": {
                    "summary": "Consume single-use approval",
                    "responses": {
                        "200": { "description": "Approval consumed" }
                    }
                }
            },
            "/v1/runs/{id}/timeline": {
                "get": {
                    "summary": "Get timeline events",
                    "responses": {
                        "200": { "description": "List of timeline events" }
                    }
                }
            },
            "/v1/audit/events": {
                "get": {
                    "summary": "Get audit events log",
                    "responses": {
                        "200": { "description": "List of audit events" }
                    }
                }
            },
            "/v1/receipts": {
                "get": {
                    "summary": "List action receipts",
                    "responses": {
                        "200": { "description": "List of receipts" }
                    }
                }
            },
            "/v1/receipts/{id}": {
                "get": {
                    "summary": "Get receipt details",
                    "responses": {
                        "200": { "description": "Receipt details" }
                    }
                }
            },
            "/v1/receipts/{id}/verify": {
                "get": {
                    "summary": "Verify single receipt hash integrity",
                    "responses": {
                        "200": { "description": "Verification status" }
                    }
                }
            },
            "/v1/receipts/verify-chain": {
                "post": {
                    "summary": "Verify sequential receipt chain linkage",
                    "responses": {
                        "200": { "description": "Chain verification result" }
                    }
                }
            },
            "/v1/alerts": {
                "get": {
                    "summary": "List SOC alerts",
                    "responses": {
                        "200": { "description": "List of SOC alerts" }
                    }
                }
            },
            "/v1/incidents": {
                "get": {
                    "summary": "List SOC incidents",
                    "responses": {
                        "200": { "description": "List of SOC incidents" }
                    }
                }
            },
            "/v1/incidents/{id}": {
                "get": {
                    "summary": "Get SOC incident details",
                    "responses": {
                        "200": { "description": "Incident details" }
                    }
                }
            },
            "/v1/incidents/{id}/close": {
                "post": {
                    "summary": "Close SOC incident",
                    "responses": {
                        "200": { "description": "Incident closed" }
                    }
                }
            },
            "/v1/incidents/{id}/narrate": {
                "get": {
                    "summary": "Narrate closed SOC incident RCA",
                    "responses": {
                        "200": { "description": "RCANarrator output" }
                    }
                }
            },
            "/v1/soc/summary": {
                "get": {
                    "summary": "Get aggregated SOC counts summary",
                    "responses": {
                        "200": { "description": "Aggregate SOC summary" }
                    }
                }
            },
            "/v1/tenants": {
                "post": {
                    "summary": "Create new tenant",
                    "responses": {
                        "201": { "description": "Tenant created" }
                    }
                }
            },
            "/v1/tenants/{id}": {
                "get": {
                    "summary": "Get tenant info details",
                    "responses": {
                        "200": { "description": "Tenant info details" }
                    }
                },
                "delete": {
                    "summary": "Permanently delete a tenant and all owned data (GDPR right to erasure)",
                    "responses": {
                        "204": { "description": "Tenant and all owned data deleted" },
                        "404": { "description": "Tenant not found" }
                    }
                }
            },
            "/v1/ws/events": {
                "get": {
                    "summary": "WebSocket live events stream",
                    "responses": {
                        "101": { "description": "Protocol upgraded to WebSocket" }
                    }
                }
            },
            "/v1/stats": {
                "get": {
                    "summary": "Get tenant statistics summary",
                    "responses": {
                        "200": { "description": "Tenant stats" }
                    }
                }
            },
            "/v1/admin/db-stats": {
                "get": {
                    "summary": "Get whole-database operational stats (size, per-table row counts)",
                    "responses": {
                        "200": { "description": "DB stats" }
                    }
                }
            },
            "/v1/admin/backup": {
                "post": {
                    "summary": "Create a point-in-time database backup copy",
                    "responses": {
                        "200": { "description": "Backup created" },
                        "400": { "description": "Invalid filename" },
                        "409": { "description": "Backup file already exists" }
                    }
                }
            }
        }
    });

    (StatusCode::OK, Json(spec))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events;
    use axum::body::to_bytes;
    use axum::extract::FromRequestParts;
    use tokio::sync::mpsc;

    static ENV_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

    fn get_env_lock() -> &'static tokio::sync::Mutex<()> {
        ENV_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    #[tokio::test]
    async fn test_jwt_tenant_extraction() {
        let _guard = get_env_lock().lock().await;
        use jsonwebtoken::{encode, EncodingKey, Header};

        let secret = "test_jwt_secret_1234567890";
        std::env::set_var("AEGIS_JWT_SECRET", secret);
        std::env::set_var("AEGIS_JWT_REQUIRED", "true");

        let claims = Claims {
            sub: "tenant_from_sub".to_string(),
            tenant_id: Some("tenant_from_claim".to_string()),
            exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        // Test validate_jwt helper directly
        let extracted = validate_jwt(&token);
        assert_eq!(extracted, Some("tenant_from_claim".to_string()));

        // Test validate_jwt with sub fallback
        let claims_sub_only = Claims {
            sub: "tenant_from_sub_fallback".to_string(),
            tenant_id: None,
            exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
        };
        let token_sub = encode(
            &Header::default(),
            &claims_sub_only,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();
        let extracted_sub = validate_jwt(&token_sub);
        assert_eq!(extracted_sub, Some("tenant_from_sub_fallback".to_string()));

        // Test validate_jwt with wrong secret
        let wrong_token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("wrong_secret".as_bytes()),
        )
        .unwrap();
        assert_eq!(validate_jwt(&wrong_token), None);

        let (state, _, _) = setup_state("jwt_tenant_extraction").await;
        db::register_tenant(&state.pool, "tenant_from_claim", "JWT Tenant", "developer")
            .await
            .unwrap();

        // Test extractor
        let request = axum::http::Request::builder()
            .header("Authorization", format!("Bearer {}", token))
            .body(())
            .unwrap();

        let (mut parts, _) = request.into_parts();
        let tenant = TenantId::from_request_parts(&mut parts, &state)
            .await
            .unwrap();
        assert_eq!(tenant.0, "tenant_from_claim");

        // Test extractor with invalid token when JWT is required
        let request_invalid = axum::http::Request::builder()
            .header("Authorization", "Bearer invalid_token")
            .body(())
            .unwrap();
        let (mut parts_invalid, _) = request_invalid.into_parts();
        let res = TenantId::from_request_parts(&mut parts_invalid, &state).await;
        assert!(res.is_err());
        let (status, _) = res.unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Clean up env vars
        std::env::remove_var("AEGIS_JWT_SECRET");
        std::env::remove_var("AEGIS_JWT_REQUIRED");
    }

    #[tokio::test]
    async fn test_hardened_tenant_and_jwt_rules() {
        let _guard = get_env_lock().lock().await;
        let (state, _, _) = setup_state("hardened_tenant").await;
        db::register_tenant(
            &state.pool,
            "tenant_custom_id",
            "Custom Tenant",
            "developer",
        )
        .await
        .unwrap();

        // 1. Ensure validate_jwt returns None when AEGIS_JWT_SECRET is unset
        std::env::remove_var("AEGIS_JWT_SECRET");
        assert_eq!(validate_jwt("any_token"), None);

        // 2. Ensure validate_jwt returns None when AEGIS_JWT_SECRET is "default_secret"
        std::env::set_var("AEGIS_JWT_SECRET", "default_secret");
        assert_eq!(validate_jwt("any_token"), None);

        // 3. Ensure TenantId extractor rejects token not starting with "tenant_" when JWT not required
        std::env::remove_var("AEGIS_JWT_SECRET"); // make sure validate_jwt fails
        std::env::remove_var("AEGIS_JWT_REQUIRED");
        let request_bad_heuristic = axum::http::Request::builder()
            .header("Authorization", "Bearer not_starting_with_tenant")
            .body(())
            .unwrap();
        let (mut parts_bad, _) = request_bad_heuristic.into_parts();
        let res_bad = TenantId::from_request_parts(&mut parts_bad, &state).await;
        assert!(res_bad.is_err());
        let (status, body) = res_bad.unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            body["error"],
            "Invalid token. Bearer token must start with 'tenant_' when JWT is not required"
        );

        // 4. Ensure TenantId extractor allows token starting with "tenant_" when JWT not required
        let request_good_heuristic = axum::http::Request::builder()
            .header("Authorization", "Bearer tenant_custom_id")
            .body(())
            .unwrap();
        let (mut parts_good, _) = request_good_heuristic.into_parts();
        let res_good = TenantId::from_request_parts(&mut parts_good, &state).await;
        assert!(res_good.is_ok());
        assert_eq!(res_good.unwrap().0, "tenant_custom_id");
    }

    #[tokio::test]
    async fn test_authorize_action_requires_tenant_header() {
        let (state, _tenant_id, agent_token) = setup_state("missing_header_test").await;
        let request = mcp_authorize_request("filesystem", "read_file");

        // Build headers with ONLY Authorization and NO X-Aegis-Tenant-ID / X-Tenant-ID
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", agent_token).parse().unwrap(),
        );

        let response = authorize_action(State(state), headers, Json(request))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            json["error"],
            "Missing X-Aegis-Tenant-ID or X-Tenant-ID header"
        );
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(2.0, 10.0);
        assert!(limiter.check_rate_limit("t1"));
        assert!(limiter.check_rate_limit("t1"));
        assert!(!limiter.check_rate_limit("t1")); // bucket exhausted

        // Different tenant has its own bucket
        assert!(limiter.check_rate_limit("t2"));

        // Refill check
        tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
        assert!(limiter.check_rate_limit("t1")); // refilled at least 1 token
    }

    #[tokio::test]
    async fn test_quota_manager() {
        let quota = QuotaManager::new(2, 1); // limit 2 requests per 1 second
        assert!(quota.check_quota("t1"));
        assert!(quota.check_quota("t1"));
        assert!(!quota.check_quota("t1")); // quota exceeded

        // Different tenant has its own quota
        assert!(quota.check_quota("t2"));

        // Reset check after window passes
        tokio::time::sleep(tokio::time::Duration::from_millis(1100)).await;
        assert!(quota.check_quota("t1")); // window reset
    }

    #[tokio::test]
    async fn test_authorize_action_rate_limiting_and_quota() {
        let (state_raw, tenant_id, agent_token, events_rx) =
            setup_state_with_events("limit_test").await;
        // Drain events in background
        tokio::spawn(events::drain(events_rx, state_raw.pool.clone()));

        // Create a custom app state with rate limit capacity = 1
        let policy_engine1 = PolicyEngine::init("policies.cedar").await.unwrap();
        let state = Arc::new(AppState {
            pool: state_raw.pool.clone(),
            policy_engine: policy_engine1,
            events: state_raw.events.clone(),
            metrics: crate::metrics::SecurityMetrics::new(),
            approval_ttl_secs: 1800,
            rate_limiter: RateLimiter::new(1.0, 1.0),
            quota_manager: QuotaManager::new(0, 86400), // quota disabled
            skill_cache: SkillActionCache::new(1024),
            startup_complete: std::sync::atomic::AtomicBool::new(true),
        });

        let request = mcp_authorize_request("mcp:server:tool", "read");
        let headers = agent_headers(&agent_token, &tenant_id);

        // First request is allowed through rate limiter
        let resp1 = authorize_action(State(state.clone()), headers.clone(), Json(request.clone()))
            .await
            .into_response();
        // Since we don't have "mcp:server:tool" registered/approved in the database for this test setup,
        // it will be denied (403 or similar) or return require_approval/etc., but NOT 429!
        assert_ne!(resp1.status(), StatusCode::TOO_MANY_REQUESTS);

        // Immediate second request is blocked by rate limiter (429)
        let resp2 = authorize_action(State(state.clone()), headers.clone(), Json(request.clone()))
            .await
            .into_response();
        assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);

        // Now test quota
        let policy_engine2 = PolicyEngine::init("policies.cedar").await.unwrap();
        let state_quota = Arc::new(AppState {
            pool: state_raw.pool.clone(),
            policy_engine: policy_engine2,
            events: state_raw.events.clone(),
            metrics: crate::metrics::SecurityMetrics::new(),
            approval_ttl_secs: 1800,
            rate_limiter: RateLimiter::new(100.0, 100.0), // high rate limit
            quota_manager: QuotaManager::new(1, 86400),   // quota limit 1
            skill_cache: SkillActionCache::new(1024),
            startup_complete: std::sync::atomic::AtomicBool::new(true),
        });

        // First request is allowed through quota
        let resp3 = authorize_action(
            State(state_quota.clone()),
            headers.clone(),
            Json(request.clone()),
        )
        .await
        .into_response();
        assert_ne!(resp3.status(), StatusCode::TOO_MANY_REQUESTS);

        // Second request is blocked by quota (429)
        let resp4 = authorize_action(
            State(state_quota.clone()),
            headers.clone(),
            Json(request.clone()),
        )
        .await
        .into_response();
        assert_eq!(resp4.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    async fn setup_state(test_name: &str) -> (Arc<AppState>, String, String) {
        let (state, tenant_id, agent_token, events_rx) = setup_state_with_events(test_name).await;
        // Drain in the background so existing tests are unaffected by the stream.
        // Phase 5: pass pool.clone() so the drain can persist alerts + incidents.
        tokio::spawn(events::drain(events_rx, state.pool.clone()));
        (state, tenant_id, agent_token)
    }

    async fn setup_state_with_events(
        test_name: &str,
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
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db::insert_agent(&pool, &agent).await.unwrap();

        let policy_engine = PolicyEngine::init("policies.cedar").await.unwrap();
        let (events, events_rx) = EventSink::channel(events::DEFAULT_CAPACITY);
        let state = Arc::new(AppState {
            pool,
            policy_engine,
            events,
            metrics: crate::metrics::SecurityMetrics::new(),
            approval_ttl_secs: 1800,
            rate_limiter: RateLimiter::new(1000.0, 1000.0),
            quota_manager: QuotaManager::new(0, 86400),
            skill_cache: SkillActionCache::new(1024),
            startup_complete: std::sync::atomic::AtomicBool::new(true),
        });

        (state, tenant_id, agent_token, events_rx)
    }

    fn agent_headers(agent_token: &str, tenant_id: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", agent_token).parse().unwrap(),
        );
        headers.insert("X-Aegis-Tenant-ID", tenant_id.parse().unwrap());
        headers
    }

    fn mcp_authorize_request(tool: &str, action: &str) -> AuthorizeRequest {
        AuthorizeRequest {
            request_id: None,
            callback: None,
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
            }),
        }
    }

    async fn call_authorize(
        state: Arc<AppState>,
        tenant_id: &str,
        agent_token: &str,
        request: AuthorizeRequest,
    ) -> AuthorizeResponse {
        let response = authorize_action(
            State(state),
            agent_headers(agent_token, tenant_id),
            Json(request),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn authorize_emits_security_event() {
        // Phase 0 keystone: every authorize decision must feed the async SOC
        // stream, non-blocking. We keep the receiver and assert the decision
        // surfaces as exactly one AseEvent — the spine every later SOC phase
        // (detection, correlation, response, indexing) consumes.
        let (state, tenant_id, agent_token, mut events_rx) =
            setup_state_with_events("emits_security_event").await;

        let request = mcp_authorize_request("filesystem", "read_file");
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;

        let event = events_rx
            .try_recv()
            .expect("authorize must emit exactly one ASE event onto the SOC stream");
        assert_eq!(event.kind, "authorize_decision");
        assert_eq!(event.tenant_id, tenant_id);
        assert_eq!(event.decision, response.decision);
        assert_eq!(event.tool, "filesystem");
        assert_eq!(event.action, "read_file");
        assert_eq!(event.run_id.as_deref(), Some("run_routes"));
    }

    #[test]
    fn canonical_action_matches_shared_corpus() {
        // Locks the gateway side of the cross-language canonicalization contract to
        // the same corpus the Python SDK test pins. If both sides match the corpus
        // string, their SHA-256 action hashes are equal by construction, which is
        // what makes the fail-closed approval guarantee sound across languages.
        let corpus_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/canonical_action_vectors.json"
        );
        let raw = std::fs::read_to_string(corpus_path)
            .expect("shared canonical corpus must exist at tests/canonical_action_vectors.json");
        let corpus: Value = serde_json::from_str(&raw).expect("corpus must be valid JSON");

        assert_eq!(
            corpus["canon_version"].as_str(),
            Some(CANON_VERSION),
            "corpus canon_version must match gateway CANON_VERSION"
        );

        let vectors = corpus["vectors"].as_array().expect("vectors array");
        for vector in vectors {
            let name = vector["name"].as_str().unwrap_or("<unnamed>");
            let tool_call: AuthorizeToolCall = serde_json::from_value(vector["tool_call"].clone())
                .unwrap_or_else(|e| panic!("vector {name}: tool_call must deserialize: {e}"));

            let produced = canonical_action_string(&tool_call);
            let expected = vector["canonical"].as_str().unwrap();
            assert_eq!(
                produced, expected,
                "vector {name}: canonical string mismatch"
            );

            // Hash must equal SHA-256 of the corpus canonical string.
            let expected_hash = sha256_hex(expected.as_bytes());
            assert_eq!(
                hash_tool_call(&tool_call),
                expected_hash,
                "vector {name}: action_hash mismatch"
            );
        }
    }

    /// TASK-0154 (#1000): `aegis-jcs-1` canonicalization must handle Unicode
    /// parameter values and object keys correctly — raw UTF-8 (no `\uXXXX`
    /// escaping), object keys sorted by Unicode code point (not by byte/UTF-16
    /// order), and 4-byte UTF-8 sequences (emoji / supplementary-plane
    /// characters) preserved exactly. A divergence here would break
    /// cross-language byte-parity for non-ASCII payloads.
    #[test]
    fn canonicalization_handles_unicode_parameters() {
        let tool_call = AuthorizeToolCall {
            tool: "github".to_string(),
            action: "create_issue".to_string(),
            resource: Some("repo/example".to_string()),
            mutates_state: true,
            parameters: json!({
                "title": "日本語のタイトル",
                "emoji": "🔥🚀",
                "é": 1,
                "z": 2,
                "a": 3,
            }),
        };

        let canonical = canonical_action_string(&tool_call);

        // Raw UTF-8, not \uXXXX-escaped.
        assert!(canonical.contains("日本語のタイトル"));
        assert!(canonical.contains("🔥🚀"));
        assert!(!canonical.contains("\\u"));

        // Object keys sorted by Unicode code point: 'a' (0x61) < 'z' (0x7A) <
        // 'é' (0xE9), so within "parameters" the order is a, z, é.
        let params_start = canonical.find("\"parameters\":{").unwrap();
        let params_section = &canonical[params_start..];
        let a_pos = params_section.find("\"a\":3").unwrap();
        let z_pos = params_section.find("\"z\":2").unwrap();
        let e_pos = params_section.find("\"é\":1").unwrap();
        assert!(
            a_pos < z_pos && z_pos < e_pos,
            "keys must sort by Unicode code point: a < z < é"
        );

        // Canonicalization and hashing are deterministic for Unicode input.
        let canonical2 = canonical_action_string(&tool_call);
        assert_eq!(canonical, canonical2);
        assert_eq!(hash_tool_call(&tool_call), hash_tool_call(&tool_call));
    }

    fn make_test_approval(
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

    #[test]
    fn approval_is_expired_detects_past_window() {
        assert!(approval_is_expired(&make_test_approval(
            Some(Utc::now() - Duration::minutes(1)),
            "created"
        )));
        assert!(!approval_is_expired(&make_test_approval(
            Some(Utc::now() + Duration::minutes(30)),
            "created"
        )));
        // No expiry set -> never expired.
        assert!(!approval_is_expired(&make_test_approval(None, "created")));
    }

    #[test]
    fn receipt_chain_matches_shared_corpus() {
        // Proves the gateway reproduces the Python-generated receipt_hash values
        // byte-for-byte: receipt_hash = SHA-256(canonical(body)) where body is
        // every field except receipt_hash (incl. prev_receipt_hash). This is the
        // cross-language guarantee that lets the Python verifier / aegis-verify-receipts
        // validate gateway-emitted receipts. See docs/action-receipt-spec.md.
        let corpus_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/receipt_chain_vectors.json"
        );
        let raw = std::fs::read_to_string(corpus_path)
            .expect("shared receipt corpus must exist at tests/receipt_chain_vectors.json");
        let corpus: Value = serde_json::from_str(&raw).expect("corpus must be valid JSON");

        assert_eq!(corpus["canon_version"].as_str(), Some(CANON_VERSION));

        let receipts = corpus["receipts"].as_array().expect("receipts array");
        let mut prev = String::new();
        for receipt in receipts {
            let obj = receipt.as_object().expect("receipt object");
            let stored = obj
                .get("receipt_hash")
                .and_then(|v| v.as_str())
                .expect("receipt_hash present");

            // body = all fields except receipt_hash (prev_receipt_hash stays in).
            let mut body = obj.clone();
            body.remove("receipt_hash");
            let recomputed = sha256_hex(canonical_value_string(&Value::Object(body)).as_bytes());
            assert_eq!(recomputed, stored, "receipt hash mismatch vs corpus");

            // Chain linkage: each receipt references the previous receipt's hash.
            let prev_in_receipt = obj
                .get("prev_receipt_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            assert_eq!(prev_in_receipt, prev, "broken chain link");
            prev = stored.to_string();
        }
    }

    #[tokio::test]
    async fn consume_is_single_use() {
        let (state, tenant_id, agent_token) = setup_state("consume_single_use").await;

        // Create an approval (merge to main) and approve it.
        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/9".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        let approve = approve_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        // First consume succeeds.
        let first = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(first.status(), StatusCode::OK);

        // Second consume is rejected — single-use.
        let second = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(second.status(), StatusCode::CONFLICT);
    }

    /// #1004: two concurrent `consume_approval` calls for the same approved,
    /// single-use approval race against each other. The atomic
    /// `UPDATE ... WHERE consumed_at IS NULL` in `db::consume_approval`
    /// guarantees exactly one wins (200 OK) and the other is rejected (409
    /// CONFLICT) — never both succeeding (which would allow replay).
    #[tokio::test]
    async fn consume_approval_concurrent_race_only_one_succeeds() {
        let (state, tenant_id, agent_token) = setup_state("consume_concurrent_race").await;

        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/77".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        let approve = approve_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        let (a, b) = tokio::join!(
            consume_approval(
                State(state.clone()),
                TenantId(tenant_id.clone()),
                Path(approval_id),
                None,
            ),
            consume_approval(
                State(state.clone()),
                TenantId(tenant_id.clone()),
                Path(approval_id),
                None,
            ),
        );

        let statuses = [a.into_response().status(), b.into_response().status()];
        let ok_count = statuses.iter().filter(|s| **s == StatusCode::OK).count();
        let conflict_count = statuses
            .iter()
            .filter(|s| **s == StatusCode::CONFLICT)
            .count();
        assert_eq!(ok_count, 1, "exactly one consume must succeed");
        assert_eq!(conflict_count, 1, "exactly one consume must be rejected");
    }

    /// #1168: 50 concurrent `consume_approval` calls for the same approved,
    /// single-use approval. Exactly one must win (200 OK) and the other 49
    /// must be rejected (409 CONFLICT) — and the receipt chain produced by
    /// the resulting tamper-attempt receipts must remain a single unbroken
    /// chain (no fork), per `crate::jobs::verify_tenant_receipt_chain`.
    #[tokio::test]
    async fn consume_approval_50_concurrent_only_one_succeeds_and_chain_unforked() {
        let (state, tenant_id, agent_token) = setup_state("consume_concurrent_50").await;

        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/78".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        let approve = approve_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        let mut handles = Vec::new();
        for _ in 0..50 {
            let state = state.clone();
            let tenant_id = tenant_id.clone();
            handles.push(tokio::spawn(async move {
                consume_approval(State(state), TenantId(tenant_id), Path(approval_id), None)
                    .await
                    .into_response()
                    .status()
            }));
        }

        let mut ok_count = 0;
        let mut conflict_count = 0;
        for handle in handles {
            match handle.await.unwrap() {
                StatusCode::OK => ok_count += 1,
                StatusCode::CONFLICT => conflict_count += 1,
                other => panic!("unexpected status: {other}"),
            }
        }
        assert_eq!(ok_count, 1, "exactly one of 50 consumes must succeed");
        assert_eq!(conflict_count, 49, "the other 49 consumes must be rejected");

        crate::jobs::verify_tenant_receipt_chain(&state.pool, &tenant_id)
            .await
            .expect("receipt chain must remain a single unbroken chain (no fork)");
    }

    /// Shared helper for the approval-lifecycle tests below: triggers a
    /// require_approval decision (a production GitHub merge) and returns its
    /// approval id plus the bound `action_hash`.
    async fn create_pending_approval(
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

    /// #0127: approve_approval transitions a pending approval to APPROVED.
    #[tokio::test]
    async fn approve_approval_changes_status_to_approved() {
        let (state, tenant_id, agent_token) = setup_state("approve_sets_status").await;
        let (approval_id, _hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "20").await;

        let approve = approve_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        let stored = db::get_approval_by_id(&state.pool, &tenant_id, &approval_id.to_string())
            .await
            .unwrap()
            .expect("approval should exist");
        assert_eq!(stored.status, "APPROVED");
    }

    /// #0128: approve_approval records the approver_user_id on the approval.
    #[tokio::test]
    async fn approve_approval_sets_approver_user_id() {
        let (state, tenant_id, agent_token) = setup_state("approve_sets_approver").await;
        let (approval_id, _hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "21").await;

        let approve = approve_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Json(ApproveRequest {
                approver_user_id: "reviewer-42".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        let stored = db::get_approval_by_id(&state.pool, &tenant_id, &approval_id.to_string())
            .await
            .unwrap()
            .expect("approval should exist");
        assert_eq!(stored.approver_user_id.as_deref(), Some("reviewer-42"));
    }

    /// #0129: reject_approval transitions a pending approval to REJECTED.
    #[tokio::test]
    async fn reject_approval_changes_status_to_rejected() {
        let (state, tenant_id, agent_token) = setup_state("reject_sets_status").await;
        let (approval_id, _hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "22").await;

        let reject = reject_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: Some("not safe to ship".to_string()),
            }),
        )
        .await
        .into_response();
        assert_eq!(reject.status(), StatusCode::OK);

        let stored = db::get_approval_by_id(&state.pool, &tenant_id, &approval_id.to_string())
            .await
            .unwrap()
            .expect("approval should exist");
        assert_eq!(stored.status, "REJECTED");
        assert_eq!(stored.reason.as_deref(), Some("not safe to ship"));
    }

    /// #0133: consume_approval rejects an APPROVED approval whose expiry window
    /// has already passed (fail-closed) — a single-use approval that ages out
    /// before execution must not be consumable.
    #[tokio::test]
    async fn consume_approval_rejects_expired_approval() {
        let (state, tenant_id, agent_token) = setup_state("consume_rejects_expired").await;
        let (approval_id, _hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "23").await;

        let approve = approve_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        // Age the approval out after it was granted.
        sqlx::query("UPDATE approvals SET expires_at = ? WHERE tenant_id = ? AND id = ?")
            .bind(Utc::now() - Duration::minutes(5))
            .bind(tenant_id.as_str())
            .bind(approval_id.to_string())
            .execute(&state.pool)
            .await
            .unwrap();

        let consume = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(consume.status(), StatusCode::CONFLICT);
    }

    /// #0134: consume_approval returns the original action_hash that the
    /// approval was bound to, so the SDK can re-verify it before executing.
    #[tokio::test]
    async fn consume_approval_returns_bound_action_hash() {
        let (state, tenant_id, agent_token) = setup_state("consume_returns_hash").await;
        let (approval_id, bound_hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "24").await;

        let approve = approve_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        let consume = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(consume.status(), StatusCode::OK);

        let body = to_bytes(consume.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["action_hash"].as_str(), Some(bound_hash.as_str()));
    }

    /// #0130: edit_approval re-hashes the edited tool call and binds the
    /// approval to the new action_hash (not the original).
    #[tokio::test]
    async fn edit_approval_rehashes_and_stores_edited_call() {
        let (state, tenant_id, agent_token) = setup_state("edit_rehashes").await;
        let (approval_id, original_hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "30").await;

        let mut edited_tool_call = mcp_authorize_request("github", "merge_pull_request").tool_call;
        edited_tool_call.resource = Some("repo/example/pull/30".to_string());
        edited_tool_call.parameters = serde_json::json!({"base_branch": "release"});
        let expected_hash = hash_tool_call(&edited_tool_call);
        assert_ne!(expected_hash, original_hash);

        let edit = edit_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Json(EditApprovalRequest {
                approver_user_id: "reviewer".to_string(),
                edited_tool_call: edited_tool_call.clone(),
                reason: Some("changed target branch".to_string()),
            }),
        )
        .await
        .into_response();
        assert_eq!(edit.status(), StatusCode::OK);

        let stored = db::get_approval_by_id(&state.pool, &tenant_id, &approval_id.to_string())
            .await
            .unwrap()
            .expect("approval should exist");
        assert_eq!(stored.status, "EDITED");
        assert_eq!(stored.original_call_hash, expected_hash);
        let stored_edited: AuthorizeToolCall =
            serde_json::from_str(stored.edited_skill_call.as_deref().unwrap()).unwrap();
        assert_eq!(stored_edited.parameters, edited_tool_call.parameters);
    }

    /// #0131: edit_approval rejects an approval that has already been decided
    /// (e.g. already consumed/approved) — no re-deciding a decided approval.
    #[tokio::test]
    async fn edit_approval_rejects_if_already_consumed() {
        let (state, tenant_id, agent_token) = setup_state("edit_rejects_consumed").await;
        let (approval_id, _hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "31").await;

        let approve = approve_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        let consume = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(consume.status(), StatusCode::OK);

        let mut edited_tool_call = mcp_authorize_request("github", "merge_pull_request").tool_call;
        edited_tool_call.resource = Some("repo/example/pull/31".to_string());

        let edit = edit_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Json(EditApprovalRequest {
                approver_user_id: "reviewer".to_string(),
                edited_tool_call,
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(edit.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn authorize_emits_verifiable_receipt() {
        let (state, tenant_id, agent_token) = setup_state("emit_receipt").await;

        // Any decision (here a read-only allow) must emit a receipt.
        let mut request = mcp_authorize_request("github", "read_issue");
        request.tool_call.mutates_state = false;
        let _ = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;

        let (receipt_id,): (String,) = sqlx::query_as(
            "SELECT id FROM action_receipts WHERE tenant_id = ? ORDER BY rowid DESC LIMIT 1",
        )
        .bind(tenant_id.as_str())
        .fetch_one(&state.pool)
        .await
        .expect("a receipt should have been emitted for the decision");

        // The /verify endpoint recomputes the hash and confirms integrity.
        let response = verify_receipt(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(receipt_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["verified"].as_bool(), Some(true));
        assert_eq!(json["receipt_id"].as_str(), Some(receipt_id.as_str()));
        // Hermetic default: no signing key configured → unsigned.
        // signature_verified is null and `signed` is false; hash `verified` unchanged.
        assert_eq!(json["signed"].as_bool(), Some(false));
        assert!(json["signature_verified"].is_null());
    }

    /// #930: every emitted receipt records the canonicalization scheme that hashed
    /// it, and that field is additive — the byte-parity-locked `receipt_hash` is the
    /// same whether or not `canon_version` is set.
    #[tokio::test]
    async fn emitted_receipt_records_canon_version() {
        let (state, tenant_id, agent_token) = setup_state("receipt_canon_version").await;

        let request = mcp_authorize_request("github", "read_issue");
        let _ = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;

        let (receipt_id,): (String,) = sqlx::query_as(
            "SELECT id FROM action_receipts WHERE tenant_id = ? ORDER BY rowid DESC LIMIT 1",
        )
        .bind(tenant_id.as_str())
        .fetch_one(&state.pool)
        .await
        .unwrap();

        let receipt = db::get_action_receipt_by_id(&state.pool, &tenant_id, &receipt_id)
            .await
            .unwrap()
            .expect("emitted receipt should be retrievable");

        // The scheme is recorded and self-describing.
        assert_eq!(receipt.canon_version, CANON_VERSION);
        assert_eq!(receipt.canon_version, "aegis-jcs-1");

        // Byte-parity guard: canon_version is additive metadata, NOT folded into the
        // hash — recomputing the hash over the same body still matches.
        assert_eq!(receipt.receipt_hash, compute_receipt_hash(&receipt));
    }

    // A fixed test secret (hex, 32 bytes). Test-only — not a real key. Used to
    // emit a signed receipt directly via the atomic appender (so we exercise the
    // verify endpoint's signature path without coupling to the process-global env
    // signer, which `OnceLock`-initializes once per process).
    const TEST_SIGNING_SECRET_HEX: &str =
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    fn unsigned_receipt_template(tenant_id: &str) -> ActionReceiptRecord {
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
            created_at: Utc::now(),
        }
    }

    /// #0136: verify_receipt detects a receipt whose stored `receipt_hash` no
    /// longer matches its recomputed value (tamper detection).
    #[tokio::test]
    async fn verify_receipt_detects_tampered_receipt() {
        let (state, tenant_id, _agent_token) = setup_state("tampered_single_receipt").await;

        let rec = db::append_action_receipt_atomic(&state.pool, &tenant_id, |prev| {
            let mut r = unsigned_receipt_template(&tenant_id);
            r.prev_receipt_hash = prev;
            r.receipt_hash = compute_receipt_hash(&r);
            r
        })
        .await
        .expect("receipt insert");

        sqlx::query("UPDATE action_receipts SET receipt_hash = 'sha256:tampered' WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id.as_str())
            .bind(&rec.id)
            .execute(&state.pool)
            .await
            .unwrap();

        let response = verify_receipt(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(rec.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["verified"].as_bool(), Some(false));
        assert_eq!(json["receipt_hash"].as_str(), Some("sha256:tampered"));
        assert_ne!(
            json["recomputed_hash"].as_str(),
            json["receipt_hash"].as_str()
        );
    }

    #[tokio::test]
    async fn verify_reports_signature_for_a_signed_receipt() {
        let (state, tenant_id, _agent_token) = setup_state("signed_receipt").await;
        let signer = sign::ReceiptSigner::from_secret_hex(TEST_SIGNING_SECRET_HEX).unwrap();

        // Insert a signed receipt through the real atomic appender. Hash FIRST over
        // the live chain head, then sign OVER that hash (additive metadata).
        let rec = db::append_action_receipt_atomic(&state.pool, &tenant_id, |prev| {
            let mut r = unsigned_receipt_template(&tenant_id);
            r.prev_receipt_hash = prev;
            r.receipt_hash = compute_receipt_hash(&r);
            r.signature = Some(signer.sign_hash(&r.receipt_hash));
            r.signer_public_key = Some(signer.public_key_hex());
            r
        })
        .await
        .expect("signed receipt insert");

        let response = verify_receipt(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(rec.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Hash integrity unchanged AND signature verifies.
        assert_eq!(json["verified"].as_bool(), Some(true));
        assert_eq!(json["signed"].as_bool(), Some(true));
        assert_eq!(json["signature_verified"].as_bool(), Some(true));
        assert_eq!(
            json["signer_public_key"].as_str(),
            Some(signer.public_key_hex().as_str())
        );
    }

    #[test]
    fn signing_does_not_perturb_receipt_hash() {
        // BYTE-PARITY GUARD: compute_receipt_hash must be identical whether or not
        // the signature/signer fields are populated. The signature sits OVER the
        // hash; it is never an input to it.
        let signer = sign::ReceiptSigner::from_secret_hex(TEST_SIGNING_SECRET_HEX).unwrap();

        let mut unsigned = ActionReceiptRecord {
            id: "rcpt_parity".to_string(),
            tenant_id: "t".to_string(),
            decision_id: None,
            ts: "2026-06-02T12:00:00Z".to_string(),
            agent_id: Some("a".to_string()),
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
            created_at: Utc::now(),
        };
        let hash_unsigned = compute_receipt_hash(&unsigned);

        // Populate the signature fields and re-hash: the hash MUST be unchanged.
        unsigned.signature = Some(signer.sign_hash(&hash_unsigned));
        unsigned.signer_public_key = Some(signer.public_key_hex());
        let hash_signed = compute_receipt_hash(&unsigned);

        assert_eq!(
            hash_unsigned, hash_signed,
            "signing must not change the receipt hash (byte-parity moat)"
        );
    }

    #[tokio::test]
    async fn expired_approval_is_reported_and_cannot_be_approved() {
        let (state, tenant_id, agent_token) = setup_state("approve_expired").await;

        // Create a real require_approval via authorize (merge to main).
        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/7".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        // Force the approval past its window.
        sqlx::query("UPDATE approvals SET expires_at = ? WHERE tenant_id = ? AND id = ?")
            .bind(Utc::now() - Duration::minutes(5))
            .bind(tenant_id.as_str())
            .bind(approval_id.to_string())
            .execute(&state.pool)
            .await
            .unwrap();

        // get_approval reports EXPIRED for the still-pending, past-window approval.
        let get_resp = get_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
        )
        .await
        .into_response();
        let body = to_bytes(get_resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "EXPIRED");

        // approve_approval refuses to grant an expired approval.
        let approve_resp = approve_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve_resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn authorize_denies_unknown_mcp_tools_by_default() {
        let (state, tenant_id, agent_token) = setup_state("unknown_mcp_tool").await;
        let response = call_authorize(
            state,
            &tenant_id,
            &agent_token,
            mcp_authorize_request("mcp:github-mcp", "unknown_tool"),
        )
        .await;

        assert_eq!(response.decision, "deny");
        assert_eq!(response.risk_level, "critical");
        assert_eq!(response.risk_score, 100);
        assert!(response
            .matched_policies
            .contains(&"mcp_unknown_tool".to_string()));
    }

    /// #0117: a non-mutating ("read-only") action on a registered low-risk
    /// skill is allowed, with the registered risk level/score reflected back.
    #[tokio::test]
    async fn authorize_allows_read_only_action() {
        let (state, tenant_id, agent_token) = setup_state("authorize_read_only").await;
        register_ship_action(&state, &tenant_id, "low").await;

        let mut request = mcp_authorize_request("deployer", "ship");
        request.tool_call.mutates_state = false;
        request.context.source_trust = "trusted_internal_signed".to_string();

        let response = call_authorize(state, &tenant_id, &agent_token, request).await;

        assert_eq!(response.decision, "allow");
        assert_eq!(response.risk_level, "low");
        assert_eq!(response.risk_score, 10);
    }

    /// #0118: a mutating action whose triggering content has untrusted
    /// provenance is denied outright (anti-confused-deputy gate), regardless
    /// of the registered action's risk level.
    #[tokio::test]
    async fn authorize_denies_untrusted_mutation() {
        let (state, tenant_id, agent_token) = setup_state("authorize_untrusted_mutation").await;
        register_ship_action(&state, &tenant_id, "low").await;

        let mut request = mcp_authorize_request("deployer", "ship");
        request.tool_call.mutates_state = true;
        request.context.source_trust = "untrusted_external".to_string();

        let response = call_authorize(state, &tenant_id, &agent_token, request).await;

        assert_eq!(response.decision, "deny");
    }

    /// #0122: every authorize decision writes a corresponding row to
    /// `audit_events`, retrievable via `GET /v1/audit/events` with the
    /// matching tool/action/decision details embedded in `event_json`.
    #[tokio::test]
    async fn authorize_emits_audit_event() {
        let (state, tenant_id, agent_token) = setup_state("authorize_audit_event").await;
        register_ship_action(&state, &tenant_id, "low").await;

        let mut request = mcp_authorize_request("deployer", "ship");
        request.tool_call.mutates_state = false;
        request.context.source_trust = "trusted_internal_signed".to_string();

        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(response.decision, "allow");

        let audit_response = get_audit_events(State(state), TenantId(tenant_id.clone()))
            .await
            .into_response();
        assert_eq!(audit_response.status(), StatusCode::OK);

        let body = to_bytes(audit_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let events: Vec<AuditEventRecord> = serde_json::from_slice(&body).unwrap();

        let event = events
            .iter()
            .find(|e| e.event_type == "tool_call_intercepted")
            .expect("authorize must write a tool_call_intercepted audit event");
        assert_eq!(event.tenant_id, tenant_id);
        assert_eq!(event.skill.as_deref(), Some("deployer"));
        assert_eq!(event.action.as_deref(), Some("ship"));

        let event_json: serde_json::Value = serde_json::from_str(&event.event_json).unwrap();
        assert_eq!(event_json["decision"], "allow");
        assert_eq!(event_json["id"], response.decision_id.to_string());
    }

    /// TASK-0160 (#1006): `GET /v1/audit/events` must (a) only return the
    /// caller's own tenant's events, never another tenant's, and (b) cap the
    /// result at 100 rows (`db::get_all_audit_events`'s `LIMIT 100`) even
    /// when more rows exist.
    #[tokio::test]
    async fn get_audit_events_respects_tenant_scope_and_limit() {
        let (state, tenant_id, _agent_token) = setup_state("audit_events_scope_limit").await;
        let other_tenant = "audit_events_scope_limit_other";
        db::register_tenant(&state.pool, other_tenant, "Other Tenant", "developer")
            .await
            .unwrap();

        fn audit_event(tenant_id: &str, n: usize) -> AuditEventRecord {
            AuditEventRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.to_string(),
                event_type: "test_event".to_string(),
                agent_id: None,
                user_id: None,
                run_id: None,
                trace_id: None,
                span_id: None,
                skill: None,
                action: None,
                resource: Some(format!("item-{n}")),
                event_json: "{}".to_string(),
                input_hash: None,
                output_hash: None,
                created_at: Utc::now(),
            }
        }

        // 105 events for the caller's tenant (exceeds the 100-row cap) and one
        // for another tenant (must never be returned).
        for n in 0..105 {
            db::insert_audit_event(&state.pool, &audit_event(&tenant_id, n))
                .await
                .unwrap();
        }
        db::insert_audit_event(&state.pool, &audit_event(other_tenant, 0))
            .await
            .unwrap();

        let response = get_audit_events(State(state), TenantId(tenant_id.clone()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let events: Vec<AuditEventRecord> = serde_json::from_slice(&body).unwrap();

        assert_eq!(events.len(), 100, "result must be capped at 100 rows");
        assert!(
            events.iter().all(|e| e.tenant_id == tenant_id),
            "must never return another tenant's audit events"
        );
    }

    /// TASK-0159 (#1005): `GET /v1/runs/:id/timeline` must return events for the
    /// requested run in chronological (`created_at ASC`) order, regardless of
    /// the order they were inserted, and must exclude events from other runs.
    #[tokio::test]
    async fn get_timeline_returns_events_in_chronological_order() {
        let (state, tenant_id, _agent_token) = setup_state("timeline_chronological_order").await;
        let run_id = "run-timeline-1";

        fn timeline_event(
            tenant_id: &str,
            run_id: &str,
            label: &str,
            age_secs: i64,
        ) -> AuditEventRecord {
            AuditEventRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.to_string(),
                event_type: "test_event".to_string(),
                agent_id: None,
                user_id: None,
                run_id: Some(run_id.to_string()),
                trace_id: None,
                span_id: None,
                skill: None,
                action: None,
                resource: Some(label.to_string()),
                event_json: "{}".to_string(),
                input_hash: None,
                output_hash: None,
                created_at: Utc::now() - Duration::seconds(age_secs),
            }
        }

        // insert_audit_event relies on the column's DEFAULT CURRENT_TIMESTAMP and
        // does not bind `created_at`, so set the desired timestamps directly
        // after each insert to exercise ORDER BY created_at ASC deterministically.
        async fn insert_with_created_at(pool: &sqlx::SqlitePool, event: &AuditEventRecord) {
            db::insert_audit_event(pool, event).await.unwrap();
            sqlx::query("UPDATE audit_events SET created_at = ? WHERE id = ?")
                .bind(event.created_at)
                .bind(&event.id)
                .execute(pool)
                .await
                .unwrap();
        }

        // Insert out of chronological order: "third" (oldest) last.
        insert_with_created_at(
            &state.pool,
            &timeline_event(&tenant_id, run_id, "first", 10),
        )
        .await;
        insert_with_created_at(
            &state.pool,
            &timeline_event(&tenant_id, run_id, "second", 5),
        )
        .await;
        insert_with_created_at(
            &state.pool,
            &timeline_event(&tenant_id, run_id, "third", 20),
        )
        .await;
        // A different run — must not appear in this run's timeline.
        insert_with_created_at(
            &state.pool,
            &timeline_event(&tenant_id, "run-timeline-other", "other-run", 1),
        )
        .await;

        let response = get_timeline(
            State(state),
            TenantId(tenant_id.clone()),
            Path(run_id.to_string()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let events: Vec<AuditEventRecord> = serde_json::from_slice(&body).unwrap();

        let resources: Vec<&str> = events
            .iter()
            .map(|e| e.resource.as_deref().unwrap())
            .collect();
        assert_eq!(
            resources,
            vec!["third", "first", "second"],
            "events must be ordered oldest-first by created_at, regardless of insertion order"
        );
    }

    /// #0119: a mutating action whose triggering content has
    /// `semi_trusted_customer` provenance is paused for human review rather
    /// than auto-allowed or auto-denied.
    #[tokio::test]
    async fn authorize_requires_approval_for_customer_context() {
        let (state, tenant_id, agent_token) = setup_state("authorize_customer_context").await;
        register_ship_action(&state, &tenant_id, "low").await;

        let mut request = mcp_authorize_request("deployer", "ship");
        request.tool_call.mutates_state = true;
        request.context.source_trust = "semi_trusted_customer".to_string();

        let response = call_authorize(state, &tenant_id, &agent_token, request).await;

        assert_eq!(response.decision, "require_approval");
        let approval = response.approval.expect("approval info should be present");
        assert_eq!(
            approval.approver_group.as_deref(),
            Some("security-reviewers")
        );
    }

    /// #1187/TASK-0082-0083: an optional `callback` on the authorize request
    /// is persisted on the resulting approval as `callback_url` (verbatim)
    /// and `callback_secret_hash` (sha256 of the secret) — the plaintext
    /// secret itself is never stored.
    #[tokio::test]
    async fn authorize_persists_approval_callback_with_hashed_secret() {
        let (state, tenant_id, agent_token) = setup_state("authorize_callback").await;
        register_ship_action(&state, &tenant_id, "low").await;

        let mut request = mcp_authorize_request("deployer", "ship");
        request.tool_call.mutates_state = true;
        request.context.source_trust = "semi_trusted_customer".to_string();
        request.callback = Some(crate::models::ApprovalCallback {
            url: "https://example.com/aegis-callback".to_string(),
            secret: Some("topsecret".to_string()),
        });

        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(response.decision, "require_approval");
        let approval_id = response.approval.expect("approval info").approval_id;

        let stored = db::get_approval_by_id(&state.pool, &tenant_id, &approval_id.to_string())
            .await
            .unwrap()
            .expect("approval row should exist");

        assert_eq!(
            stored.callback_url.as_deref(),
            Some("https://example.com/aegis-callback")
        );
        assert_eq!(
            stored.callback_secret_hash.as_deref(),
            Some(sha256_hex(b"topsecret").as_str())
        );
        // The plaintext secret never appears in the persisted row.
        assert_ne!(stored.callback_secret_hash.as_deref(), Some("topsecret"));
    }

    /// #0120: the `risk_score` returned by `/v1/authorize` matches the
    /// registered action's risk level via `risk_score_for_level`.
    #[tokio::test]
    async fn authorize_returns_correct_risk_score() {
        let (state, tenant_id, agent_token) = setup_state("authorize_risk_score").await;
        register_ship_action(&state, &tenant_id, "high").await;

        let mut request = mcp_authorize_request("deployer", "ship");
        request.tool_call.mutates_state = false;
        request.context.source_trust = "trusted_internal_signed".to_string();

        let response = call_authorize(state, &tenant_id, &agent_token, request).await;

        assert_eq!(response.risk_level, "high");
        assert_eq!(response.risk_score, 75);
    }

    /// #0121: a critical-risk registered action that would otherwise be
    /// allowed has `matched_policies` annotated with the secure-default that
    /// downgraded it to `require_approval`.
    #[tokio::test]
    async fn authorize_returns_correct_matched_policies() {
        let (state, tenant_id, agent_token) = setup_state("authorize_matched_policies").await;
        register_ship_action(&state, &tenant_id, "critical").await;

        let mut request = mcp_authorize_request("deployer", "ship");
        request.tool_call.mutates_state = false;
        request.context.source_trust = "trusted_internal_signed".to_string();

        let response = call_authorize(state, &tenant_id, &agent_token, request).await;

        assert_eq!(response.decision, "require_approval");
        assert_eq!(response.risk_score, 95);
        assert!(response
            .matched_policies
            .contains(&"critical_risk_requires_approval".to_string()));
    }

    #[tokio::test]
    async fn approval_flow_binds_original_action_hash() {
        let (state, tenant_id, agent_token) = setup_state("approval_action_hash").await;
        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/42".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});

        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(response.decision, "require_approval");

        let approval = response.approval.expect("approval info should be present");
        assert_eq!(approval.action_hash.len(), 64);
        assert!(approval
            .action_hash
            .chars()
            .all(|ch| ch.is_ascii_hexdigit()));

        let status_response = get_approval(
            State(state),
            TenantId("tenant_routes".to_string()),
            Path(approval.approval_id),
        )
        .await
        .into_response();
        assert_eq!(status_response.status(), StatusCode::OK);

        let body = to_bytes(status_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let status_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(status_json["action_hash"], approval.action_hash);
    }

    /// #0072: a repeat `/v1/authorize` call with the same `request_id` returns the
    /// original decision unchanged — for an `allow` decision, and for a
    /// `require_approval` decision it must NOT create a second approval (the
    /// replayed response carries the same `approval_id`/`action_hash`).
    #[tokio::test]
    async fn authorize_is_idempotent_for_repeated_request_id() {
        let (state, tenant_id, agent_token) = setup_state("idempotency_key").await;

        // Allow path
        let mut allow_request = mcp_authorize_request("filesystem", "read_file");
        allow_request.request_id = Some("req-allow-1".to_string());
        let first = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            allow_request.clone(),
        )
        .await;
        assert_eq!(first.decision, "allow");

        let second = call_authorize(state.clone(), &tenant_id, &agent_token, allow_request).await;
        assert_eq!(second.decision, first.decision);
        assert_eq!(second.decision_id, first.decision_id);
        assert_eq!(second.risk_score, first.risk_score);

        // Only one decision row was written for this request_id.
        let agent = db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap();
        let stored =
            db::get_decision_by_request_id(&state.pool, &tenant_id, &agent.id, "req-allow-1")
                .await
                .unwrap()
                .unwrap();
        assert_eq!(stored.id, first.decision_id.to_string());

        // require_approval path: the second call must replay the SAME approval.
        let mut approval_request = mcp_authorize_request("github", "merge_pull_request");
        approval_request.tool_call.mutates_state = true;
        approval_request.tool_call.resource = Some("repo/example/pull/7".to_string());
        approval_request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        approval_request.request_id = Some("req-approval-1".to_string());

        let first = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            approval_request.clone(),
        )
        .await;
        assert_eq!(first.decision, "require_approval");
        let first_approval = first.approval.expect("approval info expected");

        let second =
            call_authorize(state.clone(), &tenant_id, &agent_token, approval_request).await;
        assert_eq!(second.decision, "require_approval");
        let second_approval = second.approval.expect("approval info expected on replay");
        assert_eq!(second_approval.approval_id, first_approval.approval_id);
        assert_eq!(second_approval.action_hash, first_approval.action_hash);

        // Still exactly one pending approval for this decision.
        let approvals = db::list_pending_approvals(&state.pool, &tenant_id, 50, 0)
            .await
            .unwrap();
        assert_eq!(
            approvals
                .iter()
                .filter(|a| a.id == first_approval.approval_id.to_string())
                .count(),
            1
        );
    }

    /// #0081: every decision row records the wall-clock time spent evaluating
    /// the `/v1/authorize` request, for SOC/perf dashboards.
    #[tokio::test]
    async fn authorize_records_decision_latency_ms() {
        let (state, tenant_id, agent_token) = setup_state("decision_latency_ms").await;

        let response = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            mcp_authorize_request("filesystem", "read_file"),
        )
        .await;
        assert_eq!(response.decision, "allow");

        let stored =
            db::get_decision_by_id(&state.pool, &tenant_id, &response.decision_id.to_string())
                .await
                .unwrap()
                .unwrap();
        let latency = stored.latency_ms.expect("latency_ms should be populated");
        assert!(latency >= 0);
    }

    #[tokio::test]
    async fn authorize_requires_mcp_tool_approval() {
        let (state, tenant_id, agent_token) = setup_state("mcp_tool_approval").await;
        let server_id = db::upsert_mcp_server(
            &state.pool,
            &tenant_id,
            "github-mcp",
            "GitHub MCP",
            Some("platform"),
            "http",
            Some("internal-registry"),
            "trusted_internal_signed",
            "http://127.0.0.1:9001/mcp",
        )
        .await
        .unwrap();
        let tool = McpToolManifestItem {
            tool_key: "create_issue".to_string(),
            name: "Create issue".to_string(),
            description: None,
            input_schema: None,
            risk: "medium".to_string(),
            mutates_state: false,
            approval_required: false,
        };
        db::upsert_mcp_tool(&state.pool, &tenant_id, &server_id, &tool)
            .await
            .unwrap();

        let pending_response = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            mcp_authorize_request("mcp:github-mcp", "create_issue"),
        )
        .await;
        assert_eq!(pending_response.decision, "deny");
        assert!(pending_response
            .matched_policies
            .contains(&"mcp_tool_status".to_string()));

        let updated = db::set_mcp_tool_status(
            &state.pool,
            &tenant_id,
            "github-mcp",
            "create_issue",
            "approved",
        )
        .await
        .unwrap();
        assert!(updated);

        let approved_response = call_authorize(
            state,
            &tenant_id,
            &agent_token,
            mcp_authorize_request("mcp:github-mcp", "create_issue"),
        )
        .await;
        assert_eq!(approved_response.decision, "allow");
        assert_eq!(approved_response.risk_level, "medium");
        assert_eq!(approved_response.risk_score, 40);
    }

    // T-D hardening (a): concurrent appends must keep a tenant's receipt chain
    // strictly linear. If head-select + insert were not atomic, two racing tasks
    // could read the same head and fork the chain (two receipts sharing one
    // `prev_receipt_hash`). We append from many tokio tasks at once and assert the
    // resulting chain is a single unbroken line with no duplicated prev-hash.
    #[tokio::test]
    async fn concurrent_receipt_appends_stay_linear() {
        let (state, tenant_id, _agent_token) = setup_state("concurrent_chain").await;

        const TASKS: usize = 24;
        let mut handles = Vec::with_capacity(TASKS);
        for i in 0..TASKS {
            let pool = state.pool.clone();
            let tenant = tenant_id.clone();
            handles.push(tokio::spawn(async move {
                db::append_action_receipt_atomic(&pool, &tenant, |prev| {
                    let mut rec = ActionReceiptRecord {
                        id: Uuid::new_v4().to_string(),
                        tenant_id: tenant.clone(),
                        decision_id: Some(Uuid::new_v4().to_string()),
                        ts: Utc::now().to_rfc3339(),
                        agent_id: Some("concurrency-agent".to_string()),
                        user_id: None,
                        run_id: None,
                        trace_id: None,
                        tool: Some("github".to_string()),
                        action: Some(format!("op_{}", i)),
                        resource: None,
                        source_trust: "trusted_internal_signed".to_string(),
                        decision: "allow".to_string(),
                        approver: None,
                        action_hash: Some(format!("sha256:dead{:04}", i)),
                        prev_receipt_hash: prev,
                        receipt_hash: String::new(),
                        canon_version: CANON_VERSION.to_string(),
                        signature: None,
                        signer_public_key: None,
                        created_at: Utc::now(),
                    };
                    rec.receipt_hash = compute_receipt_hash(&rec);
                    rec
                })
                .await
            }));
        }
        for h in handles {
            h.await.unwrap().expect("atomic append must succeed");
        }

        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT prev_receipt_hash, receipt_hash FROM action_receipts
             WHERE tenant_id = ? ORDER BY rowid ASC",
        )
        .bind(tenant_id.as_str())
        .fetch_all(&state.pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), TASKS, "every append must commit exactly once");

        let mut seen_prev = std::collections::HashSet::new();
        let mut seen_receipt = std::collections::HashSet::new();
        let mut expected_prev = String::new();
        for (prev, receipt) in &rows {
            assert_eq!(
                prev, &expected_prev,
                "fork detected: prev-hash does not chain to the prior receipt"
            );
            assert!(
                seen_prev.insert(prev.clone()),
                "fork detected: duplicate prev_receipt_hash {}",
                prev
            );
            assert!(
                seen_receipt.insert(receipt.clone()),
                "duplicate receipt_hash {}",
                receipt
            );
            expected_prev = receipt.clone();
        }
    }

    // T-D hardening (b): a consume of an already-used approval is a replay attack on
    // the evidence chain. The gateway must record a tamper-attempt receipt (hashes
    // only, no payloads) so the chain captures the attempt, and still return 409.
    #[tokio::test]
    async fn replay_consume_emits_tamper_receipt() {
        let (state, tenant_id, agent_token) = setup_state("tamper_consume").await;

        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/11".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        let approve = approve_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        let first = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(first.status(), StatusCode::OK);

        let (before,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM action_receipts WHERE tenant_id = ? AND decision = ?",
        )
        .bind(tenant_id.as_str())
        .bind(TAMPER_DECISION)
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(before, 0);

        let replay = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(replay.status(), StatusCode::CONFLICT);

        let recs: Vec<ActionReceiptRecord> = sqlx::query_as(
            "SELECT * FROM action_receipts WHERE tenant_id = ? AND decision = ? ORDER BY rowid ASC",
        )
        .bind(tenant_id.as_str())
        .bind(TAMPER_DECISION)
        .fetch_all(&state.pool)
        .await
        .unwrap();
        assert_eq!(recs.len(), 1, "exactly one tamper receipt for the replay");
        let tamper = &recs[0];
        assert_eq!(tamper.receipt_hash, compute_receipt_hash(tamper));
        assert!(!tamper.prev_receipt_hash.is_empty(), "must chain onto head");
        assert_eq!(tamper.tool.as_deref(), Some("consume_not_consumable"));
        assert_eq!(
            tamper.resource.as_deref(),
            Some(format!("approval:{}", approval_id).as_str())
        );

        let (audit_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM audit_events WHERE tenant_id = ? AND event_type = 'tamper_attempt'",
        )
        .bind(tenant_id.as_str())
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(audit_count, 1);
    }

    // Integrity→SOC loop: a replay (consume of an already-consumed approval) must
    // STILL return 409 and STILL write exactly one tamper receipt (unchanged) AND
    // now ALSO emit a `replay_attempt` AseEvent onto the SOC stream so the detector
    // can raise a HIGH alert. We keep the receiver (no drain spawned) and assert the
    // event lands — mirroring `authorize_emits_security_event`.
    #[tokio::test]
    async fn replay_consume_emits_replay_attempt_security_event() {
        let (state, tenant_id, agent_token, mut events_rx) =
            setup_state_with_events("tamper_consume_soc").await;

        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/13".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        let approve = approve_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        let first = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(first.status(), StatusCode::OK);

        // The replay: a second consume of the now-used approval.
        let replay = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        // 409 response is UNCHANGED.
        assert_eq!(replay.status(), StatusCode::CONFLICT);

        // The tamper receipt is UNCHANGED — exactly one written for the replay.
        let (receipt_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM action_receipts WHERE tenant_id = ? AND decision = ? AND tool = 'consume_not_consumable'",
        )
        .bind(tenant_id.as_str())
        .bind(TAMPER_DECISION)
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(
            receipt_count, 1,
            "exactly one tamper receipt for the replay"
        );

        // NEW: a `replay_attempt` AseEvent must have landed on the SOC stream. Drain
        // the receiver (the earlier authorize_decision event is also queued since no
        // drain task consumes it in this harness) and find the replay event.
        let mut found_replay = false;
        while let Ok(ev) = events_rx.try_recv() {
            if ev.kind == "replay_attempt" {
                assert_eq!(ev.decision, "deny");
                assert_eq!(ev.tenant_id, tenant_id);
                assert_eq!(ev.tool, "consume_not_consumable");
                assert_eq!(
                    ev.resource.as_deref(),
                    Some(format!("approval:{}", approval_id).as_str())
                );
                found_replay = true;
            }
        }
        assert!(
            found_replay,
            "replay must emit a replay_attempt AseEvent onto the SOC stream"
        );
    }

    // T-D hardening (b): approving an expired approval is a detected integrity
    // violation; it must likewise leave a tamper-attempt receipt and return 409.
    #[tokio::test]
    async fn approve_expired_emits_tamper_receipt() {
        let (state, tenant_id, agent_token) = setup_state("tamper_approve_expired").await;

        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/12".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        sqlx::query("UPDATE approvals SET expires_at = ? WHERE tenant_id = ? AND id = ?")
            .bind(Utc::now() - Duration::minutes(5))
            .bind(tenant_id.as_str())
            .bind(approval_id.to_string())
            .execute(&state.pool)
            .await
            .unwrap();

        let approve = approve_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::CONFLICT);

        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM action_receipts WHERE tenant_id = ? AND decision = ? AND tool = 'approve_expired'",
        )
        .bind(tenant_id.as_str())
        .bind(TAMPER_DECISION)
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(
            count, 1,
            "an expired-approval grant attempt must be recorded"
        );
    }

    /// OBS-001 (#1154): every `/v1/authorize` call records one observation on
    /// `aegis_authorize_duration_seconds`, exposed as a Prometheus histogram
    /// with `_bucket`/`_sum`/`_count` series.
    #[tokio::test]
    async fn authorize_records_duration_histogram() {
        let (state, tenant_id, agent_token) = setup_state("authorize_duration_histogram").await;

        assert_eq!(
            state.metrics.authorize_duration.count(),
            0,
            "histogram count must start at zero"
        );

        let request = mcp_authorize_request("github", "read_file");
        let _ = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;

        assert_eq!(
            state.metrics.authorize_duration.count(),
            1,
            "one authorize call must record exactly one observation"
        );

        let metrics_text = state.metrics.render_prometheus();
        assert!(
            metrics_text.contains("# TYPE aegis_authorize_duration_seconds histogram"),
            "metrics text must declare the histogram TYPE"
        );
        assert!(
            metrics_text.contains("aegis_authorize_duration_seconds_bucket{le=\"+Inf\"} 1"),
            "the +Inf bucket must include the one observation"
        );
        assert!(
            metrics_text.contains("aegis_authorize_duration_seconds_count 1"),
            "metrics text must include the observation count"
        );
        assert!(
            metrics_text.contains("aegis_authorize_duration_seconds_sum "),
            "metrics text must include the cumulative sum"
        );
    }

    // ── Security metrics tests ────────────────────────────────────────────────

    /// A mutating action from an untrusted-external source is denied by Cedar's
    /// "untrusted-mutation-forbid" rule AND increments `provenance_denials_total`.
    #[tokio::test]
    async fn provenance_denial_increments_counter() {
        use std::sync::atomic::Ordering;

        let (state, tenant_id, agent_token) = setup_state("provenance_denial_counter").await;

        let mut request = mcp_authorize_request("github", "push_commit");
        request.tool_call.mutates_state = true;
        request.context.source_trust = "untrusted_external".to_string();

        assert_eq!(
            state
                .metrics
                .provenance_denials_total
                .load(Ordering::Relaxed),
            0,
            "counter must start at zero"
        );

        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(
            response.decision, "deny",
            "untrusted mutating action must be denied"
        );

        assert_eq!(
            state
                .metrics
                .provenance_denials_total
                .load(Ordering::Relaxed),
            1,
            "provenance_denials_total must be 1 after one denied provenance"
        );

        let metrics_text = state.metrics.render_prometheus();
        assert!(
            metrics_text.contains("provenance_denials_total 1\n"),
            "metrics text must include updated counter value"
        );
        assert!(
            metrics_text.contains("# TYPE provenance_denials_total counter"),
            "metrics text must include TYPE declaration"
        );
    }

    /// All three untrusted levels increment the same counter.
    #[tokio::test]
    async fn provenance_denial_counter_accumulates() {
        use std::sync::atomic::Ordering;

        let (state, tenant_id, agent_token) = setup_state("provenance_denial_accumulates").await;

        for trust in &["untrusted_external", "malicious_suspected", "unknown"] {
            let mut req = mcp_authorize_request("github", "delete_branch");
            req.tool_call.mutates_state = true;
            req.context.source_trust = (*trust).to_string();
            let resp = call_authorize(state.clone(), &tenant_id, &agent_token, req).await;
            assert_eq!(resp.decision, "deny");
        }

        assert_eq!(
            state
                .metrics
                .provenance_denials_total
                .load(Ordering::Relaxed),
            3,
            "all three untrusted trust levels must increment the counter"
        );
    }

    /// A trusted-internal mutating action that is ALLOWED must NOT increment the counter.
    #[tokio::test]
    async fn trusted_mutating_action_does_not_increment_provenance_counter() {
        use std::sync::atomic::Ordering;

        let (state, tenant_id, agent_token) = setup_state("provenance_no_increment").await;

        let mut req = mcp_authorize_request("github", "push_commit");
        req.tool_call.mutates_state = true;
        req.context.source_trust = "trusted_internal_signed".to_string();
        let resp = call_authorize(state.clone(), &tenant_id, &agent_token, req).await;
        assert_ne!(resp.decision, "deny");

        assert_eq!(
            state
                .metrics
                .provenance_denials_total
                .load(Ordering::Relaxed),
            0,
            "trusted mutating actions must not touch the provenance counter"
        );
    }

    /// Hash mismatch on consume_approval increments approval_hash_mismatch_total
    /// and returns 409 CONFLICT, blocking execution (approve-then-swap defence).
    #[tokio::test]
    async fn hash_mismatch_on_consume_increments_counter() {
        use std::sync::atomic::Ordering;

        let (state, tenant_id, agent_token) = setup_state("hash_mismatch_counter").await;

        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/99".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        let approve = approve_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        assert_eq!(
            state
                .metrics
                .approval_hash_mismatch_total
                .load(Ordering::Relaxed),
            0
        );

        let mismatch_resp = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Some(Json(ConsumeApprovalBody {
                claimed_action_hash: Some(
                    "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                ),
            })),
        )
        .await
        .into_response();
        assert_eq!(
            mismatch_resp.status(),
            StatusCode::CONFLICT,
            "hash mismatch must return 409"
        );

        assert_eq!(
            state
                .metrics
                .approval_hash_mismatch_total
                .load(Ordering::Relaxed),
            1,
            "approval_hash_mismatch_total must be 1 after one swap attempt"
        );
    }

    // ── SOC Phase 5: Indexer route tests ─────────────────────────────────────

    /// list_alerts returns an empty array when no alerts exist, not an error.
    #[tokio::test]
    async fn list_alerts_empty_when_no_alerts() {
        let (state, tenant_id, _agent_token) = setup_state("alerts_empty").await;

        let response = list_alerts(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().is_empty());
    }

    /// list_incidents returns an empty array when no incidents exist.
    #[tokio::test]
    async fn list_incidents_empty_when_no_incidents() {
        let (state, tenant_id, _agent_token) = setup_state("incidents_empty").await;

        let response = list_incidents(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().is_empty());
    }

    /// Inserting a SOC alert directly into the DB then calling list_alerts via the
    /// route returns that alert scoped to the correct tenant.
    #[tokio::test]
    async fn list_alerts_returns_tenant_scoped_alerts() {
        let (state, tenant_id, _agent_token) = setup_state("alerts_tenant_route").await;

        // Directly seed an alert for the tenant.
        let alert = crate::models::SocAlertRecord {
            id: "route_alert_1".to_string(),
            tenant_id: tenant_id.clone(),
            rule: "confused_deputy_block".to_string(),
            severity: "high".to_string(),
            agent_id: "agent_route".to_string(),
            source_event_id: "evt_route_1".to_string(),
            summary: "Route test alert".to_string(),
            created_at: "2026-06-06T10:00:00Z".to_string(),
        };
        db::insert_soc_alert(&state.pool, &alert).await.unwrap();

        let response = list_alerts(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"], "route_alert_1");
        assert_eq!(arr[0]["rule"], "confused_deputy_block");
        assert_eq!(arr[0]["severity"], "high");
        assert_eq!(arr[0]["tenant_id"], tenant_id.as_str());
    }

    #[tokio::test]
    async fn test_list_agents_returns_tenant_scoped_and_paginated_agents() {
        let (state, tenant_id, _agent_token) = setup_state("list_agents_route").await;

        // Seed 3 agents for this tenant
        for idx in 1..=3 {
            let agent = AgentRecord {
                id: format!("agent_id_{}", idx),
                tenant_id: tenant_id.clone(),
                agent_key: format!("agent-key-{}", idx),
                agent_token: format!("agent-token-{}", idx),
                name: format!("Agent Name {}", idx),
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
                created_at: Utc::now() - Duration::hours(idx), // older first
                updated_at: Utc::now(),
            };
            db::insert_agent(&state.pool, &agent).await.unwrap();
        }

        // Seed an agent for another tenant to test isolation
        let other_tenant = "other_tenant_id".to_string();
        db::register_tenant(&state.pool, &other_tenant, "Other Tenant", "developer")
            .await
            .unwrap();
        let other_agent = AgentRecord {
            id: "other_agent_id".to_string(),
            tenant_id: other_tenant.clone(),
            agent_key: "other-agent-key".to_string(),
            agent_token: "other-agent-token".to_string(),
            name: "Other Agent Name".to_string(),
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
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db::insert_agent(&state.pool, &other_agent).await.unwrap();

        // 1. Check all agents for tenant_id (should be 4 total including the default setup agent)
        let response = list_agents(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        // 3 newly seeded agents + 1 setup agent = 4
        assert_eq!(arr.len(), 4);

        // 2. Check pagination (limit=2)
        let response_paginated = list_agents(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(Some("limit=2".to_string())),
        )
        .await
        .into_response();
        assert_eq!(response_paginated.status(), StatusCode::OK);
        let body_p = to_bytes(response_paginated.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_p: serde_json::Value = serde_json::from_slice(&body_p).unwrap();
        assert_eq!(json_p.as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_get_agent_detail_route() {
        let (state, tenant_id, _agent_token) = setup_state("get_agent_route").await;

        // Seed an agent
        let agent = AgentRecord {
            id: "get_agent_test_id".to_string(),
            tenant_id: tenant_id.clone(),
            agent_key: "get-agent-key".to_string(),
            agent_token: "get-agent-token".to_string(),
            name: "Get Agent Name".to_string(),
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
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db::insert_agent(&state.pool, &agent).await.unwrap();

        // 1. Fetch existing agent (should return 200)
        let response = get_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("get_agent_test_id".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let fetched: AgentRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(fetched.id, "get_agent_test_id");
        assert_eq!(fetched.name, "Get Agent Name");

        // 2. Fetch non-existing agent (should return 404)
        let response_404 = get_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("non_existent_id".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response_404.status(), StatusCode::NOT_FOUND);

        // 3. Fetch cross-tenant agent (should return 404)
        let other_tenant = "other_tenant_id".to_string();
        let response_cross = get_agent(
            State(state.clone()),
            TenantId(other_tenant),
            Path("get_agent_test_id".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response_cross.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_patch_agent_route() {
        let (state, tenant_id, _agent_token) = setup_state("patch_agent_route").await;

        // Seed an agent
        let agent = AgentRecord {
            id: "patch_agent_test_id".to_string(),
            tenant_id: tenant_id.clone(),
            agent_key: "patch-agent-key".to_string(),
            agent_token: "patch-agent-token".to_string(),
            name: "Original Name".to_string(),
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
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db::insert_agent(&state.pool, &agent).await.unwrap();

        // 1. Patch name and environment
        let patch_request = PatchAgentRequest {
            name: Some("Updated Name".to_string()),
            owner_team: Some("new-team".to_string()),
            owner_email: None,
            environment: Some("staging".to_string()),
            framework: None,
            model_provider: None,
            model_name: None,
            purpose: None,
            risk_tier: None,
            status: Some("frozen".to_string()),
        };

        let response = patch_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("patch_agent_test_id".to_string()),
            Json(patch_request),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let updated: AgentRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(updated.name, "Updated Name");
        assert_eq!(updated.owner_team, Some("new-team".to_string()));
        assert_eq!(updated.environment, "staging");
        assert_eq!(updated.status, "frozen");

        // Verify it was actually updated in the database
        let db_agent = db::get_agent_by_id(&state.pool, &tenant_id, "patch_agent_test_id")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(db_agent.name, "Updated Name");
        assert_eq!(db_agent.environment, "staging");
        assert_eq!(db_agent.status, "frozen");

        // 2. Patch non-existing agent (should return 404)
        let response_404 = patch_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("non_existent_id".to_string()),
            Json(PatchAgentRequest {
                name: Some("New Name".to_string()),
                owner_team: None,
                owner_email: None,
                environment: None,
                framework: None,
                model_provider: None,
                model_name: None,
                purpose: None,
                risk_tier: None,
                status: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response_404.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_agent_route() {
        let (state, tenant_id, _agent_token) = setup_state("delete_agent_route").await;

        // Seed an agent
        let agent = AgentRecord {
            id: "delete_agent_test_id".to_string(),
            tenant_id: tenant_id.clone(),
            agent_key: "delete-agent-key".to_string(),
            agent_token: "delete-agent-token".to_string(),
            name: "Delete Test Agent".to_string(),
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
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db::insert_agent(&state.pool, &agent).await.unwrap();

        // 1. Delete the agent
        let response = delete_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("delete_agent_test_id".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        // 2. Fetch the agent (should return 404 because it is soft-deleted)
        let response_get = get_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("delete_agent_test_id".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response_get.status(), StatusCode::NOT_FOUND);

        // 3. Delete non-existing agent (should return 404)
        let response_404 = delete_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("non_existent_id".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response_404.status(), StatusCode::NOT_FOUND);
    }

    /// Inserting a SOC incident directly then calling list_incidents via the route
    /// returns it tenant-scoped.
    #[tokio::test]
    async fn list_incidents_returns_tenant_scoped_incidents() {
        let (state, tenant_id, _agent_token) = setup_state("incidents_tenant_route").await;

        let source_ids = serde_json::to_string(&vec!["evt_1", "evt_2"]).unwrap();
        let incident = crate::models::SocIncidentRecord {
            id: "route_inc_1".to_string(),
            tenant_id: tenant_id.clone(),
            kind: "deny_storm".to_string(),
            severity: "high".to_string(),
            agent_id: "agent_route".to_string(),
            summary: "Route test incident".to_string(),
            source_event_ids: source_ids.clone(),
            opened_at: "2026-06-06T10:00:00Z".to_string(),
            status: "open".to_string(),
            closed_at: None,
        };
        db::insert_soc_incident(&state.pool, &incident)
            .await
            .unwrap();

        let response = list_incidents(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"], "route_inc_1");
        assert_eq!(arr[0]["kind"], "deny_storm");
        assert_eq!(arr[0]["tenant_id"], tenant_id.as_str());
    }

    /// parse_pagination caps limit at SOC_MAX_LIMIT and defaults correctly.
    #[test]
    fn parse_pagination_caps_and_defaults() {
        // No query string → defaults
        let (limit, offset) = parse_pagination(None);
        assert_eq!(limit, db::SOC_DEFAULT_LIMIT);
        assert_eq!(offset, 0);

        // Explicit small limit and offset
        let (limit, offset) = parse_pagination(Some("limit=10&offset=5"));
        assert_eq!(limit, 10);
        assert_eq!(offset, 5);

        // Exceeding max cap
        let (limit, _) = parse_pagination(Some("limit=99999"));
        assert_eq!(limit, db::SOC_MAX_LIMIT);

        // Zero limit → clamped to 1
        let (limit, _) = parse_pagination(Some("limit=0"));
        assert_eq!(limit, 1);

        // Negative offset → clamped to 0
        let (_, offset) = parse_pagination(Some("offset=-5"));
        assert_eq!(offset, 0);
    }

    // ── SOC Phase 6: narrate_incident route tests ─────────────────────────────

    /// Helper: insert a bare-minimum incident row for a tenant (no agent required).
    async fn insert_test_incident(
        pool: &sqlx::SqlitePool,
        tenant_id: &str,
        incident_id: &str,
        kind: &str,
    ) {
        let record = SocIncidentRecord {
            id: incident_id.to_string(),
            tenant_id: tenant_id.to_string(),
            kind: kind.to_string(),
            severity: "high".to_string(),
            agent_id: "agent-test".to_string(),
            summary: "Test incident for narration".to_string(),
            source_event_ids: serde_json::json!(["evt_a", "evt_b"]).to_string(),
            opened_at: "2026-06-06T12:00:00Z".to_string(),
            status: "open".to_string(),
            closed_at: None,
        };
        db::insert_soc_incident(pool, &record).await.unwrap();
    }

    #[tokio::test]
    async fn narrate_incident_returns_narrative_for_own_incident() {
        let (state, tenant_id, _agent_token) = setup_state("narrate_own").await;

        insert_test_incident(&state.pool, &tenant_id, "inc_narrate_1", "deny_storm").await;

        // Call the handler directly — same pattern used by all other route tests.
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", tenant_id).parse().unwrap(),
        );

        let response = narrate_incident(
            State(state),
            TenantId(tenant_id.clone()),
            Path("inc_narrate_1".to_string()),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(json["incident_id"], "inc_narrate_1");
        let narrative = json["narrative"].as_str().unwrap();
        // Default template must include the incident kind.
        assert!(
            narrative.contains("deny_storm"),
            "narrative must contain kind"
        );
    }

    #[tokio::test]
    async fn narrate_incident_returns_404_for_other_tenants_incident() {
        let (state, tenant_id, _agent_token) = setup_state("narrate_isolation").await;

        // Register a second tenant and insert the incident under it.
        let other_tenant = "tenant_other_narrator";
        db::register_tenant(&state.pool, other_tenant, "Other", "developer")
            .await
            .unwrap();
        insert_test_incident(&state.pool, other_tenant, "inc_other", "deny_storm").await;

        // Authenticate as our tenant and try to fetch the other tenant's incident.
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", tenant_id).parse().unwrap(),
        );

        let response = narrate_incident(
            State(state),
            TenantId(tenant_id.clone()),
            Path("inc_other".to_string()),
        )
        .await
        .into_response();

        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "must not expose another tenant's incident"
        );
    }

    // ── close_incident route tests ────────────────────────────────────────────

    /// Helper: close an incident via the route handler and parse the JSON body.
    async fn do_close(
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

    /// `POST /v1/incidents/:id/close` returns 200 with `status: "closed"` and a
    /// non-null `closed_at` for a persisted open incident owned by the tenant.
    #[tokio::test]
    async fn close_incident_returns_closed_for_own_incident() {
        let (state, tenant_id, _) = setup_state("close_own").await;
        insert_test_incident(&state.pool, &tenant_id, "inc_close_route_1", "deny_storm").await;

        let (status, json) = do_close(state, &tenant_id, "inc_close_route_1").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "closed");
        assert_eq!(json["incident_id"], "inc_close_route_1");
        assert!(
            !json["closed_at"].is_null(),
            "closed_at must be set after close"
        );
        assert_eq!(json["already_closed"], false);
    }

    /// `POST /v1/incidents/:id/close` returns 404 when the incident id belongs
    /// to a different tenant — tenant-isolation (CWE-284).
    #[tokio::test]
    async fn close_incident_returns_404_for_other_tenants_incident() {
        let (state, tenant_id, _) = setup_state("close_iso").await;

        let other_tenant = "tenant_other_close_iso";
        db::register_tenant(&state.pool, other_tenant, "Other", "developer")
            .await
            .unwrap();
        insert_test_incident(&state.pool, other_tenant, "inc_other_close", "deny_storm").await;

        let (status, json) = do_close(state, &tenant_id, "inc_other_close").await;

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "must not expose another tenant's incident"
        );
        assert!(json["error"].as_str().is_some());
    }

    /// A second `POST /v1/incidents/:id/close` is idempotent — returns 200 with
    /// `already_closed: true` and the original `closed_at` unchanged.
    #[tokio::test]
    async fn close_incident_is_idempotent() {
        let (state, tenant_id, _) = setup_state("close_idempotent_route").await;
        insert_test_incident(&state.pool, &tenant_id, "inc_idem_route", "replay_attempt").await;

        let (s1, j1) = do_close(state.clone(), &tenant_id, "inc_idem_route").await;
        assert_eq!(s1, StatusCode::OK);
        assert_eq!(j1["already_closed"], false);
        let first_closed_at = j1["closed_at"].as_str().unwrap().to_string();

        let (s2, j2) = do_close(state, &tenant_id, "inc_idem_route").await;
        assert_eq!(s2, StatusCode::OK, "second close must still be 200");
        assert_eq!(j2["already_closed"], true);
        assert_eq!(
            j2["closed_at"].as_str().unwrap(),
            first_closed_at,
            "closed_at must not change on second close"
        );
    }

    // ── SOC query layer: get_incident + soc_summary route tests ──────────────

    /// Helper: call GET /v1/incidents/:id and return (status, json body).
    async fn do_get_incident(
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

    /// GET /v1/incidents/:id returns 200 with the incident body for the owning tenant.
    #[tokio::test]
    async fn get_incident_returns_200_for_own_incident() {
        let (state, tenant_id, _) = setup_state("get_inc_own").await;
        insert_test_incident(&state.pool, &tenant_id, "inc_get_own", "deny_storm").await;

        let (status, json) = do_get_incident(state, &tenant_id, "inc_get_own").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["id"], "inc_get_own");
        assert_eq!(json["kind"], "deny_storm");
        assert_eq!(json["tenant_id"], tenant_id.as_str());
    }

    /// GET /v1/incidents/:id returns 404 for an unknown id.
    #[tokio::test]
    async fn get_incident_returns_404_for_unknown_id() {
        let (state, tenant_id, _) = setup_state("get_inc_missing").await;

        let (status, json) = do_get_incident(state, &tenant_id, "does_not_exist").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(json["error"].as_str().is_some());
    }

    /// GET /v1/incidents/:id returns 404 when the incident belongs to a different
    /// tenant — cross-tenant isolation (CWE-284).
    #[tokio::test]
    async fn get_incident_returns_404_cross_tenant() {
        let (state, tenant_id_a, _) = setup_state("get_inc_cross_tenant").await;
        // Register a second tenant and insert an incident under it.
        let tenant_id_b = format!("tenant_b_{}", uuid::Uuid::new_v4().simple());
        db::register_tenant(&state.pool, &tenant_id_b, "Tenant B", "developer")
            .await
            .unwrap();
        db::insert_soc_incident(
            &state.pool,
            &SocIncidentRecord {
                id: "inc_other_tenant".to_string(),
                tenant_id: tenant_id_b.clone(),
                kind: "deny_storm".to_string(),
                severity: "high".to_string(),
                agent_id: "agent-b".to_string(),
                summary: "B's incident".to_string(),
                source_event_ids: serde_json::json!(["e1"]).to_string(),
                opened_at: "2026-06-06T12:00:00Z".to_string(),
                status: "open".to_string(),
                closed_at: None,
            },
        )
        .await
        .unwrap();

        // tenant_a must get 404, not tenant_b's data.
        let (status, _) = do_get_incident(state, &tenant_id_a, "inc_other_tenant").await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "cross-tenant incident must return 404"
        );
    }

    /// GET /v1/alerts?severity=high only returns high-severity alerts (route-level).
    #[tokio::test]
    async fn list_alerts_severity_filter_via_route() {
        let (state, tenant_id, _) = setup_state("alerts_sev_route").await;

        // Insert 1 high + 1 low alert.
        db::insert_soc_alert(
            &state.pool,
            &SocAlertRecord {
                id: "ra_high".to_string(),
                tenant_id: tenant_id.clone(),
                rule: "r1".to_string(),
                severity: "high".to_string(),
                agent_id: "ag1".to_string(),
                source_event_id: "evt1".to_string(),
                summary: "High alert".to_string(),
                created_at: "2026-06-06T10:00:00Z".to_string(),
            },
        )
        .await
        .unwrap();
        db::insert_soc_alert(
            &state.pool,
            &SocAlertRecord {
                id: "ra_low".to_string(),
                tenant_id: tenant_id.clone(),
                rule: "r2".to_string(),
                severity: "low".to_string(),
                agent_id: "ag1".to_string(),
                source_event_id: "evt2".to_string(),
                summary: "Low alert".to_string(),
                created_at: "2026-06-06T10:01:00Z".to_string(),
            },
        )
        .await
        .unwrap();

        let response = list_alerts(
            State(state),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(Some("severity=high".to_string())),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let arr: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = arr.as_array().unwrap();
        assert_eq!(arr.len(), 1, "only 1 high-severity alert");
        assert_eq!(arr[0]["id"], "ra_high");
        assert_eq!(arr[0]["severity"], "high");
    }

    /// GET /v1/soc/summary returns correct aggregate counts for the tenant.
    #[tokio::test]
    async fn soc_summary_returns_correct_counts() {
        let (state, tenant_id, _) = setup_state("soc_summary_route").await;

        // Seed: 2 alerts (1 high, 1 medium), 2 incidents (1 open, 1 closed).
        db::insert_soc_alert(
            &state.pool,
            &SocAlertRecord {
                id: "ss_a1".to_string(),
                tenant_id: tenant_id.clone(),
                rule: "r1".to_string(),
                severity: "high".to_string(),
                agent_id: "ag1".to_string(),
                source_event_id: "evt1".to_string(),
                summary: "High".to_string(),
                created_at: "2026-06-06T10:00:00Z".to_string(),
            },
        )
        .await
        .unwrap();
        db::insert_soc_alert(
            &state.pool,
            &SocAlertRecord {
                id: "ss_a2".to_string(),
                tenant_id: tenant_id.clone(),
                rule: "r2".to_string(),
                severity: "medium".to_string(),
                agent_id: "ag1".to_string(),
                source_event_id: "evt2".to_string(),
                summary: "Medium".to_string(),
                created_at: "2026-06-06T10:01:00Z".to_string(),
            },
        )
        .await
        .unwrap();
        insert_test_incident(&state.pool, &tenant_id, "ss_i1", "deny_storm").await;
        insert_test_incident(&state.pool, &tenant_id, "ss_i2", "exfil").await;
        db::close_soc_incident(&state.pool, &tenant_id, "ss_i2")
            .await
            .unwrap();

        let response = soc_summary(State(state), TenantId(tenant_id.clone()))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["alerts_total"], 2);
        assert_eq!(json["alerts_high"], 1);
        assert_eq!(json["incidents_total"], 2);
        assert_eq!(json["incidents_open"], 1);
        assert_eq!(json["incidents_closed"], 1);
    }

    /// GET /v1/soc/summary for a tenant with no data returns all-zero counts.
    #[tokio::test]
    async fn soc_summary_returns_zeros_when_empty() {
        let (state, tenant_id, _) = setup_state("soc_summary_empty").await;

        let response = soc_summary(State(state), TenantId(tenant_id.clone()))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["alerts_total"], 0);
        assert_eq!(json["alerts_high"], 0);
        assert_eq!(json["incidents_total"], 0);
        assert_eq!(json["incidents_open"], 0);
        assert_eq!(json["incidents_closed"], 0);
    }

    // --- MCP tool-manifest drift (SOC `mcp_manifest_drift`) ---

    fn drift_tool(tool_key: &str, risk: &str) -> McpToolManifestItem {
        McpToolManifestItem {
            tool_key: tool_key.to_string(),
            name: format!("Tool {}", tool_key),
            description: None,
            input_schema: None,
            risk: risk.to_string(),
            mutates_state: false,
            approval_required: false,
        }
    }

    /// The manifest hash is order-independent (discovery order must not matter) but
    /// sensitive to any security-relevant field change (e.g. a tool's risk level).
    #[test]
    fn mcp_manifest_hash_is_order_independent_and_change_sensitive() {
        let a = vec![
            drift_tool("create_issue", "medium"),
            drift_tool("merge", "high"),
        ];
        let b = vec![
            drift_tool("merge", "high"),
            drift_tool("create_issue", "medium"),
        ];
        assert_eq!(
            compute_mcp_manifest_hash(&a),
            compute_mcp_manifest_hash(&b),
            "reordering tools must not change the manifest hash"
        );

        let c = vec![
            drift_tool("create_issue", "critical"),
            drift_tool("merge", "high"),
        ];
        assert_ne!(
            compute_mcp_manifest_hash(&a),
            compute_mcp_manifest_hash(&c),
            "changing a tool's risk must change the manifest hash"
        );

        assert!(compute_mcp_manifest_hash(&a).starts_with("sha256:"));
    }

    /// Re-discovering a server whose advertised manifest changed must emit a
    /// `mcp_manifest_drift` AseEvent onto the SOC stream (and only on change).
    #[tokio::test]
    async fn discover_emits_manifest_drift_only_when_manifest_changes() {
        let (state, tenant_id, _agent_token, mut events_rx) =
            setup_state_with_events("mcp_drift").await;
        db::upsert_mcp_server(
            &state.pool,
            &tenant_id,
            "github-mcp",
            "GitHub MCP",
            Some("platform"),
            "http",
            Some("internal-registry"),
            "trusted_internal_signed",
            "http://127.0.0.1:9001/mcp",
        )
        .await
        .unwrap();

        // 1) First discovery pins the manifest — no drift.
        let req1 = DiscoverMcpToolsRequest {
            tools: vec![drift_tool("create_issue", "medium")],
        };
        discover_mcp_tools(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
            Json(req1),
        )
        .await;

        // 2) Identical re-discovery — still no drift.
        let req2 = DiscoverMcpToolsRequest {
            tools: vec![drift_tool("create_issue", "medium")],
        };
        discover_mcp_tools(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
            Json(req2),
        )
        .await;

        // 3) Changed manifest (risk escalated) — must drift.
        let req3 = DiscoverMcpToolsRequest {
            tools: vec![drift_tool("create_issue", "critical")],
        };
        discover_mcp_tools(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
            Json(req3),
        )
        .await;

        let mut drift_events = 0;
        while let Ok(ev) = events_rx.try_recv() {
            if ev.kind == "mcp_manifest_drift" {
                assert_eq!(ev.tenant_id, tenant_id);
                assert_eq!(ev.decision, "flag");
                assert_eq!(ev.resource.as_deref(), Some("github-mcp"));
                assert_eq!(ev.tool, "mcp:github-mcp");
                drift_events += 1;
            }
        }
        assert_eq!(
            drift_events, 1,
            "exactly one drift event — pinned first, silent on identical, fires on change"
        );

        // The new manifest is now pinned (re-pinned on drift).
        let pinned = db::get_mcp_server_manifest_hash(&state.pool, &tenant_id, "github-mcp")
            .await
            .unwrap();
        let expected = compute_mcp_manifest_hash(&[drift_tool("create_issue", "critical")]);
        assert_eq!(pinned, expected);

        // Fail-closed response: drift must auto-quarantine the server.
        let server = db::get_mcp_server_by_key(&state.pool, &tenant_id, "github-mcp")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(server.status, "quarantined");
    }

    /// DB-007 (#932): `last_discovery_at` is `None` until the first discovery
    /// call, then set (and bumped on every subsequent discovery).
    #[tokio::test]
    async fn discover_sets_last_discovery_at_timestamp() {
        let (state, tenant_id, _agent_token, _events_rx) =
            setup_state_with_events("mcp_last_discovery_at").await;
        db::upsert_mcp_server(
            &state.pool,
            &tenant_id,
            "github-mcp",
            "GitHub MCP",
            Some("platform"),
            "http",
            Some("internal-registry"),
            "trusted_internal_signed",
            "http://127.0.0.1:9001/mcp",
        )
        .await
        .unwrap();

        let before = db::get_mcp_server_by_key(&state.pool, &tenant_id, "github-mcp")
            .await
            .unwrap()
            .unwrap();
        assert!(
            before.last_discovery_at.is_none(),
            "no discovery has run yet"
        );

        let req = DiscoverMcpToolsRequest {
            tools: vec![drift_tool("create_issue", "medium")],
        };
        discover_mcp_tools(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
            Json(req),
        )
        .await;

        let after = db::get_mcp_server_by_key(&state.pool, &tenant_id, "github-mcp")
            .await
            .unwrap()
            .unwrap();
        assert!(
            after.last_discovery_at.is_some(),
            "discovery must stamp last_discovery_at"
        );
    }

    /// A quarantined MCP server must deny an otherwise-approved tool inline
    /// (Phase 4 response enforcement). Before this, quarantine was recorded but
    /// never checked on the authorize hot path.
    #[tokio::test]
    async fn quarantined_mcp_server_denies_approved_tool() {
        let (state, tenant_id, agent_token) = setup_state("mcp_quarantine_enforced").await;
        let server_id = db::upsert_mcp_server(
            &state.pool,
            &tenant_id,
            "github-mcp",
            "GitHub MCP",
            Some("platform"),
            "http",
            Some("internal-registry"),
            "trusted_internal_signed",
            "http://127.0.0.1:9001/mcp",
        )
        .await
        .unwrap();
        let tool = McpToolManifestItem {
            tool_key: "create_issue".to_string(),
            name: "Create issue".to_string(),
            description: None,
            input_schema: None,
            risk: "medium".to_string(),
            mutates_state: false,
            approval_required: false,
        };
        db::upsert_mcp_tool(&state.pool, &tenant_id, &server_id, &tool)
            .await
            .unwrap();
        db::set_mcp_tool_status(
            &state.pool,
            &tenant_id,
            "github-mcp",
            "create_issue",
            "approved",
        )
        .await
        .unwrap();

        // Baseline: the approved tool authorizes while the server is active.
        let allowed = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            mcp_authorize_request("mcp:github-mcp", "create_issue"),
        )
        .await;
        assert_eq!(allowed.decision, "allow");

        // Quarantine the server — the same approved tool must now be denied.
        assert!(
            db::set_mcp_server_status(&state.pool, &tenant_id, "github-mcp", "quarantined")
                .await
                .unwrap()
        );
        let denied = call_authorize(
            state,
            &tenant_id,
            &agent_token,
            mcp_authorize_request("mcp:github-mcp", "create_issue"),
        )
        .await;
        assert_eq!(denied.decision, "deny");
        assert!(denied
            .matched_policies
            .contains(&"mcp_server_quarantined".to_string()));
    }

    #[tokio::test]
    async fn authorize_action_denies_frozen_and_revoked_agent() {
        let (state, tenant_id, agent_token) = setup_state("agent_frozen_revoked").await;

        let agent = db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap();
        let agent_id = agent.id;

        // Baseline: active agent should be allowed
        let request = mcp_authorize_request("filesystem", "read_file");
        let allowed =
            call_authorize(state.clone(), &tenant_id, &agent_token, request.clone()).await;
        assert_eq!(allowed.decision, "allow");

        // Freeze the agent
        assert!(
            db::set_agent_status(&state.pool, &tenant_id, &agent_id, "frozen")
                .await
                .unwrap()
        );

        // Frozen agent should be denied
        let frozen_denied =
            call_authorize(state.clone(), &tenant_id, &agent_token, request.clone()).await;
        assert_eq!(frozen_denied.decision, "deny");
        assert!(frozen_denied
            .matched_policies
            .contains(&"agent_frozen".to_string()));

        // Revoke the agent
        assert!(
            db::set_agent_status(&state.pool, &tenant_id, &agent_id, "revoked")
                .await
                .unwrap()
        );

        // Revoked agent should be denied
        let revoked_denied =
            call_authorize(state.clone(), &tenant_id, &agent_token, request.clone()).await;
        assert_eq!(revoked_denied.decision, "deny");
        assert!(revoked_denied
            .matched_policies
            .contains(&"agent_revoked".to_string()));
    }

    /// #1184 (Phase 4 response engine completion): once `agents.force_approval`
    /// is set (e.g. by the SOC Response Engine after a `trust_escalation`
    /// incident), every otherwise-`allow` decision for that agent is downgraded
    /// to `require_approval` until an operator clears it.
    #[tokio::test]
    async fn force_approval_agent_downgrades_allow_to_require_approval() {
        let (state, tenant_id, agent_token) = setup_state("agent_force_approval").await;

        let agent = db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap();
        let agent_id = agent.id;

        let request = mcp_authorize_request("filesystem", "read_file");

        // Baseline: active agent, normally-allowed action.
        let allowed =
            call_authorize(state.clone(), &tenant_id, &agent_token, request.clone()).await;
        assert_eq!(allowed.decision, "allow");

        // Simulate the Response Engine setting force_approval after a
        // trust_escalation incident.
        db::set_agent_force_approval(&state.pool, &tenant_id, &agent_id, true)
            .await
            .unwrap();

        let downgraded =
            call_authorize(state.clone(), &tenant_id, &agent_token, request.clone()).await;
        assert_eq!(downgraded.decision, "require_approval");
        assert!(downgraded
            .matched_policies
            .contains(&"soc_response_force_approval".to_string()));

        // Clearing force_approval restores the normal allow decision.
        db::set_agent_force_approval(&state.pool, &tenant_id, &agent_id, false)
            .await
            .unwrap();
        let restored = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(restored.decision, "allow");
    }

    /// #0078-#0080: agent lifecycle columns. `last_seen_at` is a heartbeat updated
    /// on every authorize call; `freeze_agent` records an operator-supplied
    /// `frozen_reason` that is cleared on unfreeze; `quarantined_at` is set when
    /// status transitions to `quarantined` and cleared on any other transition.
    #[tokio::test]
    async fn agent_lifecycle_columns_are_populated_and_cleared() {
        let (state, tenant_id, agent_token) = setup_state("agent_lifecycle").await;
        let agent = db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap();
        let agent_id = agent.id.clone();
        assert!(agent.last_seen_at.is_none());

        // last_seen_at: populated by a successful authorize call.
        let request = mcp_authorize_request("filesystem", "read_file");
        let _ = call_authorize(state.clone(), &tenant_id, &agent_token, request.clone()).await;
        let agent = db::get_agent_by_id(&state.pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert!(agent.last_seen_at.is_some());

        // frozen_reason: set via freeze_agent's optional body, cleared on unfreeze.
        let resp = freeze_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(agent_id.clone()),
            Some(Json(FreezeAgentRequest {
                reason: Some("compromised credentials".to_string()),
            })),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let agent = db::get_agent_by_id(&state.pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(agent.status, "frozen");
        assert_eq!(
            agent.frozen_reason.as_deref(),
            Some("compromised credentials")
        );

        let _ = unfreeze_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(agent_id.clone()),
        )
        .await
        .into_response();
        let agent = db::get_agent_by_id(&state.pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(agent.status, "active");
        assert!(agent.frozen_reason.is_none());

        // quarantined_at: set on transition to quarantined, cleared on transition out.
        assert!(
            db::set_agent_status(&state.pool, &tenant_id, &agent_id, "quarantined")
                .await
                .unwrap()
        );
        let agent = db::get_agent_by_id(&state.pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(agent.status, "quarantined");
        assert!(agent.quarantined_at.is_some());

        assert!(
            db::set_agent_status(&state.pool, &tenant_id, &agent_id, "active")
                .await
                .unwrap()
        );
        let agent = db::get_agent_by_id(&state.pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(agent.status, "active");
        assert!(agent.quarantined_at.is_none());
    }

    /// #0141: revoke_agent permanently sets the agent's status to "revoked".
    #[tokio::test]
    async fn revoke_agent_sets_status_to_revoked() {
        let (state, tenant_id, agent_token) = setup_state("revoke_agent_status").await;
        let agent = db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap();
        let agent_id = agent.id;

        let resp = revoke_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(agent_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let agent = db::get_agent_by_id(&state.pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(agent.status, "revoked");
    }

    /// #0142: quarantine_mcp_server sets the MCP server's status to
    /// "quarantined", retrievable via db::get_mcp_server_by_key.
    #[tokio::test]
    async fn quarantine_mcp_server_sets_status_to_quarantined() {
        let (state, tenant_id, _agent_token) = setup_state("quarantine_mcp_server_status").await;
        db::upsert_mcp_server(
            &state.pool,
            &tenant_id,
            "github-mcp",
            "GitHub MCP",
            Some("platform"),
            "http",
            Some("internal-registry"),
            "trusted_internal_signed",
            "http://127.0.0.1:9001/mcp",
        )
        .await
        .unwrap();

        let resp = quarantine_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let server = db::get_mcp_server_by_key(&state.pool, &tenant_id, "github-mcp")
            .await
            .unwrap()
            .expect("server should exist");
        assert_eq!(server.status, "quarantined");
    }

    #[tokio::test]
    async fn test_list_and_get_decisions_route() {
        let (state, tenant_id, agent_token) = setup_state("list_get_decisions").await;
        let agent = db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap();
        let agent_id = agent.id;

        let agent_id2 = Uuid::new_v4().to_string();
        let agent2 = AgentRecord {
            id: agent_id2.clone(),
            tenant_id: tenant_id.clone(),
            agent_key: "second-agent".to_string(),
            agent_token: "tok_2".to_string(),
            name: "Second Agent".to_string(),
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
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db::insert_agent(&state.pool, &agent2).await.unwrap();

        let decision_id1 = Uuid::new_v4().to_string();
        let record1 = DecisionRecord {
            id: decision_id1.clone(),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            user_id: Some("user_1".to_string()),
            run_id: Some("run_1".to_string()),
            trace_id: Some("trace_1".to_string()),
            skill: "fs".to_string(),
            action: "read".to_string(),
            resource: Some("foo.txt".to_string()),
            input_json: "{}".to_string(),
            decision: "allow".to_string(),
            risk_score: Some(1),
            reason: Some("ok".to_string()),
            matched_policy_ids: None,
            request_id: None,
            latency_ms: None,
            created_at: Utc::now(),
        };
        db::insert_decision(&state.pool, &record1).await.unwrap();

        let decision_id2 = Uuid::new_v4().to_string();
        let record2 = DecisionRecord {
            id: decision_id2.clone(),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id2.clone(),
            user_id: Some("user_2".to_string()),
            run_id: Some("run_2".to_string()),
            trace_id: Some("trace_2".to_string()),
            skill: "http".to_string(),
            action: "get".to_string(),
            resource: Some("http://example.com".to_string()),
            input_json: "{}".to_string(),
            decision: "deny".to_string(),
            risk_score: Some(10),
            reason: Some("bad site".to_string()),
            matched_policy_ids: None,
            request_id: None,
            latency_ms: None,
            created_at: Utc::now() - Duration::seconds(10),
        };
        db::insert_decision(&state.pool, &record2).await.unwrap();

        // 1. List decisions without filters
        let response = list_decisions(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let list = json.as_array().unwrap();
        assert_eq!(list.len(), 2);
        // Order is newest first, so record1 (created Utc::now()) should be first
        assert_eq!(list[0]["id"].as_str(), Some(decision_id1.as_str()));
        assert_eq!(list[1]["id"].as_str(), Some(decision_id2.as_str()));

        // 2. List decisions with filter: agent_id
        let response_filter = list_decisions(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(Some(format!("agent_id={}", agent_id2))),
        )
        .await
        .into_response();
        assert_eq!(response_filter.status(), StatusCode::OK);
        let body_filter = to_bytes(response_filter.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_filter: serde_json::Value = serde_json::from_slice(&body_filter).unwrap();
        let list_filter = json_filter.as_array().unwrap();
        assert_eq!(list_filter.len(), 1);
        assert_eq!(list_filter[0]["id"].as_str(), Some(decision_id2.as_str()));

        // 3. Get decision detail success
        let response_detail = get_decision(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(decision_id1.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_detail.status(), StatusCode::OK);
        let body_detail = to_bytes(response_detail.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_detail: serde_json::Value = serde_json::from_slice(&body_detail).unwrap();
        assert_eq!(json_detail["id"].as_str(), Some(decision_id1.as_str()));

        // 4. Get decision detail cross-tenant (should return 404)
        let other_tenant = "tenant_other_decisions";
        db::register_tenant(&state.pool, other_tenant, "Other Tenant", "developer")
            .await
            .unwrap();
        let response_cross = get_decision(
            State(state.clone()),
            TenantId(other_tenant.to_string()),
            Path(decision_id1.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_cross.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list_approvals_route() {
        let (state, tenant_id, agent_token) = setup_state("list_approvals").await;
        let agent = db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap();
        let agent_id = agent.id;

        let decision_id1 = Uuid::new_v4().to_string();
        let record_dec = DecisionRecord {
            id: decision_id1.clone(),
            tenant_id: tenant_id.clone(),
            agent_id,
            user_id: None,
            run_id: None,
            trace_id: None,
            skill: "fs".to_string(),
            action: "write".to_string(),
            resource: None,
            input_json: "{}".to_string(),
            decision: "require_approval".to_string(),
            risk_score: None,
            reason: None,
            matched_policy_ids: None,
            request_id: None,
            latency_ms: None,
            created_at: Utc::now(),
        };
        db::insert_decision(&state.pool, &record_dec).await.unwrap();

        let approval_id1 = Uuid::new_v4().to_string();
        let record1 = ApprovalRecord {
            id: approval_id1.clone(),
            tenant_id: tenant_id.clone(),
            decision_id: decision_id1.clone(),
            status: "created".to_string(),
            approver_group: None,
            approver_user_id: None,
            reason: None,
            original_skill_call: "{}".to_string(),
            original_call_hash: "hash1".to_string(),
            edited_skill_call: None,
            expires_at: Some(Utc::now() + Duration::minutes(10)),
            decided_at: None,
            callback_url: None,
            callback_secret_hash: None,
            created_at: Utc::now(),
        };
        db::insert_approval(&state.pool, &record1).await.unwrap();

        // Expired approval
        let approval_id2 = Uuid::new_v4().to_string();
        let record2 = ApprovalRecord {
            id: approval_id2.clone(),
            tenant_id: tenant_id.clone(),
            decision_id: decision_id1.clone(),
            status: "created".to_string(),
            approver_group: None,
            approver_user_id: None,
            reason: None,
            original_skill_call: "{}".to_string(),
            original_call_hash: "hash2".to_string(),
            edited_skill_call: None,
            expires_at: Some(Utc::now() - Duration::minutes(10)),
            decided_at: None,
            callback_url: None,
            callback_secret_hash: None,
            created_at: Utc::now() - Duration::minutes(10),
        };
        db::insert_approval(&state.pool, &record2).await.unwrap();

        // 1. List approvals (should only return non-expired record1)
        let response = list_approvals(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let list = json.as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["approval_id"].as_str(), Some(approval_id1.as_str()));
    }

    /// #0145: tenant isolation — an approval created under tenant A is invisible
    /// (404) to tenant B via GET /v1/approvals/:id, and is excluded from
    /// tenant B's GET /v1/approvals listing.
    #[tokio::test]
    async fn get_approval_returns_404_cross_tenant() {
        let (state, tenant_a, agent_token) = setup_state("approval_cross_tenant").await;
        let (approval_id, _hash) =
            create_pending_approval(&state, &tenant_a, &agent_token, "40").await;

        let tenant_b = format!("tenant_b_{}", Uuid::new_v4().simple());
        db::register_tenant(&state.pool, &tenant_b, "Tenant B", "developer")
            .await
            .unwrap();

        // Owning tenant can fetch it.
        let own = get_approval(
            State(state.clone()),
            TenantId(tenant_a.clone()),
            Path(approval_id),
        )
        .await
        .into_response();
        assert_eq!(own.status(), StatusCode::OK);

        // Cross-tenant fetch returns 404, not the other tenant's approval.
        let cross = get_approval(
            State(state.clone()),
            TenantId(tenant_b.clone()),
            Path(approval_id),
        )
        .await
        .into_response();
        assert_eq!(cross.status(), StatusCode::NOT_FOUND);

        // Cross-tenant listing must not include tenant A's approval.
        let list_response = list_approvals(
            State(state.clone()),
            TenantId(tenant_b),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(list_response.status(), StatusCode::OK);
        let body = to_bytes(list_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_list_and_get_receipts_route() {
        let (state, tenant_id, _) = setup_state("list_get_receipts").await;

        let rec = db::append_action_receipt_atomic(&state.pool, &tenant_id, |prev| {
            let mut r = unsigned_receipt_template(&tenant_id);
            r.prev_receipt_hash = prev;
            r.receipt_hash = compute_receipt_hash(&r);
            r
        })
        .await
        .unwrap();

        // 1. List receipts
        let response = list_receipts(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let list = json.as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["id"].as_str(), Some(rec.id.as_str()));

        // 2. Get receipt detail success
        let response_detail = get_receipt(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(rec.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_detail.status(), StatusCode::OK);
        let body_detail = to_bytes(response_detail.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_detail: serde_json::Value = serde_json::from_slice(&body_detail).unwrap();
        assert_eq!(json_detail["id"].as_str(), Some(rec.id.as_str()));

        // 3. Get receipt detail cross-tenant (should return 404)
        let other_tenant = "tenant_other_receipts";
        db::register_tenant(&state.pool, other_tenant, "Other Tenant", "developer")
            .await
            .unwrap();
        let response_cross = get_receipt(
            State(state.clone()),
            TenantId(other_tenant.to_string()),
            Path(rec.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_cross.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_verify_receipt_chain_route() {
        let (state, tenant_id, _) = setup_state("verify_chain_route").await;

        let corpus_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/receipt_chain_vectors.json"
        );
        let raw = std::fs::read_to_string(corpus_path).expect("shared receipt corpus must exist");
        let corpus: Value = serde_json::from_str(&raw).unwrap();
        let receipts = corpus["receipts"].as_array().unwrap().clone();

        // 1. Verify successful corpus chain
        let payload = VerifyChainRequest {
            receipts: receipts.clone(),
        };
        let response = verify_receipt_chain(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["verified"].as_bool(), Some(true));

        // 2. Tampered field (hash mismatch)
        let mut tampered_receipts = receipts.clone();
        if let Some(obj) = tampered_receipts[1].as_object_mut() {
            obj.insert("action".to_string(), json!("delete_repo"));
        }
        let payload_tampered = VerifyChainRequest {
            receipts: tampered_receipts,
        };
        let response_tampered = verify_receipt_chain(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload_tampered),
        )
        .await
        .into_response();
        assert_eq!(response_tampered.status(), StatusCode::OK);
        let body_tampered = to_bytes(response_tampered.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_tampered: Value = serde_json::from_slice(&body_tampered).unwrap();
        assert_eq!(json_tampered["verified"].as_bool(), Some(false));

        // 3. Mismatched tenant validation
        let mut tenant_receipts = receipts.clone();
        if let Some(obj) = tenant_receipts[0].as_object_mut() {
            obj.insert("tenant_id".to_string(), json!("tenant_other"));
        }
        let payload_tenant = VerifyChainRequest {
            receipts: tenant_receipts,
        };
        let response_tenant = verify_receipt_chain(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload_tenant),
        )
        .await
        .into_response();
        assert_eq!(response_tenant.status(), StatusCode::OK);
        let body_tenant = to_bytes(response_tenant.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_tenant: Value = serde_json::from_slice(&body_tenant).unwrap();
        assert_eq!(json_tenant["verified"].as_bool(), Some(false));
    }

    #[tokio::test]
    async fn test_policy_crud_and_reload_route() {
        let (state, tenant_id, _) = setup_state("policy_crud_reload").await;

        // 1. List policies (initially empty)
        let response = list_policies(State(state.clone()), TenantId(tenant_id.clone()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().is_empty());

        // 2. Create custom Cedar policy
        let payload = CreatePolicyRequest {
            policy_key: "allow-all".to_string(),
            name: "Allow All".to_string(),
            body: "permit (principal, action, resource);".to_string(),
        };
        let response_create = create_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload),
        )
        .await
        .into_response();
        assert_eq!(response_create.status(), StatusCode::CREATED);
        let body_create = to_bytes(response_create.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_create: Value = serde_json::from_slice(&body_create).unwrap();
        let policy_id = json_create["id"].as_str().unwrap().to_string();

        // 3. Create invalid policy (should return 400)
        let payload_invalid = CreatePolicyRequest {
            policy_key: "invalid".to_string(),
            name: "Invalid".to_string(),
            body: "permit (invalid syntax);".to_string(),
        };
        let response_invalid = create_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload_invalid),
        )
        .await
        .into_response();
        assert_eq!(response_invalid.status(), StatusCode::BAD_REQUEST);

        // 4. List policies (should contain 1 policy)
        let response_list = list_policies(State(state.clone()), TenantId(tenant_id.clone()))
            .await
            .into_response();
        assert_eq!(response_list.status(), StatusCode::OK);
        let body_list = to_bytes(response_list.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_list: Value = serde_json::from_slice(&body_list).unwrap();
        assert_eq!(json_list.as_array().unwrap().len(), 1);

        // 5. Update policy (change status to inactive)
        let payload_update = UpdatePolicyRequest {
            policy_key: None,
            name: None,
            body: None,
            status: Some("inactive".to_string()),
        };
        let response_update = update_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(policy_id.clone()),
            Json(payload_update),
        )
        .await
        .into_response();
        assert_eq!(response_update.status(), StatusCode::OK);

        // 6. Delete policy
        let response_delete = delete_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(policy_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_delete.status(), StatusCode::OK);

        // 7. Delete non-existent policy (should return 404)
        let response_delete_404 = delete_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(policy_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_delete_404.status(), StatusCode::NOT_FOUND);
    }

    /// SOC-004 (#1187): `POST /v1/ingest` normalizes a GitHub webhook payload,
    /// emits it onto the SOC event stream, and the drain task's behavioral
    /// baseline records it as the agent's first-ever (tool, action) — proving
    /// the ingested event flows through the same pipeline as `/v1/authorize`.
    #[tokio::test]
    async fn test_ingest_github_webhook_route() {
        let (state, tenant_id, _) = setup_state("ingest_github_webhook").await;

        let payload = IngestRequest {
            source: "github_webhook".to_string(),
            payload: serde_json::json!({
                "action": "opened",
                "repository": {"full_name": "lavkushry/AegisAgent"},
                "sender": {"login": "alice"}
            }),
        };

        let response = ingest_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        // Give the background drain task a moment to persist the alert.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let alerts = db::list_soc_alerts(&state.pool, &tenant_id, 10, 0, None, None)
            .await
            .unwrap();
        assert!(
            alerts
                .iter()
                .any(|a| a.rule == "behavioral_anomaly_new_tool" && a.agent_id == "alice"),
            "expected the ingested github event to flow through the SOC pipeline, got: {alerts:?}"
        );
    }

    /// SOC-004 (#1187): an unsupported `source` is rejected with 400.
    #[tokio::test]
    async fn test_ingest_rejects_unsupported_source() {
        let (state, tenant_id, _) = setup_state("ingest_unsupported_source").await;

        let payload = IngestRequest {
            source: "slack_webhook".to_string(),
            payload: serde_json::json!({}),
        };

        let response = ingest_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// SOC-004 (#1187): a payload missing required fields for the chosen
    /// source is rejected with 400 rather than emitting a malformed event.
    #[tokio::test]
    async fn test_ingest_rejects_unnormalizable_payload() {
        let (state, tenant_id, _) = setup_state("ingest_bad_payload").await;

        let payload = IngestRequest {
            source: "github_webhook".to_string(),
            payload: serde_json::json!({"foo": "bar"}),
        };

        let response = ingest_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_tenant_crud_route() {
        let (state, tenant_id, _) = setup_state("tenant_crud_route").await;

        // 1. Create a new tenant
        let new_tenant_id = "tenant_test_xyz";
        let create_payload = CreateTenantRequest {
            id: new_tenant_id.to_string(),
            name: "XYZ Corporation".to_string(),
            plan: "enterprise".to_string(),
        };

        let create_resp = create_tenant(State(state.clone()), Json(create_payload))
            .await
            .into_response();
        assert_eq!(create_resp.status(), StatusCode::CREATED);
        let body = to_bytes(create_resp.into_body(), usize::MAX).await.unwrap();
        let record: TenantRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(record.id, new_tenant_id);
        assert_eq!(record.name, "XYZ Corporation");
        assert_eq!(record.plan, "enterprise");

        // 2. Create again (should conflict)
        let create_payload_dup = CreateTenantRequest {
            id: new_tenant_id.to_string(),
            name: "XYZ Corporation".to_string(),
            plan: "enterprise".to_string(),
        };
        let create_resp_dup = create_tenant(State(state.clone()), Json(create_payload_dup))
            .await
            .into_response();
        assert_eq!(create_resp_dup.status(), StatusCode::CONFLICT);

        // 3. Get tenant info
        let get_resp = get_tenant(
            State(state.clone()),
            TenantId(new_tenant_id.to_string()),
            Path(new_tenant_id.to_string()),
        )
        .await
        .into_response();
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body_get = to_bytes(get_resp.into_body(), usize::MAX).await.unwrap();
        let record_get: TenantRecord = serde_json::from_slice(&body_get).unwrap();
        assert_eq!(record_get.id, new_tenant_id);

        // 4. Get tenant info (cross-tenant, should return 404)
        let get_resp_cross = get_tenant(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(new_tenant_id.to_string()),
        )
        .await
        .into_response();
        assert_eq!(get_resp_cross.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_mcp_servers_metadata_route() {
        let (state, tenant_id, _) = setup_state("mcp_servers_metadata_route").await;

        // Register two MCP servers
        let server_key1 = "github-mcp";
        let payload1 = RegisterMcpServerRequest {
            server_key: server_key1.to_string(),
            name: "GitHub MCP Server".to_string(),
            owner_team: Some("secops".to_string()),
            transport: "stdio".to_string(),
            source: Some("npx".to_string()),
            trust_level: "semi_trusted".to_string(),
            endpoint: "http://localhost:5001".to_string(),
        };
        let _ = register_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload1),
        )
        .await;

        let server_key2 = "slack-mcp";
        let payload2 = RegisterMcpServerRequest {
            server_key: server_key2.to_string(),
            name: "Slack MCP Server".to_string(),
            owner_team: Some("comms".to_string()),
            transport: "http".to_string(),
            source: None,
            trust_level: "trusted_internal".to_string(),
            endpoint: "http://localhost:5002".to_string(),
        };
        let _ = register_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload2),
        )
        .await;

        // 1. List MCP servers
        let list_resp = list_mcp_servers(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(Some("limit=10".to_string())),
        )
        .await
        .into_response();
        assert_eq!(list_resp.status(), StatusCode::OK);
        let body_list = to_bytes(list_resp.into_body(), usize::MAX).await.unwrap();
        let list: Vec<McpServerRecord> = serde_json::from_slice(&body_list).unwrap();
        assert_eq!(list.len(), 2);

        // 2. Get specific MCP server
        let get_resp = get_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(server_key1.to_string()),
        )
        .await
        .into_response();
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body_get = to_bytes(get_resp.into_body(), usize::MAX).await.unwrap();
        let s1: McpServerRecord = serde_json::from_slice(&body_get).unwrap();
        assert_eq!(s1.server_key, server_key1);
        assert_eq!(s1.trust_level, "semi_trusted");

        // 3. Update MCP server metadata
        let update_payload = UpdateMcpServerRequest {
            name: Some("GitHub Enterprise MCP".to_string()),
            owner_team: Some(Some("devops-core".to_string())),
            transport: None,
            source: None,
            trust_level: Some("trusted_internal".to_string()),
            endpoint: Some("http://internal-gateway:8081".to_string()),
            status: Some("active".to_string()),
        };
        let update_resp = update_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(server_key1.to_string()),
            Json(update_payload),
        )
        .await
        .into_response();
        assert_eq!(update_resp.status(), StatusCode::OK);
        let body_update = to_bytes(update_resp.into_body(), usize::MAX).await.unwrap();
        let s_updated: McpServerRecord = serde_json::from_slice(&body_update).unwrap();
        assert_eq!(s_updated.name, "GitHub Enterprise MCP");
        assert_eq!(s_updated.owner_team, Some("devops-core".to_string()));
        assert_eq!(s_updated.trust_level, "trusted_internal");
        assert_eq!(s_updated.endpoint, "http://internal-gateway:8081");

        // 4. Update non-existent (should return 404)
        let update_404_resp = update_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("non-existent".to_string()),
            Json(UpdateMcpServerRequest {
                name: Some("xyz".to_string()),
                owner_team: None,
                transport: None,
                source: None,
                trust_level: None,
                endpoint: None,
                status: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(update_404_resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_tenant_stats_route() {
        let (state, tenant_id, agent_token) = setup_state("tenant_stats_route").await;

        let auth_payload = AuthorizeRequest {
            request_id: None,
            callback: None,
            agent: AuthorizeAgentContext {
                id: "routes-agent".to_string(),
                environment: "production".to_string(),
            },
            user: None,
            tool_call: AuthorizeToolCall {
                tool: "github".to_string(),
                action: "read_file".to_string(),
                resource: Some("README.md".to_string()),
                mutates_state: false,
                parameters: json!({}),
            },
            context: AuthorizeDynamicContext {
                source_trust: "trusted_internal_signed".to_string(),
                contains_sensitive_data: false,
            },
            trace: None,
        };

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "Authorization",
            axum::http::HeaderValue::from_str(&format!("Bearer {}", agent_token)).unwrap(),
        );
        headers.insert(
            "X-Aegis-Tenant-ID",
            axum::http::HeaderValue::from_str(&tenant_id).unwrap(),
        );

        let _ = authorize_action(State(state.clone()), headers, Json(auth_payload)).await;

        // Query stats
        let stats_resp = get_tenant_stats(State(state.clone()), TenantId(tenant_id.clone()))
            .await
            .into_response();
        assert_eq!(stats_resp.status(), StatusCode::OK);
        let body_stats = to_bytes(stats_resp.into_body(), usize::MAX).await.unwrap();
        let stats: TenantStats = serde_json::from_slice(&body_stats).unwrap();
        assert_eq!(stats.total_decisions, 1);
        assert_eq!(stats.decisions_allow, 1);
        assert_eq!(stats.total_agents, 1);
    }

    /// #949, #950: GET /v1/admin/db-stats reports a non-zero on-disk size and
    /// includes a row-count entry for every core table, with `decisions`
    /// reflecting at least the one row written above.
    #[tokio::test]
    async fn test_db_stats_route() {
        let (state, tenant_id, agent_token) = setup_state("db_stats_route").await;

        let auth_payload = AuthorizeRequest {
            request_id: None,
            callback: None,
            agent: AuthorizeAgentContext {
                id: "routes-agent".to_string(),
                environment: "production".to_string(),
            },
            user: None,
            tool_call: AuthorizeToolCall {
                tool: "github".to_string(),
                action: "read_file".to_string(),
                resource: Some("README.md".to_string()),
                mutates_state: false,
                parameters: json!({}),
            },
            context: AuthorizeDynamicContext {
                source_trust: "trusted_internal_signed".to_string(),
                contains_sensitive_data: false,
            },
            trace: None,
        };

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "Authorization",
            axum::http::HeaderValue::from_str(&format!("Bearer {}", agent_token)).unwrap(),
        );
        headers.insert(
            "X-Aegis-Tenant-ID",
            axum::http::HeaderValue::from_str(&tenant_id).unwrap(),
        );

        let _ = authorize_action(State(state.clone()), headers, Json(auth_payload)).await;

        let resp = get_db_stats(State(state.clone())).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let stats: DbStats = serde_json::from_slice(&body).unwrap();

        assert!(stats.size_bytes > 0);
        let decisions = stats
            .tables
            .iter()
            .find(|t| t.table == "decisions")
            .expect("decisions table present in db-stats");
        assert!(decisions.row_count >= 1);
    }

    /// #945: POST /v1/admin/backup writes a point-in-time copy under
    /// AEGIS_BACKUP_DIR; rejects path-traversal filenames; rejects a repeat
    /// request for the same filename (VACUUM INTO refuses to overwrite).
    #[tokio::test]
    async fn test_create_db_backup_route() {
        let _guard = get_env_lock().lock().await;
        let (state, _tenant_id, _agent_token) = setup_state("db_backup_route").await;

        let backup_dir = format!("target/backup_route_{}", Uuid::new_v4().simple());
        std::env::set_var("AEGIS_BACKUP_DIR", &backup_dir);

        // Path traversal is rejected.
        let bad_resp = create_db_backup(
            State(state.clone()),
            Json(CreateBackupRequest {
                filename: "../escape.db".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(bad_resp.status(), StatusCode::BAD_REQUEST);

        // A bare filename succeeds and reports a non-zero size.
        let resp = create_db_backup(
            State(state.clone()),
            Json(CreateBackupRequest {
                filename: "snapshot.db".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let backup: CreateBackupResponse = serde_json::from_slice(&body).unwrap();
        assert!(backup.size_bytes > 0);
        assert!(std::path::Path::new(&backup.path).exists());

        // A repeat with the same filename is rejected (file already exists).
        let dup_resp = create_db_backup(
            State(state.clone()),
            Json(CreateBackupRequest {
                filename: "snapshot.db".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(dup_resp.status(), StatusCode::CONFLICT);

        std::env::remove_var("AEGIS_BACKUP_DIR");
        let _ = std::fs::remove_dir_all(&backup_dir);
    }

    /// #947 (GDPR right to erasure): DELETE /v1/tenants/:id removes the
    /// tenant row plus every owned row across decisions, approvals,
    /// receipts, audit events, and MCP servers/tools — without touching a
    /// second tenant's data, and a cross-tenant request 404s.
    #[tokio::test]
    async fn test_delete_tenant_route_removes_all_owned_data() {
        let (state, tenant_id, agent_token) = setup_state("delete_tenant_route").await;

        // Populate decisions/audit_events/action_receipts via authorize.
        let read_request = mcp_authorize_request("github", "read_file");
        let _ = call_authorize(state.clone(), &tenant_id, &agent_token, read_request).await;

        // Populate an approval (require_approval decision).
        let _ = create_pending_approval(&state, &tenant_id, &agent_token, "99").await;

        // Populate an MCP server.
        let _ = register_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(RegisterMcpServerRequest {
                server_key: "gdpr-test-server".to_string(),
                name: "GDPR Test Server".to_string(),
                owner_team: None,
                transport: "stdio".to_string(),
                source: None,
                trust_level: "trusted_internal_signed".to_string(),
                endpoint: "stdio://test".to_string(),
            }),
        )
        .await;

        // A second tenant with its own data must be unaffected.
        let tenant_b = format!("tenant_b_{}", Uuid::new_v4().simple());
        db::register_tenant(&state.pool, &tenant_b, "Tenant B", "developer")
            .await
            .unwrap();

        // Sanity check: tenant_id has rows before deletion.
        let stats_before = db::get_tenant_stats(&state.pool, &tenant_id).await.unwrap();
        assert!(stats_before.total_decisions >= 1);

        let resp = delete_tenant(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(tenant_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // The tenant and all owned rows are gone.
        assert!(db::get_tenant_by_id(&state.pool, &tenant_id)
            .await
            .unwrap()
            .is_none());
        let stats_after = db::get_tenant_stats(&state.pool, &tenant_id).await.unwrap();
        assert_eq!(stats_after.total_decisions, 0);
        assert_eq!(stats_after.total_agents, 0);
        assert_eq!(stats_after.total_receipts, 0);

        let remaining_approvals = db::list_pending_approvals(&state.pool, &tenant_id, 50, 0)
            .await
            .unwrap();
        assert!(remaining_approvals.is_empty());

        let remaining_servers = db::list_mcp_servers(&state.pool, &tenant_id, 50, 0)
            .await
            .unwrap();
        assert!(remaining_servers.is_empty());

        // tenant_b is untouched.
        assert!(db::get_tenant_by_id(&state.pool, &tenant_b)
            .await
            .unwrap()
            .is_some());

        // A cross-tenant delete (now that tenant_id is gone) reports 404.
        let cross = delete_tenant(
            State(state.clone()),
            TenantId(tenant_b.clone()),
            Path(tenant_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(cross.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_openapi_spec_route() {
        let spec_resp = get_openapi_spec().await.into_response();
        assert_eq!(spec_resp.status(), StatusCode::OK);
        let body_spec = to_bytes(spec_resp.into_body(), usize::MAX).await.unwrap();
        let spec_json: Value = serde_json::from_slice(&body_spec).unwrap();
        assert_eq!(spec_json["openapi"], "3.1.0");
        assert_eq!(spec_json["info"]["title"], "AegisAgent Control Plane API");
    }

    #[tokio::test]
    async fn test_event_sink_broadcasting() {
        let (sink, _rx) = EventSink::channel(100);
        let mut sub = sink.subscribe();

        let event = AseEvent {
            event_id: "evt_test".to_string(),
            occurred_at: "2026-06-02T12:00:00Z".to_string(),
            tenant_id: "tenant_abc".to_string(),
            kind: "authorize_decision".to_string(),
            agent_id: "agent_abc".to_string(),
            decision: "allow".to_string(),
            tool: "github".to_string(),
            action: "read".to_string(),
            resource: None,
            risk_score: 10,
            reason: "test".to_string(),
            run_id: None,
            trace_id: None,
            matched_policies: vec![],
        };

        sink.emit(event.clone());

        let received = sub.recv().await.unwrap();
        assert_eq!(received.event_id, "evt_test");
        assert_eq!(received.tenant_id, "tenant_abc");
    }

    #[tokio::test]
    async fn test_request_size_limit() {
        use axum::http::{Request, StatusCode};
        use axum::{extract::DefaultBodyLimit, routing::post, Router};
        use tower::ServiceExt;

        // Create a test app with a body limit of 10 bytes
        let app = Router::new()
            .route("/", post(|body: String| async { body }))
            .layer(DefaultBodyLimit::max(10));

        // Send a request with a small body (8 bytes)
        let request_small = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "text/plain")
            .body(axum::body::Body::from("12345678"))
            .unwrap();
        let response_small = app.clone().oneshot(request_small).await.unwrap();
        assert_eq!(response_small.status(), StatusCode::OK);

        // Send a request with a large body (12 bytes)
        let request_large = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "text/plain")
            .body(axum::body::Body::from("123456789012"))
            .unwrap();
        let response_large = app.oneshot(request_large).await.unwrap();
        assert_eq!(response_large.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_request_timeout() {
        use axum::http::{Request, StatusCode};
        use axum::{routing::get, Router};
        use std::time::Duration;
        use tower::ServiceExt;
        use tower_http::timeout::TimeoutLayer;

        // Create a test app with a timeout of 50ms
        let app = Router::new()
            .route("/fast", get(|| async { "fast" }))
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    "slow"
                }),
            )
            .layer(TimeoutLayer::new(Duration::from_millis(50)));

        // Fast request should succeed
        let req_fast = Request::builder()
            .uri("/fast")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp_fast = app.clone().oneshot(req_fast).await.unwrap();
        assert_eq!(resp_fast.status(), StatusCode::OK);

        // Slow request should time out
        let req_slow = Request::builder()
            .uri("/slow")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp_slow = app.oneshot(req_slow).await.unwrap();
        assert!(
            resp_slow.status() == StatusCode::REQUEST_TIMEOUT
                || resp_slow.status() == StatusCode::GATEWAY_TIMEOUT
                || resp_slow.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "expected timeout status, got: {:?}",
            resp_slow.status()
        );
    }

    #[tokio::test]
    async fn test_response_compression() {
        use axum::http::{header, Request, StatusCode};
        use axum::{routing::get, Router};
        use tower::ServiceExt;
        use tower_http::compression::CompressionLayer;

        let app = Router::new()
            .route(
                "/",
                get(|| async {
                    let large_body = "hello compression ".repeat(200);
                    ([(header::CONTENT_TYPE, "text/plain")], large_body)
                }),
            )
            .layer(CompressionLayer::new());

        // Request with Accept-Encoding: gzip
        let req = Request::builder()
            .uri("/")
            .header(header::ACCEPT_ENCODING, "gzip")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let content_encoding = resp.headers().get(header::CONTENT_ENCODING);
        assert!(
            content_encoding.is_some(),
            "Content-Encoding header missing"
        );
        assert_eq!(content_encoding.unwrap(), "gzip");
    }

    /// GET /v1/mcp/servers lists a tenant's servers with status + manifest_hash,
    /// and never leaks another tenant's servers.
    #[tokio::test]
    async fn list_mcp_servers_is_tenant_scoped_and_shows_status() {
        let (state, tenant_id, _agent_token) = setup_state("list_mcp_servers").await;

        for key in ["alpha-mcp", "beta-mcp"] {
            db::upsert_mcp_server(
                &state.pool,
                &tenant_id,
                key,
                "Server",
                Some("platform"),
                "http",
                Some("internal-registry"),
                "trusted_internal_signed",
                "http://127.0.0.1:9001/mcp",
            )
            .await
            .unwrap();
        }
        // beta is quarantined; alpha gets a pinned manifest hash.
        db::set_mcp_server_status(&state.pool, &tenant_id, "beta-mcp", "quarantined")
            .await
            .unwrap();
        db::set_mcp_server_manifest_hash(&state.pool, &tenant_id, "alpha-mcp", "sha256:abc")
            .await
            .unwrap();

        let response = list_mcp_servers(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let servers: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(servers.len(), 2);
        // Order-agnostic: locate each server by key (the handler paginates by
        // created_at DESC).
        let alpha = servers
            .iter()
            .find(|s| s["server_key"] == "alpha-mcp")
            .unwrap();
        let beta = servers
            .iter()
            .find(|s| s["server_key"] == "beta-mcp")
            .unwrap();
        assert_eq!(alpha["status"], "active");
        assert_eq!(alpha["manifest_hash"], "sha256:abc");
        assert_eq!(beta["status"], "quarantined");

        // A different tenant sees none of these servers.
        db::register_tenant(&state.pool, "tenant_other", "Other Tenant", "developer")
            .await
            .unwrap();
        let other = list_mcp_servers(
            State(state),
            TenantId("tenant_other".to_string()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        let other_body = to_bytes(other.into_body(), usize::MAX).await.unwrap();
        let other_servers: Vec<serde_json::Value> = serde_json::from_slice(&other_body).unwrap();
        assert!(other_servers.is_empty());
    }

    // ---- #899: skill_action read-through LRU cache ----

    #[test]
    fn skill_action_cache_hit_evict_invalidate_and_disabled() {
        let meta = |r: &str| (r.to_string(), false, false, "policy".to_string());
        let cache = SkillActionCache::new(2);
        let k1 = SkillActionCache::cache_key("t1", "s", "a1");
        let k2 = SkillActionCache::cache_key("t1", "s", "a2");
        let k3 = SkillActionCache::cache_key("t1", "s", "a3");

        cache.insert(k1.clone(), meta("low"));
        assert_eq!(cache.get(&k1), Some(meta("low"))); // hit
                                                       // Tenant-scoped: same skill/action under another tenant is a distinct key.
        assert_eq!(
            cache.get(&SkillActionCache::cache_key("t2", "s", "a1")),
            None
        );

        // LRU eviction at capacity 2: k1 is most-recently-used, so inserting k3
        // over capacity evicts the least-recent (k2).
        cache.insert(k2.clone(), meta("low"));
        let _ = cache.get(&k1);
        cache.insert(k3.clone(), meta("low"));
        assert_eq!(cache.get(&k2), None);
        assert!(cache.get(&k1).is_some());
        assert!(cache.get(&k3).is_some());

        cache.invalidate(&k1);
        assert_eq!(cache.get(&k1), None);

        // Capacity 0 disables the cache entirely.
        let disabled = SkillActionCache::new(0);
        disabled.insert(k1.clone(), meta("low"));
        assert_eq!(disabled.get(&k1), None);
    }

    async fn register_ship_action(state: &Arc<AppState>, tenant_id: &str, risk: &str) {
        let req = RegisterToolRequest {
            skill_key: "deployer".to_string(),
            name: "Deployer".to_string(),
            r#type: "static".to_string(),
            auth_type: None,
            owner_team: None,
            default_risk: None,
            actions: vec![RegisterToolAction {
                action_key: "ship".to_string(),
                description: None,
                risk: risk.to_string(),
                mutates_state: false,
                data_access: None,
                approval_required: false,
                default_decision: "policy".to_string(),
            }],
        };
        let resp = register_tool(
            State(state.clone()),
            TenantId(tenant_id.to_string()),
            Json(req),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Fail-closed staleness guard: after a cached authorize, re-registering the
    /// same action with a STRICTER risk must be reflected on the next authorize
    /// (the registration invalidates the cache — no stale looser metadata).
    #[tokio::test]
    async fn authorize_skill_cache_invalidated_on_reregister() {
        let (state, tenant_id, agent_token) = setup_state("skill_cache_reregister").await;

        register_ship_action(&state, &tenant_id, "low").await;
        let r1 = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            mcp_authorize_request("deployer", "ship"),
        )
        .await;
        assert_eq!(r1.risk_level, "low"); // populates the cache

        register_ship_action(&state, &tenant_id, "critical").await; // invalidates
        let r2 = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            mcp_authorize_request("deployer", "ship"),
        )
        .await;
        assert_eq!(
            r2.risk_level, "critical",
            "re-registration must invalidate the cache (no stale low-risk metadata)"
        );
    }

    /// #946 GDPR export: a tenant exports its own data bundle; a mismatched path
    /// id is 404; another tenant's export contains none of this tenant's records.
    #[tokio::test]
    async fn export_tenant_bundles_own_data_and_is_scoped() {
        let (state, tenant_id, agent_token) = setup_state("tenant_export").await;

        // Generate data: one authorize → a decision + receipt + audit event.
        let _ = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            mcp_authorize_request("github", "read_issue"),
        )
        .await;

        // Happy path: export own tenant.
        let resp = export_tenant(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(tenant_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["schema"], "aegis-tenant-export-1");
        assert_eq!(v["tenant_id"], tenant_id);
        assert!(
            !v["agents"].as_array().unwrap().is_empty(),
            "export must include the tenant's agent"
        );
        assert!(
            !v["decisions"].as_array().unwrap().is_empty(),
            "export must include the decision"
        );
        assert!(!v["action_receipts"].as_array().unwrap().is_empty());

        // Cross-tenant: a path id that isn't the authenticated tenant → 404.
        let denied = export_tenant(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("tenant_other".to_string()),
        )
        .await
        .into_response();
        assert_eq!(denied.status(), StatusCode::NOT_FOUND);

        // Tenant isolation: another tenant's export contains none of A's records.
        db::register_tenant(&state.pool, "tenant_other", "Other", "developer")
            .await
            .unwrap();
        let other = db::export_tenant_data(&state.pool, "tenant_other")
            .await
            .unwrap();
        assert!(other.agents.is_empty());
        assert!(other.decisions.is_empty());
        assert!(other.action_receipts.is_empty());
    }

    fn register_agent_router(state: Arc<AppState>) -> axum::Router {
        use axum::routing::post;
        axum::Router::new()
            .route("/v1/agents/register", post(register_agent))
            .with_state(state)
    }

    fn register_agent_payload(agent_key: &str) -> serde_json::Value {
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

    /// #0111: POST /v1/agents/register with a valid payload returns 201 and
    /// a fresh agent_id/agent_token.
    #[tokio::test]
    async fn register_agent_returns_201_with_valid_payload() {
        use axum::http::Request;
        use tower::ServiceExt;

        let (state, tenant_id, _agent_token) = setup_state("register_agent_201").await;
        let app = register_agent_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/agents/register")
            .header("content-type", "application/json")
            .header("Authorization", format!("Bearer {}", tenant_id))
            .body(axum::body::Body::from(
                register_agent_payload("new-agent").to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: RegisterAgentResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.agent_key, "new-agent");
        assert!(!parsed.agent_token.is_empty());
    }

    /// #0112: registering the same agent_key twice returns 200 with the
    /// existing agent's id/token, instead of creating a duplicate.
    #[tokio::test]
    async fn register_agent_returns_existing_agent_on_duplicate_key() {
        use axum::http::Request;
        use tower::ServiceExt;

        let (state, tenant_id, _agent_token) = setup_state("register_agent_dup").await;
        let app = register_agent_router(state);

        let make_request = || {
            Request::builder()
                .method("POST")
                .uri("/v1/agents/register")
                .header("content-type", "application/json")
                .header("Authorization", format!("Bearer {}", tenant_id))
                .body(axum::body::Body::from(
                    register_agent_payload("dup-agent").to_string(),
                ))
                .unwrap()
        };

        let first = app.clone().oneshot(make_request()).await.unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);
        let first_body = axum::body::to_bytes(first.into_body(), usize::MAX)
            .await
            .unwrap();
        let first_parsed: RegisterAgentResponse = serde_json::from_slice(&first_body).unwrap();

        let second = app.oneshot(make_request()).await.unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        let second_body = axum::body::to_bytes(second.into_body(), usize::MAX)
            .await
            .unwrap();
        let second_parsed: RegisterAgentResponse = serde_json::from_slice(&second_body).unwrap();

        assert_eq!(second_parsed.id, first_parsed.id);
        assert_eq!(second_parsed.agent_token, "[REDACTED]");
    }

    #[tokio::test]
    async fn test_unregistered_tenant_returns_404() {
        use axum::http::Request;
        use tower::ServiceExt;

        let (state, _tenant_id, _) = setup_state("unregistered_tenant").await;
        let app = register_agent_router(state);

        // Make a request with a tenant ID that does not exist in the database
        let request = Request::builder()
            .method("POST")
            .uri("/v1/agents/register")
            .header("content-type", "application/json")
            .header("Authorization", "Bearer tenant_nonexistent_xyz")
            .body(axum::body::Body::from(
                register_agent_payload("new-agent").to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "Tenant 'tenant_nonexistent_xyz' not found");
    }

    #[tokio::test]
    async fn test_agent_token_is_hashed_in_db() {
        use axum::http::Request;
        use tower::ServiceExt;

        let (state, tenant_id, _) = setup_state("agent_token_hashing").await;
        let app = register_agent_router(state.clone());

        // 1. Register a new agent
        let request = Request::builder()
            .method("POST")
            .uri("/v1/agents/register")
            .header("content-type", "application/json")
            .header("Authorization", format!("Bearer {}", tenant_id))
            .body(axum::body::Body::from(
                register_agent_payload("hash-agent").to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: RegisterAgentResponse = serde_json::from_slice(&body).unwrap();
        let cleartext_token = parsed.agent_token;

        // Verify we got a valid-looking cleartext token
        assert!(cleartext_token.starts_with("agent_tok_"));

        // 2. Query the DB directly to check the stored token
        let stored_agent = db::get_agent_by_key(&state.pool, &tenant_id, "hash-agent")
            .await
            .unwrap()
            .expect("agent should exist in database");

        // Stored token must NOT be cleartext
        assert_ne!(stored_agent.agent_token, cleartext_token);

        // Stored token must be the SHA-256 hash of the cleartext token
        let expected_hash = db::hash_token(&cleartext_token);
        assert_eq!(stored_agent.agent_token, expected_hash);

        // 3. Verify that get_agent_by_token successfully resolves the agent using cleartext
        let resolved = db::get_agent_by_token(&state.pool, &tenant_id, &cleartext_token)
            .await
            .unwrap();
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().agent_key, "hash-agent");
    }

    /// #0113: a payload missing the required agent_key field is rejected
    /// before reaching the handler (JSON extractor failure).
    #[tokio::test]
    async fn register_agent_rejects_missing_agent_key() {
        use axum::http::Request;
        use tower::ServiceExt;

        let (state, tenant_id, _agent_token) = setup_state("register_agent_missing_key").await;
        let app = register_agent_router(state);

        let mut payload = register_agent_payload("ignored");
        payload.as_object_mut().unwrap().remove("agent_key");

        let request = Request::builder()
            .method("POST")
            .uri("/v1/agents/register")
            .header("content-type", "application/json")
            .header("Authorization", format!("Bearer {}", tenant_id))
            .body(axum::body::Body::from(payload.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert!(
            response.status().is_client_error(),
            "expected a 4xx for missing agent_key, got {:?}",
            response.status()
        );
    }

    /// #0114: a request with no Authorization header is rejected with 401
    /// before the handler runs (TenantId extractor).
    #[tokio::test]
    async fn register_agent_rejects_missing_authorization_header() {
        use axum::http::Request;
        use tower::ServiceExt;

        let (state, _tenant_id, _agent_token) = setup_state("register_agent_no_auth").await;
        let app = register_agent_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/agents/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                register_agent_payload("no-auth-agent").to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    fn register_tool_router(state: Arc<AppState>) -> axum::Router {
        use axum::routing::post;
        axum::Router::new()
            .route("/v1/tools", post(register_tool))
            .with_state(state)
    }

    fn register_tool_payload(skill_key: &str, risk: &str) -> serde_json::Value {
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

    /// #0115: POST /v1/tools with a valid payload creates the skill and its
    /// actions, retrievable via `db::get_skill_action`.
    #[tokio::test]
    async fn register_tool_creates_skill_with_actions() {
        use axum::http::Request;
        use tower::ServiceExt;

        let (state, tenant_id, _agent_token) = setup_state("register_tool_creates").await;
        let pool = state.pool.clone();
        let app = register_tool_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/tools")
            .header("content-type", "application/json")
            .header("Authorization", format!("Bearer {}", tenant_id))
            .body(axum::body::Body::from(
                register_tool_payload("deployer", "low").to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let action = db::get_skill_action(&pool, &tenant_id, "deployer", "ship")
            .await
            .unwrap()
            .expect("registered action should be queryable");
        let (risk, mutates_state, approval_required, default_decision) = action;
        assert_eq!(risk, "low");
        assert!(mutates_state);
        assert!(!approval_required);
        assert_eq!(default_decision, "policy");
    }

    /// #0116: re-registering the same skill_key with a different action risk
    /// upserts in place rather than creating a duplicate skill/action.
    #[tokio::test]
    async fn register_tool_upserts_on_duplicate_skill_key() {
        use axum::http::Request;
        use tower::ServiceExt;

        let (state, tenant_id, _agent_token) = setup_state("register_tool_dup").await;
        let pool = state.pool.clone();
        let app = register_tool_router(state);

        let first = Request::builder()
            .method("POST")
            .uri("/v1/tools")
            .header("content-type", "application/json")
            .header("Authorization", format!("Bearer {}", tenant_id))
            .body(axum::body::Body::from(
                register_tool_payload("deployer", "low").to_string(),
            ))
            .unwrap();
        let first_response = app.clone().oneshot(first).await.unwrap();
        assert_eq!(first_response.status(), StatusCode::OK);

        let second = Request::builder()
            .method("POST")
            .uri("/v1/tools")
            .header("content-type", "application/json")
            .header("Authorization", format!("Bearer {}", tenant_id))
            .body(axum::body::Body::from(
                register_tool_payload("deployer", "high").to_string(),
            ))
            .unwrap();
        let second_response = app.oneshot(second).await.unwrap();
        assert_eq!(second_response.status(), StatusCode::OK);

        let action = db::get_skill_action(&pool, &tenant_id, "deployer", "ship")
            .await
            .unwrap()
            .expect("registered action should be queryable");
        let (risk, _mutates_state, _approval_required, _default_decision) = action;
        assert_eq!(risk, "high", "second registration should upsert risk");

        let skill_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM skills WHERE tenant_id = ? AND skill_key = 'deployer'",
        )
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            skill_count, 1,
            "duplicate registration must not create a second skill row"
        );
    }

    /// #1167: 100 tenants are created concurrently, each with its own agent,
    /// decision, pending approval, and action receipt. No tenant's list
    /// endpoints (`/v1/agents`, `/v1/decisions`, `/v1/approvals`,
    /// `/v1/receipts`) may return another tenant's rows.
    #[tokio::test]
    async fn cross_tenant_isolation_stress_100_tenants() {
        const N: usize = 100;
        let (state, _tenant_id, _agent_token) = setup_state("cross_tenant_stress").await;

        let mut handles = Vec::new();
        for i in 0..N {
            let state = state.clone();
            handles.push(tokio::spawn(async move {
                let tenant_id = format!("tenant_stress_{i}");
                db::register_tenant(
                    &state.pool,
                    &tenant_id,
                    &format!("Stress Tenant {i}"),
                    "developer",
                )
                .await
                .unwrap();

                let agent_token = format!("agent_tok_stress_{i}_{}", Uuid::new_v4().simple());
                let agent = AgentRecord {
                    id: Uuid::new_v4().to_string(),
                    tenant_id: tenant_id.clone(),
                    agent_key: "routes-agent".to_string(),
                    agent_token: db::hash_token(&agent_token),
                    name: format!("Stress Agent {i}"),
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
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                };
                db::insert_agent(&state.pool, &agent).await.unwrap();

                // Creates a decision row, a pending approval, and an action receipt
                // all bound to this tenant.
                create_pending_approval(&state, &tenant_id, &agent_token, &format!("{i}")).await;

                tenant_id
            }));
        }

        let mut tenant_ids = Vec::with_capacity(N);
        for handle in handles {
            tenant_ids.push(handle.await.unwrap());
        }

        for tenant_id in &tenant_ids {
            let agents: Vec<serde_json::Value> = serde_json::from_slice(
                &to_bytes(
                    list_agents(
                        State(state.clone()),
                        TenantId(tenant_id.clone()),
                        axum::extract::RawQuery(None),
                    )
                    .await
                    .into_response()
                    .into_body(),
                    usize::MAX,
                )
                .await
                .unwrap(),
            )
            .unwrap();
            assert_eq!(agents.len(), 1, "tenant {tenant_id} sees != 1 agent");
            assert_eq!(agents[0]["tenant_id"], json!(tenant_id));

            let decisions: Vec<serde_json::Value> = serde_json::from_slice(
                &to_bytes(
                    list_decisions(
                        State(state.clone()),
                        TenantId(tenant_id.clone()),
                        axum::extract::RawQuery(None),
                    )
                    .await
                    .into_response()
                    .into_body(),
                    usize::MAX,
                )
                .await
                .unwrap(),
            )
            .unwrap();
            assert_eq!(decisions.len(), 1, "tenant {tenant_id} sees != 1 decision");
            assert_eq!(decisions[0]["tenant_id"], json!(tenant_id));

            let approvals: Vec<serde_json::Value> = serde_json::from_slice(
                &to_bytes(
                    list_approvals(
                        State(state.clone()),
                        TenantId(tenant_id.clone()),
                        axum::extract::RawQuery(None),
                    )
                    .await
                    .into_response()
                    .into_body(),
                    usize::MAX,
                )
                .await
                .unwrap(),
            )
            .unwrap();
            assert_eq!(approvals.len(), 1, "tenant {tenant_id} sees != 1 approval");

            let receipts: Vec<serde_json::Value> = serde_json::from_slice(
                &to_bytes(
                    list_receipts(
                        State(state.clone()),
                        TenantId(tenant_id.clone()),
                        axum::extract::RawQuery(None),
                    )
                    .await
                    .into_response()
                    .into_body(),
                    usize::MAX,
                )
                .await
                .unwrap(),
            )
            .unwrap();
            assert_eq!(receipts.len(), 1, "tenant {tenant_id} sees != 1 receipt");
            assert_eq!(receipts[0]["tenant_id"], json!(tenant_id));
        }
    }

    /// #1169: a real WebSocket client connects to `/v1/ws/events`, receives
    /// `authorize_decision` events emitted for its own tenant within 100ms,
    /// and never receives events emitted for a different tenant.
    #[tokio::test]
    async fn ws_events_stream_is_tenant_scoped() {
        use axum::routing::get;
        use axum::Router;
        use futures_util::StreamExt;
        use tokio_tungstenite::connect_async;
        use tokio_tungstenite::tungstenite::Message as WsMessage;

        let (state, _tenant_id, _agent_token) = setup_state("ws_events_stream").await;

        let app = Router::new()
            .route("/v1/ws/events", get(ws_events))
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("ws://{addr}/v1/ws/events?token=tenant_a");
        let (mut ws_stream, _resp) = connect_async(url).await.unwrap();

        // Give the server a moment to register the subscription before emitting.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        fn make_event(tenant_id: &str, event_id: &str) -> AseEvent {
            AseEvent {
                event_id: event_id.to_string(),
                occurred_at: Utc::now().to_rfc3339(),
                tenant_id: tenant_id.to_string(),
                kind: "authorize_decision".to_string(),
                agent_id: "agent_ws_test".to_string(),
                decision: "allow".to_string(),
                tool: "github".to_string(),
                action: "read_file".to_string(),
                resource: None,
                risk_score: 10,
                reason: "policy_allow".to_string(),
                run_id: None,
                trace_id: None,
                matched_policies: vec![],
            }
        }

        // Event for a different tenant must NOT be delivered to tenant_a's socket.
        state
            .events
            .emit(make_event("tenant_b", "evt_other_tenant"));
        // Event for tenant_a must be delivered within 100ms.
        state.events.emit(make_event("tenant_a", "evt_own_tenant"));

        let msg = tokio::time::timeout(std::time::Duration::from_millis(100), ws_stream.next())
            .await
            .expect("event must arrive within 100ms")
            .expect("stream must not close")
            .expect("message must not be an error");

        let text = match msg {
            WsMessage::Text(t) => t,
            other => panic!("expected text message, got {other:?}"),
        };
        let received: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(received["event_id"], "evt_own_tenant");
        assert_eq!(received["tenant_id"], "tenant_a");

        let _ = ws_stream.close(None).await;
    }
}
