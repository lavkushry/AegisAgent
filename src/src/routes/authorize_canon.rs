//! Canonicalization and hashing helpers for the authorization pipeline.
//!
//! Extracted from `authorize.rs` for clarity. All functions are `pub(crate)` and
//! re-exported via `routes/mod.rs` so existing call sites are unaffected.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::models::*;

/// Recursively sort JSON object keys by Unicode code point (`aegis-jcs-1`).
/// Delegates to `aegis_canon` (TEST-002, #1162) so the fuzz targets in
/// `fuzz/` exercise the exact same implementation as the gateway.
pub(crate) fn canonicalize_json(value: Value) -> Value {
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
pub(crate) fn canonical_action_string(tool_call: &AuthorizeToolCall) -> String {
    aegis_canon::canonical_value_string(tool_call)
}

pub(crate) fn hash_tool_call(tool_call: &AuthorizeToolCall) -> String {
    sha256_hex(canonical_action_string(tool_call).as_bytes())
}

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

pub struct CanonicalHashCache {
    inner: Mutex<CanonicalHashCacheInner>,
    capacity: usize,
}

#[derive(Default)]
struct CanonicalHashCacheInner {
    map: HashMap<String, String>,
    /// Recency order, least-recent at the front.
    order: VecDeque<String>,
}

impl CanonicalHashCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(CanonicalHashCacheInner::default()),
            capacity,
        }
    }

    pub fn cache_key(tenant_id: &str, request_id: &str) -> String {
        format!("{tenant_id}\x1f{request_id}")
    }

    fn touch(order: &mut VecDeque<String>, key: &str) {
        if let Some(pos) = order.iter().position(|k| k == key) {
            order.remove(pos);
        }
        order.push_back(key.to_string());
    }

    pub fn get(&self, tenant_id: &str, request_id: &str) -> Option<String> {
        if self.capacity == 0 {
            return None;
        }
        let key = Self::cache_key(tenant_id, request_id);
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let val = inner.map.get(&key).cloned();
        if val.is_some() {
            Self::touch(&mut inner.order, &key);
        }
        val
    }

    pub fn insert(&self, tenant_id: &str, request_id: &str, hash: String) {
        if self.capacity == 0 {
            return;
        }
        let key = Self::cache_key(tenant_id, request_id);
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        inner.map.insert(key.clone(), hash);
        Self::touch(&mut inner.order, &key);
        while inner.map.len() > self.capacity {
            if let Some(evict) = inner.order.pop_front() {
                inner.map.remove(&evict);
            } else {
                break;
            }
        }
    }
}

pub(crate) fn hash_tool_call_cached(
    state: &super::AppState,
    tenant_id: &str,
    request_id: Option<&str>,
    tool_call: &AuthorizeToolCall,
) -> String {
    if let Some(req_id) = request_id.filter(|r| !r.is_empty()) {
        if let Some(cached_hash) = state.canonical_hash_cache.get(tenant_id, req_id) {
            return cached_hash;
        }
        let hash = hash_tool_call(tool_call);
        state
            .canonical_hash_cache
            .insert(tenant_id, req_id, hash.clone());
        hash
    } else {
        hash_tool_call(tool_call)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_hits_and_misses() {
        let cache = CanonicalHashCache::new(5);
        assert_eq!(cache.get("tenant-1", "req-1"), None);

        cache.insert("tenant-1", "req-1", "hash-1".to_string());
        assert_eq!(cache.get("tenant-1", "req-1"), Some("hash-1".to_string()));

        // Different request_id misses
        assert_eq!(cache.get("tenant-1", "req-2"), None);
    }

    #[test]
    fn test_multi_tenant_isolation() {
        let cache = CanonicalHashCache::new(5);
        cache.insert("tenant-1", "req-1", "hash-tenant-1".to_string());

        // Same request_id for different tenant should miss
        assert_eq!(cache.get("tenant-2", "req-1"), None);

        cache.insert("tenant-2", "req-1", "hash-tenant-2".to_string());
        assert_eq!(
            cache.get("tenant-1", "req-1"),
            Some("hash-tenant-1".to_string())
        );
        assert_eq!(
            cache.get("tenant-2", "req-1"),
            Some("hash-tenant-2".to_string())
        );
    }

    #[test]
    fn test_eviction() {
        let cache = CanonicalHashCache::new(2);
        cache.insert("tenant-1", "req-1", "hash-1".to_string());
        cache.insert("tenant-1", "req-2", "hash-2".to_string());

        // Both are present
        assert_eq!(cache.get("tenant-1", "req-1"), Some("hash-1".to_string()));
        assert_eq!(cache.get("tenant-1", "req-2"), Some("hash-2".to_string()));

        // Touch req-1 then req-2 so req-1 is oldest in order
        let _ = cache.get("tenant-1", "req-1");
        let _ = cache.get("tenant-1", "req-2");

        // Insert third entry, which triggers eviction of "req-1"
        cache.insert("tenant-1", "req-3", "hash-3".to_string());

        assert_eq!(cache.get("tenant-1", "req-1"), None); // Evicted
        assert_eq!(cache.get("tenant-1", "req-2"), Some("hash-2".to_string()));
        assert_eq!(cache.get("tenant-1", "req-3"), Some("hash-3".to_string()));
    }

    #[test]
    fn test_zero_capacity() {
        let cache = CanonicalHashCache::new(0);
        cache.insert("tenant-1", "req-1", "hash-1".to_string());
        assert_eq!(cache.get("tenant-1", "req-1"), None);
    }
}
