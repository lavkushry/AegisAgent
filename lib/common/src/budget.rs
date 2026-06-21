use chrono::{DateTime, Utc};
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

pub type SkillActionMeta = (String, bool, bool, String);

pub struct SkillActionCache {
    inner: Mutex<SkillActionCacheInner>,
    capacity: usize,
}

#[derive(Default)]
struct SkillActionCacheInner {
    map: HashMap<String, SkillActionMeta>,
    order: VecDeque<String>,
}

impl SkillActionCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(SkillActionCacheInner::default()),
            capacity,
        }
    }

    pub fn cache_key(tenant_id: &str, skill_key: &str, action_key: &str) -> String {
        format!("{tenant_id}\x1f{skill_key}\x1f{action_key}")
    }

    fn touch(order: &mut VecDeque<String>, key: &str) {
        if let Some(pos) = order.iter().position(|k| k == key) {
            order.remove(pos);
        }
        order.push_back(key.to_string());
    }

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

pub struct ReplayNonceCache {
    inner: Mutex<ReplayNonceCacheInner>,
    capacity: usize,
}

#[derive(Default)]
struct ReplayNonceCacheInner {
    seen: HashMap<String, DateTime<Utc>>,
    order: VecDeque<String>,
}

impl ReplayNonceCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(ReplayNonceCacheInner::default()),
            capacity,
        }
    }

    pub fn cache_key(tenant_id: &str, agent_id: &str, nonce: &str) -> String {
        format!("{tenant_id}\x1f{agent_id}\x1f{nonce}")
    }

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
