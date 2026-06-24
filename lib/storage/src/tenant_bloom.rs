//! #917: a fixed-size, lock-free bloom filter used as a fast "definitely
//! absent" pre-check for tenant-existence lookups on the hot request path
//! (`get_tenant_by_id` is called once per authenticated request via the
//! `TenantId` extractor).
//!
//! Unlike a `HashMap`-backed cache, the filter's memory footprint is fixed
//! regardless of how many distinct tenant IDs are ever queried, so it can't
//! be grown unbounded by a client probing many bogus tenant IDs. It never
//! produces false negatives: an ID that was inserted is always reported as
//! present. It may produce false positives, which the caller resolves by
//! falling through to the real database query unchanged — so wiring this in
//! can only skip *unnecessary* DB round trips, never change the result of a
//! lookup.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// 2^20 bits (128 KiB) — comfortable headroom for tens of thousands of
/// tenants at a low false-positive rate with 4 hash functions, and the size
/// is fixed regardless of query volume (only `insert` grows the bit count
/// set, never the allocation).
const NUM_BITS: usize = 1 << 20;
const NUM_WORDS: usize = NUM_BITS / 64;
const NUM_HASHES: usize = 4;

pub struct TenantBloomFilter {
    bits: Vec<AtomicU64>,
    populated: AtomicBool,
}

impl Default for TenantBloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl TenantBloomFilter {
    pub fn new() -> Self {
        let mut bits = Vec::with_capacity(NUM_WORDS);
        for _ in 0..NUM_WORDS {
            bits.push(AtomicU64::new(0));
        }
        Self {
            bits,
            populated: AtomicBool::new(false),
        }
    }

    pub fn build_from(tenant_ids: &[String]) -> Self {
        let filter = Self::new();
        for id in tenant_ids {
            filter.insert(id);
        }
        filter
    }

    fn hash_indices(tenant_id: &str) -> [usize; NUM_HASHES] {
        use std::hash::{Hash, Hasher};
        let mut indices = [0usize; NUM_HASHES];
        for (i, idx) in indices.iter_mut().enumerate() {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            i.hash(&mut hasher);
            tenant_id.hash(&mut hasher);
            *idx = (hasher.finish() as usize) % NUM_BITS;
        }
        indices
    }

    pub fn insert(&self, tenant_id: &str) {
        for idx in Self::hash_indices(tenant_id) {
            self.bits[idx / 64].fetch_or(1u64 << (idx % 64), Ordering::Relaxed);
        }
        self.populated.store(true, Ordering::Relaxed);
    }

    /// `false` is a definitive answer: `tenant_id` was never inserted.
    /// `true` may be a false positive — callers must still confirm via the
    /// authoritative lookup before relying on it.
    pub fn might_contain(&self, tenant_id: &str) -> bool {
        Self::hash_indices(tenant_id).iter().all(|&idx| {
            self.bits[idx / 64].load(Ordering::Relaxed) & (1u64 << (idx % 64)) != 0
        })
    }

    /// Until at least one tenant has been inserted (typically via an
    /// explicit startup warm-up from the `tenants` table), the filter is
    /// inert. Callers must check this before trusting a `false` result from
    /// `might_contain` — an empty filter would otherwise report every
    /// tenant as definitely absent.
    pub fn is_populated(&self) -> bool {
        self.populated.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_filter_is_unpopulated() {
        let filter = TenantBloomFilter::new();
        assert!(!filter.is_populated());
    }

    #[test]
    fn insert_marks_filter_populated() {
        let filter = TenantBloomFilter::new();
        filter.insert("tenant_a");
        assert!(filter.is_populated());
    }

    #[test]
    fn might_contain_is_true_for_inserted_id() {
        let filter = TenantBloomFilter::new();
        filter.insert("tenant_a");
        assert!(filter.might_contain("tenant_a"));
    }

    #[test]
    fn might_contain_is_false_for_never_inserted_id() {
        let filter = TenantBloomFilter::new();
        filter.insert("tenant_a");
        assert!(!filter.might_contain("definitely_not_a_tenant"));
    }

    #[test]
    fn build_from_inserts_every_id() {
        let filter = TenantBloomFilter::build_from(&["tenant_a".to_string(), "tenant_b".to_string()]);
        assert!(filter.is_populated());
        assert!(filter.might_contain("tenant_a"));
        assert!(filter.might_contain("tenant_b"));
        assert!(!filter.might_contain("tenant_c"));
    }

    /// Core correctness guarantee: zero false negatives. Every one of a
    /// large batch of distinct inserted IDs must report present — a false
    /// negative here would mean a real tenant gets incorrectly 404'd by the
    /// pre-check.
    #[test]
    fn no_false_negatives_across_many_inserts() {
        let ids: Vec<String> = (0..2000).map(|i| format!("tenant_{i}")).collect();
        let filter = TenantBloomFilter::build_from(&ids);
        for id in &ids {
            assert!(filter.might_contain(id), "false negative for {id}");
        }
    }
}
