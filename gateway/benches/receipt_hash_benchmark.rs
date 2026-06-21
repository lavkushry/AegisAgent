//! TEST-005 (#1165): micro-benchmark for `compute_receipt_hash` — the
//! `aegis-jcs-1` hash computed for every link in a tenant's action-receipt
//! chain (`gateway/src/routes/authorize_receipts.rs::emit_action_receipt`
//! calls this on every finalized `/v1/authorize` decision).
//!
//! This isolates the hashing cost itself (canonicalize the receipt body,
//! then SHA-256) from the DB transaction (`db::append_action_receipt_atomic`)
//! that wraps it in production — the receipt-chain-hashing concern #1165
//! actually asks about, distinct from `authorize_benchmark`'s end-to-end
//! `/v1/authorize` measurement (which includes this cost as one part of a
//! larger whole).
//!
//! Two scenarios:
//! - `chain_head` (`prev_receipt_hash` empty): the first receipt in a
//!   tenant's chain.
//! - `mid_chain` (`prev_receipt_hash` a real 64-hex-char SHA-256): every
//!   subsequent receipt — the steady-state case for a long-lived tenant.

use chrono::Utc;
use criterion::{criterion_group, criterion_main, Criterion};
use gateway::models::ActionReceiptRecord;
use gateway::routes::compute_receipt_hash;
use uuid::Uuid;

fn sample_receipt(prev_receipt_hash: String) -> ActionReceiptRecord {
    ActionReceiptRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: "tenant_bench".to_string(),
        decision_id: Some(Uuid::new_v4().to_string()),
        ts: Utc::now().to_rfc3339(),
        agent_id: Some("bench-agent".to_string()),
        user_id: None,
        run_id: Some("run_bench".to_string()),
        trace_id: Some("trace_bench".to_string()),
        tool: Some("filesystem".to_string()),
        action: Some("read_file".to_string()),
        resource: Some("bench.txt".to_string()),
        source_trust: "trusted_internal_signed".to_string(),
        decision: "allow".to_string(),
        approver: None,
        action_hash: Some(
            "a".repeat(64), // placeholder 64-hex-char action_hash shape
        ),
        prev_receipt_hash,
        receipt_hash: String::new(),
        canon_version: "aegis-jcs-1".to_string(),
        signature: None,
        signer_public_key: None,
        created_at: Utc::now(),
    }
}

fn receipt_hash_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("receipt_hash");

    let chain_head = sample_receipt(String::new());
    group.bench_function("compute_receipt_hash/chain_head", |b| {
        b.iter(|| {
            let hash = compute_receipt_hash(&chain_head);
            criterion::black_box(hash);
        });
    });

    let mid_chain = sample_receipt("b".repeat(64));
    group.bench_function("compute_receipt_hash/mid_chain", |b| {
        b.iter(|| {
            let hash = compute_receipt_hash(&mid_chain);
            criterion::black_box(hash);
        });
    });

    group.finish();
}

criterion_group!(benches, receipt_hash_benchmark);
criterion_main!(benches);
