//! TEST-005 (#1165): micro-benchmark for the `aegis-jcs-1` canonicalization
//! primitives — `canonicalize_json` (recursive key-sort) and
//! `canonical_value_string` (canonicalize + compact-serialize) — in
//! isolation from any HTTP/DB overhead.
//!
//! These are the exact functions `gateway/src/routes/authorize_canon.rs`
//! delegates to (shared with the SDKs' byte-parity corpus and the
//! `gateway/fuzz` crash-finding targets, see `canon-fuzz.yml`), and the ones
//! every `/v1/authorize` call and every receipt-chain append hashes through.
//! `authorize_benchmark`/`policy_eval_benchmark` measure larger units of
//! work that include canonicalization as one cost among many; this isolates
//! just that cost.
//!
//! Three representative payload shapes:
//! - `flat_tool_call`: a small, flat object — the common case for a simple
//!   `tool_call.parameters` body.
//! - `nested_mixed_types`: nested objects/arrays mixing strings, numbers,
//!   booleans, and null — exercises the recursive key-sort path.
//! - `large_array`: a 200-element array of small objects, approximating a
//!   bulk parameter payload (e.g. a batch operation's argument list).

use aegis_canon::{canonical_value_string, canonicalize_json};
use criterion::{criterion_group, criterion_main, Criterion};
use serde_json::{json, Value};

fn flat_tool_call() -> Value {
    json!({
        "branch": "main",
        "repo": "example/repo",
        "pull_number": 42,
        "merge_method": "squash",
        "delete_branch": true,
    })
}

fn nested_mixed_types() -> Value {
    json!({
        "tool": "github",
        "action": "merge_pull_request",
        "resource": "repo/example/pull/42",
        "mutates_state": true,
        "parameters": {
            "base_branch": "main",
            "labels": ["needs-review", "automated", null],
            "reviewers": [
                {"id": 1, "name": "alice", "approved": true},
                {"id": 2, "name": "bob", "approved": false},
            ],
            "metadata": {"source": "ci", "retries": 0, "score": 0.87},
        },
    })
}

fn large_array() -> Value {
    let items: Vec<Value> = (0..200)
        .map(|i| {
            json!({
                "id": i,
                "key": format!("item-{i}"),
                "active": i % 2 == 0,
                "tags": ["bench", "load"],
            })
        })
        .collect();
    Value::Array(items)
}

fn canon_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("canonicalization");

    for (name, value) in [
        ("flat_tool_call", flat_tool_call()),
        ("nested_mixed_types", nested_mixed_types()),
        ("large_array", large_array()),
    ] {
        group.bench_function(format!("canonicalize_json/{name}"), |b| {
            b.iter(|| {
                let canonical = canonicalize_json(value.clone());
                criterion::black_box(canonical);
            });
        });

        group.bench_function(format!("canonical_value_string/{name}"), |b| {
            b.iter(|| {
                let s = canonical_value_string(&value);
                criterion::black_box(s);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, canon_benchmark);
criterion_main!(benches);
