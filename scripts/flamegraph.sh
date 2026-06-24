#!/usr/bin/env bash
# CPU flame graph profiling for AegisAgent's performance-critical code paths
# (#910). Profiles one of the existing criterion benchmarks in
# src/benches/ — these are self-contained, finite-duration, single-process
# runs, which is exactly the workload shape cargo-flamegraph/perf sample
# cleanly (unlike a long-running server process that needs a separate load
# generator and a manual stop signal to finalize the profile).
#
# Usage:
#   ./scripts/flamegraph.sh [bench-name]
#
# bench-name (default: authorize_benchmark) must be one of the benches
# declared in src/Cargo.toml's [[bench]] sections:
#   authorize_benchmark, policy_eval_benchmark, canon_benchmark,
#   receipt_hash_benchmark, audit_batch_benchmark, evidence_graph_benchmark
#
# Requires:
#   - cargo-flamegraph: cargo install flamegraph
#   - On Linux: `perf`, with kernel.perf_event_paranoid <= 1
#     (or run this script under sudo if your system disallows unprivileged
#     perf sampling — check with: cat /proc/sys/kernel/perf_event_paranoid)
#
# Output: flamegraph.svg in the repo root (cargo-flamegraph's own default
# output location — open it in any browser to explore the call stacks).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
BENCH="${1:-authorize_benchmark}"

VALID_BENCHES=(
  authorize_benchmark
  policy_eval_benchmark
  canon_benchmark
  receipt_hash_benchmark
  audit_batch_benchmark
  evidence_graph_benchmark
)

is_valid_bench() {
  local candidate="$1"
  local b
  for b in "${VALID_BENCHES[@]}"; do
    [[ "$b" == "$candidate" ]] && return 0
  done
  return 1
}

if ! is_valid_bench "$BENCH"; then
  echo "ERROR: unknown bench '$BENCH'." >&2
  echo "Valid options: ${VALID_BENCHES[*]}" >&2
  exit 1
fi

if ! cargo flamegraph --version &>/dev/null; then
  echo "ERROR: cargo-flamegraph not found. Install with: cargo install flamegraph" >&2
  exit 1
fi

echo "==> Profiling bench '$BENCH' (output: $REPO_ROOT/flamegraph.svg)"
cd "$REPO_ROOT"

# CARGO_PROFILE_RELEASE_DEBUG=true (rather than editing src/Cargo.toml's
# [profile.release] permanently) keeps debug symbols in this one profiling
# build only — cargo-flamegraph needs them to resolve stack frames to
# function names, but normal release builds shouldn't carry the extra
# binary size/build time for a profiling-only concern.
CARGO_PROFILE_RELEASE_DEBUG=true \
  cargo flamegraph --manifest-path "$REPO_ROOT/src/Cargo.toml" --bench "$BENCH"

echo "==> Done: $REPO_ROOT/flamegraph.svg"
