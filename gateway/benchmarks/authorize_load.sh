#!/usr/bin/env bash
# TASK-1313: HTTP-level load test for POST /v1/authorize using vegeta.
#
# Vegeta (https://github.com/tsenart/vegeta) was successfully installed in
# this sandbox via:
#   /usr/local/go/bin/go install github.com/tsenart/vegeta@latest
# (binary lands at $HOME/go/bin/vegeta). k6 was not available/attempted to
# install (vegeta sufficed and matches the issue's "k6 OR vegeta" wording).
#
# This script:
#   1. registers a bench agent against a running gateway (must already be
#      listening on 127.0.0.1:8080 with policies.cedar loaded),
#   2. builds a vegeta target file for a steady-state allow `/v1/authorize`
#      call (read-only filesystem.read_file, trusted_internal_signed),
#   3. runs a short vegeta attack and reports p50/p95/p99 latency +
#      throughput via `vegeta report`.
#
# Usage:
#   cargo run --manifest-path gateway/Cargo.toml &     # start the gateway
#   bash gateway/benchmarks/authorize_load.sh
#
# Keep duration/rate modest for sandboxed runs — this defaults to 5s @ 50 rps
# (250 requests), which is enough to get stable percentiles without taxing
# the sandbox.

set -euo pipefail

GATEWAY="${GATEWAY:-http://127.0.0.1:8080}"
DURATION="${DURATION:-5s}"
RATE="${RATE:-50}"
VEGETA="${VEGETA:-$HOME/go/bin/vegeta}"

if ! command -v "$VEGETA" >/dev/null 2>&1; then
  echo "vegeta not found at $VEGETA — install with:" >&2
  echo "  go install github.com/tsenart/vegeta@latest" >&2
  exit 1
fi

TENANT_ID="tenant_bench_load"
AGENT_KEY="bench-load-agent-$$"

echo "Registering tenant + agent against $GATEWAY ..." >&2

# Register tenant (idempotent-ish: ignore failure if it already exists).
curl -s -o /dev/null -w '' -X POST "$GATEWAY/v1/tenants" \
  -H 'Content-Type: application/json' \
  -d "{\"id\": \"$TENANT_ID\", \"name\": \"Bench Load Tenant\", \"plan\": \"developer\"}" || true

REGISTER_RESPONSE=$(curl -s -X POST "$GATEWAY/v1/agents/register" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TENANT_ID" \
  -d "{\"agent_key\": \"$AGENT_KEY\", \"name\": \"Bench Load Agent\", \"environment\": \"production\", \"risk_tier\": \"high\"}")

AGENT_TOKEN=$(echo "$REGISTER_RESPONSE" | python3 -c 'import sys,json;print(json.load(sys.stdin)["agent_token"])')

if [ -z "$AGENT_TOKEN" ]; then
  echo "Failed to register bench agent. Response: $REGISTER_RESPONSE" >&2
  exit 1
fi

BODY=$(cat <<EOF
{
  "agent": {"id": "$AGENT_KEY", "environment": "production"},
  "tool_call": {
    "tool": "filesystem",
    "action": "read_file",
    "resource": "bench.txt",
    "mutates_state": false,
    "parameters": {}
  },
  "context": {"source_trust": "trusted_internal_signed", "contains_sensitive_data": false},
  "trace": {"run_id": "run_bench_load", "trace_id": "trace_bench_load"}
}
EOF
)

TARGET_FILE=$(mktemp)
trap 'rm -f "$TARGET_FILE"' EXIT

{
  echo "POST $GATEWAY/v1/authorize"
  echo "Authorization: Bearer $AGENT_TOKEN"
  echo "X-Aegis-Tenant-ID: $TENANT_ID"
  echo "Content-Type: application/json"
  echo "@$TARGET_FILE.body"
} > "$TARGET_FILE"

echo "$BODY" > "$TARGET_FILE.body"
trap 'rm -f "$TARGET_FILE" "$TARGET_FILE.body"' EXIT

echo "Running vegeta attack: rate=$RATE/s duration=$DURATION ..." >&2
"$VEGETA" attack -targets="$TARGET_FILE" -rate="$RATE" -duration="$DURATION" \
  | "$VEGETA" report -type=text
