#!/usr/bin/env bash
# Full Docker cage e2e — gateway claim path + real sandbox via aegis-cage-runner.
#
# Covers Wave A path:
#   1) create cage run (alpine quick command) → runner claims → status finished
#   2) create long sleep → POST kill → status killed (signed control command)
#
# Unlike scripts/cage-smoke.sh, this requires a Docker daemon and a running
# cage-runner process that can talk to that daemon.
#
# Prerequisites:
#   - Docker daemon reachable (`docker version`)
#   - Gateway on AEGIS_URL with AEGIS_COMMAND_SIGNING_KEY set
#   - aegis-cage-runner polling that gateway (matching public key + tenant token)
#   - curl + python3
#
# Managed mode (CI / local one-shot):
#   AEGIS_CAGE_E2E_MANAGE=1  builds/starts gateway + runner, then runs the tests.
#   Requires cargo, protoc (for gateway build), and docker.
#
# Usage:
#   # Already-running stack:
#   ./scripts/cage-docker-e2e.sh
#
#   # CI / self-contained:
#   AEGIS_CAGE_E2E_MANAGE=1 ./scripts/cage-docker-e2e.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

AEGIS_URL="${AEGIS_URL:-http://127.0.0.1:8080}"
TENANT_ID="${TENANT_ID:-tenant_dev_alpha}"
TOKEN="${AEGIS_API_TOKEN:-$TENANT_ID}"
RUNNER_ID="${AEGIS_CAGE_RUNNER_ID:-cage-docker-e2e-runner}"
# Deterministic test-only Ed25519 seed (matches gateway/sign tests). NOT for production.
SIGNING_SECRET_HEX="${AEGIS_COMMAND_SIGNING_KEY:-0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20}"
# Public key for the seed above (Ed25519, raw 32-byte hex).
PUBLIC_KEY_HEX="${AEGIS_CAGE_GATEWAY_PUBLIC_KEY_HEX:-79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664}"
WORKSPACE_ROOT="${AEGIS_CAGE_WORKSPACE_ROOT:-${TMPDIR:-/tmp}/aegis-cage-e2e-workspaces}"
POLL_SECS="${AEGIS_CAGE_E2E_POLL_SECS:-2}"
TIMEOUT_SECS="${AEGIS_CAGE_E2E_TIMEOUT_SECS:-120}"
MANAGE="${AEGIS_CAGE_E2E_MANAGE:-0}"

auth=(-H "Authorization: Bearer ${TOKEN}" -H "X-Aegis-Tenant-ID: ${TENANT_ID}" -H "Content-Type: application/json")

GATEWAY_PID=""
RUNNER_PID=""
cleanup() {
  if [[ -n "${RUNNER_PID}" ]] && kill -0 "${RUNNER_PID}" 2>/dev/null; then
    kill "${RUNNER_PID}" 2>/dev/null || true
    wait "${RUNNER_PID}" 2>/dev/null || true
  fi
  if [[ -n "${GATEWAY_PID}" ]] && kill -0 "${GATEWAY_PID}" 2>/dev/null; then
    kill "${GATEWAY_PID}" 2>/dev/null || true
    wait "${GATEWAY_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

require_docker() {
  if ! docker version >/dev/null 2>&1; then
    printf 'Docker daemon not reachable. Start Docker or skip this e2e.\n' >&2
    exit 1
  fi
  # Ensure a tiny image exists for sandboxes.
  if ! docker image inspect alpine:3 >/dev/null 2>&1; then
    printf '==> Pulling alpine:3 for sandboxes\n'
    docker pull alpine:3
  fi
}

wait_gateway() {
  local i
  for i in $(seq 1 60); do
    if curl -fsS "$AEGIS_URL/livez" >/dev/null 2>&1 || curl -fsS "$AEGIS_URL/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  printf 'Gateway not healthy at %s\n' "$AEGIS_URL" >&2
  return 1
}

start_managed_stack() {
  printf '==> Managed mode: build gateway + cage-runner\n'
  cargo build -p gateway -p aegis-cage-runner
  local gateway_bin runner_bin
  gateway_bin="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug/gateway"
  runner_bin="$(dirname "$gateway_bin")/aegis-cage-runner"
  if [[ ! -x "$gateway_bin" ]]; then
    # Binary name may be aegis-gateway on some package layouts.
    if [[ -x "$(dirname "$gateway_bin")/aegis-gateway" ]]; then
      gateway_bin="$(dirname "$gateway_bin")/aegis-gateway"
    else
      printf 'gateway binary not found under target/debug\n' >&2
      ls -la "$(dirname "$gateway_bin")" >&2 || true
      exit 1
    fi
  fi

  mkdir -p "$WORKSPACE_ROOT" "${TMPDIR:-/tmp}/aegis-cage-e2e-db"
  local db_path="${TMPDIR:-/tmp}/aegis-cage-e2e-db/aegis-e2e.db"
  rm -f "$db_path" "${db_path}-wal" "${db_path}-shm"

  printf '==> Start gateway (signing key set)\n'
  AEGIS_COMMAND_SIGNING_KEY="$SIGNING_SECRET_HEX" \
    DATABASE_URL="sqlite://${db_path}" \
    CEDAR_POLICY_PATH="${ROOT}/policies.cedar" \
    RUST_LOG="${RUST_LOG:-info,gateway=info}" \
    "$gateway_bin" &
  GATEWAY_PID=$!
  wait_gateway

  local runner_toml
  runner_toml="$(mktemp "${TMPDIR:-/tmp}/aegis-cage-e2e-XXXXXX.toml")"
  cat >"$runner_toml" <<TOML
gateway_url = "${AEGIS_URL}"
tenant_id = "${TENANT_ID}"
api_token = "${TOKEN}"
runner_id = "${RUNNER_ID}"
gateway_public_key_hex = "${PUBLIC_KEY_HEX}"
workspace_root = "${WORKSPACE_ROOT}"
claim_poll_interval_secs = 1
control_poll_interval_secs = 1
heartbeat_interval_secs = 2
TOML

  printf '==> Start cage-runner (runner_id=%s)\n' "$RUNNER_ID"
  RUST_LOG="${RUST_LOG:-info,aegis_cage_runner=info}" \
    "$runner_bin" --config "$runner_toml" &
  RUNNER_PID=$!
  sleep 2
  if ! kill -0 "$RUNNER_PID" 2>/dev/null; then
    printf 'cage-runner exited immediately\n' >&2
    exit 1
  fi
}

ensure_tenant() {
  local code
  code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$AEGIS_URL/v1/tenants" \
    -H "Content-Type: application/json" \
    -d "{\"id\":\"${TENANT_ID}\",\"name\":\"Cage Docker E2E\",\"plan\":\"free\"}" || true)
  if [[ "$code" != "201" && "$code" != "409" && "$code" != "200" ]]; then
    printf 'tenant create HTTP %s (continuing if usable)\n' "$code" >&2
  fi
}

create_run() {
  local run_key="$1"
  local image_ref="$2"
  local cmd_json="$3"
  local timeout_seconds="$4"
  local body code json
  body=$(curl -sS -w '\n%{http_code}' -X POST "$AEGIS_URL/v1/agent-cage/runs" \
    "${auth[@]}" \
    -d @- <<JSON
{
  "run_key": "${run_key}",
  "source_component": "cage-docker-e2e",
  "mode": "observe",
  "cage_spec": {
    "image_ref": "${image_ref}",
    "command": ${cmd_json},
    "working_dir": "/workspace",
    "resources": {
      "cpu_millis": 250,
      "memory_bytes": 134217728,
      "process_limit": 32,
      "timeout_seconds": ${timeout_seconds}
    },
    "network": { "direct_internet": false }
  }
}
JSON
)
  code=$(printf '%s' "$body" | tail -n1)
  json=$(printf '%s' "$body" | sed '$d')
  if [[ "$code" == "503" ]]; then
    printf 'Gateway 503 — AEGIS_COMMAND_SIGNING_KEY missing on gateway\n%s\n' "$json" >&2
    exit 1
  fi
  if [[ "$code" != "201" ]]; then
    printf 'create run failed HTTP %s\n%s\n' "$code" "$json" >&2
    exit 1
  fi
  printf '%s' "$json" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])'
}

wait_run_status() {
  local run_id="$1"
  shift
  local want=("$@")
  local deadline=$((SECONDS + TIMEOUT_SECS))
  local status body
  while (( SECONDS < deadline )); do
    body=$(curl -fsS "$AEGIS_URL/v1/agent-cage/runs/${run_id}" "${auth[@]}")
    status=$(printf '%s' "$body" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("status",""))')
    for w in "${want[@]}"; do
      if [[ "$status" == "$w" ]]; then
        printf '%s' "$status"
        return 0
      fi
    done
    sleep "$POLL_SECS"
  done
  printf 'timeout waiting for run %s in {%s}; last status=%s\n' \
    "$run_id" "$*" "${status:-unknown}" >&2
  curl -fsS "$AEGIS_URL/v1/agent-cage/runs/${run_id}" "${auth[@]}" >&2 || true
  return 1
}

phase_quick_finish() {
  local run_key="cage-e2e-quick-$(date +%s)-$$"
  printf '==> Phase 1: quick alpine command → finished (run_key=%s)\n' "$run_key"
  local run_id
  run_id=$(create_run "$run_key" "alpine:3" '["echo","cage-docker-e2e"]' 60)
  printf '    run_id=%s\n' "$run_id"
  local final
  final=$(wait_run_status "$run_id" finished killed)
  if [[ "$final" != "finished" ]]; then
    printf 'expected finished, got %s\n' "$final" >&2
    exit 1
  fi
  printf '    phase 1 ok (finished)\n'
}

phase_kill() {
  local run_key="cage-e2e-kill-$(date +%s)-$$"
  printf '==> Phase 2: long sleep → kill → killed (run_key=%s)\n' "$run_key"
  local run_id
  run_id=$(create_run "$run_key" "alpine:3" '["sleep","300"]' 600)
  printf '    run_id=%s\n' "$run_id"

  # Wait until runner has claimed and started the container.
  local running
  running=$(wait_run_status "$run_id" running finished killed paused)
  if [[ "$running" != "running" ]]; then
    printf 'expected running before kill, got %s\n' "$running" >&2
    exit 1
  fi
  printf '    running; issuing kill\n'

  local kill_code
  kill_code=$(curl -sS -o /tmp/cage-e2e-kill.json -w '%{http_code}' -X POST \
    "$AEGIS_URL/v1/agent-cage/runs/${run_id}/kill" \
    "${auth[@]}" \
    -d '{"actor":"cage-docker-e2e","reason":"cage-docker-e2e"}')
  if [[ "$kill_code" != "200" && "$kill_code" != "201" && "$kill_code" != "202" ]]; then
    printf 'kill HTTP %s\n' "$kill_code" >&2
    cat /tmp/cage-e2e-kill.json >&2 || true
    exit 1
  fi

  local final
  final=$(wait_run_status "$run_id" killed finished)
  if [[ "$final" != "killed" ]]; then
    printf 'expected killed after control command, got %s\n' "$final" >&2
    exit 1
  fi
  printf '    phase 2 ok (killed)\n'
}

# ── main ─────────────────────────────────────────────────────────────────────
require_docker

if [[ "$MANAGE" == "1" ]]; then
  start_managed_stack
else
  wait_gateway || {
    printf 'Gateway not up. Start it with AEGIS_COMMAND_SIGNING_KEY, start the runner, or set AEGIS_CAGE_E2E_MANAGE=1.\n' >&2
    exit 1
  }
fi

ensure_tenant
phase_quick_finish
phase_kill

printf '==> Cage Docker e2e PASSED\n'
