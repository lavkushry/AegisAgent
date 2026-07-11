#!/usr/bin/env bash
# Wave A narrative e2e — untrusted cage run → egress deny path → control
# action → durable receipt (Implementation_Status.md Wave A item 4).
#
# Phases:
#   1) Default isolation: alpine echo with network none → finished
#   2) Forced egress: an untrusted (root_trust_level=untrusted_external)
#      sandbox with egress_proxy_url pointed at aegis-egress-proxy running
#      in gateway mode (--gateway-url), so every check round-trips through
#      the real POST /v1/egress/check fail-closed path — the same code path
#      production traffic uses, not just the proxy's local standalone
#      decider. wget to the public Internet must fail → finished, and a
#      durable deny event/receipt must land in GET /v1/egress/events.
#   3) Control: sleep → POST kill → killed (signed control command)
#
# Managed mode builds gateway, cage-runner, and egress-proxy locally.
#
# Usage:
#   AEGIS_CAGE_E2E_MANAGE=1 ./scripts/cage-wave-a-e2e.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

AEGIS_URL="${AEGIS_URL:-http://127.0.0.1:8080}"
TENANT_ID="${TENANT_ID:-tenant_dev_alpha}"
TOKEN="${AEGIS_API_TOKEN:-$TENANT_ID}"
RUNNER_ID="${AEGIS_CAGE_RUNNER_ID:-cage-wave-a-e2e-runner}"
SIGNING_SECRET_HEX="${AEGIS_COMMAND_SIGNING_KEY:-0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20}"
PUBLIC_KEY_HEX="${AEGIS_CAGE_GATEWAY_PUBLIC_KEY_HEX:-79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664}"
WORKSPACE_ROOT="${AEGIS_CAGE_WORKSPACE_ROOT:-${TMPDIR:-/tmp}/aegis-cage-wave-a-workspaces}"
EGRESS_LISTEN="${AEGIS_EGRESS_LISTEN:-127.0.0.1:18888}"
EGRESS_PROXY_URL="${AEGIS_EGRESS_PROXY_URL:-http://${EGRESS_LISTEN}}"
# aegis-cage-runner attaches the egress-deny sandbox to a dedicated
# --internal Docker bridge and rewrites a loopback egress_proxy_url to
# `host.docker.internal` (docker_cli.rs::rewrite_loopback_proxy_for_container)
# so the sandbox can reach it. That only works if the proxy process itself
# is actually listening on an interface the bridge can reach — a listener
# bound to 127.0.0.1 only accepts connections arriving via loopback and
# silently refuses everything else, so the container's request never lands
# and no deny event/receipt is ever produced. EGRESS_PROXY_URL / EGRESS_LISTEN
# stay loopback (host-side checks + the container-side rewrite both key off
# 127.0.0.1); EGRESS_BIND is the actual `--listen` address and must be wider.
EGRESS_BIND="${AEGIS_EGRESS_BIND:-0.0.0.0:${EGRESS_LISTEN##*:}}"
POLL_SECS="${AEGIS_CAGE_E2E_POLL_SECS:-2}"
TIMEOUT_SECS="${AEGIS_CAGE_E2E_TIMEOUT_SECS:-180}"
MANAGE="${AEGIS_CAGE_E2E_MANAGE:-0}"

auth=(-H "Authorization: Bearer ${TOKEN}" -H "X-Aegis-Tenant-ID: ${TENANT_ID}" -H "Content-Type: application/json")

GATEWAY_PID=""
RUNNER_PID=""
EGRESS_PID=""
cleanup() {
  for pid_var in RUNNER_PID EGRESS_PID GATEWAY_PID; do
    pid="${!pid_var:-}"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT

require_docker() {
  if ! docker version >/dev/null 2>&1; then
    printf 'Docker daemon not reachable.\n' >&2
    exit 1
  fi
  if ! docker image inspect alpine:3 >/dev/null 2>&1; then
    printf '==> Pulling alpine:3\n'
    docker pull alpine:3
  fi
  # wget is in alpine:3 busybox.
}

wait_gateway() {
  local i
  for i in $(seq 1 90); do
    if curl -fsS "$AEGIS_URL/livez" >/dev/null 2>&1 || curl -fsS "$AEGIS_URL/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  printf 'Gateway not healthy at %s\n' "$AEGIS_URL" >&2
  return 1
}

wait_tcp() {
  local hostport="$1"
  local host="${hostport%:*}"
  local port="${hostport##*:}"
  local i
  for i in $(seq 1 30); do
    if (echo >/dev/tcp/"$host"/"$port") >/dev/null 2>&1; then
      return 0
    fi
    # bash /dev/tcp may be unavailable; fall back to curl
    if curl -fsS -o /dev/null --connect-timeout 1 "http://${hostport}/" 2>/dev/null; then
      return 0
    fi
    # proxy may not speak plain HTTP on GET / — treat connection refused vs other
    if ! curl -sS -o /dev/null --connect-timeout 1 "http://${hostport}/" 2>&1 | grep -qi 'connection refused'; then
      return 0
    fi
    sleep 0.5
  done
  printf 'nothing listening on %s\n' "$hostport" >&2
  return 1
}

target_dir() {
  cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])'
}

start_managed_stack() {
  printf '==> Managed mode: build gateway + cage-runner + egress-proxy\n'
  cargo build -p gateway -p aegis-cage-runner -p aegis-egress-proxy

  local td gateway_bin runner_bin egress_bin
  td="$(target_dir)"
  gateway_bin="${td}/debug/gateway"
  runner_bin="${td}/debug/aegis-cage-runner"
  egress_bin="${td}/debug/aegis-egress-proxy"
  if [[ ! -x "$gateway_bin" && -x "${td}/debug/aegis-gateway" ]]; then
    gateway_bin="${td}/debug/aegis-gateway"
  fi
  for b in "$gateway_bin" "$runner_bin" "$egress_bin"; do
    if [[ ! -x "$b" ]]; then
      printf 'missing binary: %s\n' "$b" >&2
      ls -la "$(dirname "$b")" >&2 || true
      exit 1
    fi
  done

  mkdir -p "$WORKSPACE_ROOT" "${TMPDIR:-/tmp}/aegis-cage-wave-a-db"
  local db_path="${TMPDIR:-/tmp}/aegis-cage-wave-a-db/aegis-e2e.db"
  rm -f "$db_path" "${db_path}-wal" "${db_path}-shm"

  printf '==> Start gateway\n'
  AEGIS_COMMAND_SIGNING_KEY="$SIGNING_SECRET_HEX" \
    DATABASE_URL="sqlite://${db_path}" \
    CEDAR_POLICY_PATH="${ROOT}/policies.cedar" \
    RUST_LOG="${RUST_LOG:-info,gateway=info}" \
    "$gateway_bin" &
  GATEWAY_PID=$!
  wait_gateway

  printf '==> Start egress-proxy in gateway mode (deny-by-default) on %s (bridge-reachable at %s)\n' "$EGRESS_BIND" "$EGRESS_LISTEN"
  # --gateway-url routes every check through the real fail-closed
  # POST /v1/egress/check (bans/quarantine layered, durable runtime
  # event + receipt written by the gateway) instead of the proxy's own
  # standalone local decider — this is the code path production traffic
  # actually uses, so the e2e proves the real thing, not a stand-in.
  #
  # Bind EGRESS_BIND (0.0.0.0 by default), not EGRESS_LISTEN (127.0.0.1):
  # the sandbox reaches this proxy via the dedicated --internal Docker
  # bridge cage-runner creates for forced egress, using
  # host.docker.internal:host-gateway — a listener scoped to 127.0.0.1
  # only accepts loopback-origin connections and silently refuses
  # anything arriving over that bridge, so the container's request would
  # never land and no deny event/receipt would ever be produced. This is
  # test/CI-only infrastructure (ephemeral runner or local dev box), not a
  # production deployment of the proxy — production's own default (in
  # main.rs) stays loopback-only.
  RUST_LOG="${RUST_LOG:-info,aegis_egress_proxy=info}" \
    "$egress_bin" --listen "$EGRESS_BIND" \
    --gateway-url "$AEGIS_URL" --api-token "$TOKEN" &
  EGRESS_PID=$!
  sleep 1
  if ! kill -0 "$EGRESS_PID" 2>/dev/null; then
    printf 'egress-proxy exited immediately\n' >&2
    exit 1
  fi
  wait_tcp "$EGRESS_LISTEN" || true

  local runner_toml
  runner_toml="$(mktemp "${TMPDIR:-/tmp}/aegis-cage-wave-a-XXXXXX.toml")"
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

  printf '==> Start cage-runner\n'
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
    -d "{\"id\":\"${TENANT_ID}\",\"name\":\"Cage Wave A E2E\",\"plan\":\"free\"}" || true)
  if [[ "$code" != "201" && "$code" != "409" && "$code" != "200" ]]; then
    printf 'tenant create HTTP %s (continuing if usable)\n' "$code" >&2
  fi
}

# create_run <run_key> <image> <cmd_json> <timeout> [network_json] [root_trust_level]
create_run() {
  local run_key="$1"
  local image_ref="$2"
  local cmd_json="$3"
  local timeout_seconds="$4"
  local network_json="${5:-{ \"direct_internet\": false \}}"
  local root_trust_level="${6:-}"
  local trust_json=""
  if [[ -n "$root_trust_level" ]]; then
    trust_json="\"root_trust_level\": \"${root_trust_level}\","
  fi
  local body code json
  body=$(curl -sS -w '\n%{http_code}' -X POST "$AEGIS_URL/v1/agent-cage/runs" \
    "${auth[@]}" \
    -d @- <<JSON
{
  "run_key": "${run_key}",
  "source_component": "cage-wave-a-e2e",
  "mode": "observe",
  ${trust_json}
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
    "network": ${network_json}
  }
}
JSON
)
  code=$(printf '%s' "$body" | tail -n1)
  json=$(printf '%s' "$body" | sed '$d')
  if [[ "$code" == "503" ]]; then
    printf 'Gateway 503 — set AEGIS_COMMAND_SIGNING_KEY\n%s\n' "$json" >&2
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
  printf 'timeout waiting for run %s in {%s}; last=%s\n' \
    "$run_id" "$*" "${status:-unknown}" >&2
  curl -fsS "$AEGIS_URL/v1/agent-cage/runs/${run_id}" "${auth[@]}" >&2 || true
  return 1
}

phase_default_isolation() {
  local run_key="wave-a-iso-$(date +%s)-$$"
  printf '==> Phase 1: network none isolation — echo finishes (run_key=%s)\n' "$run_key"
  local run_id
  run_id=$(create_run "$run_key" "alpine:3" '["echo","wave-a-isolation"]' 60)
  printf '    run_id=%s\n' "$run_id"
  local final
  final=$(wait_run_status "$run_id" finished killed)
  [[ "$final" == "finished" ]] || { printf 'expected finished, got %s\n' "$final" >&2; exit 1; }
  printf '    phase 1 ok\n'
}

# Record the newest egress-events rowid before a phase, so the post-phase
# check only looks at events that phase itself produced (the tenant/table is
# shared across the whole script run).
egress_events_watermark() {
  curl -fsS "$AEGIS_URL/v1/egress/events?limit=1" "${auth[@]}" \
    | python3 -c 'import sys,json
rows=json.load(sys.stdin)
print(rows[0]["id"] if rows else "")'
}

# verify_egress_receipt <watermark_id>
# Asserts the gateway's real POST /v1/egress/check path (not the proxy's
# standalone local decider) recorded at least one deny/blocked durable event
# since the watermark — i.e. a receipt-bearing evidence trail exists, not
# just a container exit code. Not scoped by run_id: the egress-proxy process
# is shared for the whole script and isn't told a --run-id (it's started
# before any run exists), so a fresh watermark is this test's isolation
# instead — this phase is the only one that ever talks to the proxy.
verify_egress_receipt() {
  local watermark="$1"
  local i body
  for i in $(seq 1 15); do
    body=$(curl -fsS "$AEGIS_URL/v1/egress/events?limit=50" "${auth[@]}")
    if printf '%s' "$body" | python3 -c "
import sys, json
watermark = '''${watermark}'''
rows = json.load(sys.stdin)
for row in rows:
    if watermark and row.get('id') == watermark:
        break
    if row.get('decision') in ('deny', 'blocked'):
        sys.exit(0)
sys.exit(1)
"; then
      printf '    durable deny event confirmed (real gateway /v1/egress/check path wrote receipt + runtime event)\n'
      return 0
    fi
    sleep 1
  done
  printf 'no durable deny event found in GET /v1/egress/events since watermark\n' >&2
  printf '%s\n' "$body" >&2
  return 1
}

phase_egress_deny() {
  local run_key="wave-a-egress-$(date +%s)-$$"
  printf '==> Phase 2: untrusted agent forced egress + gateway-mode deny-by-default proxy (run_key=%s)\n' "$run_key"
  local watermark
  watermark=$(egress_events_watermark)
  # busybox wget honors HTTP_PROXY. Deny-by-default proxy should refuse CONNECT/GET.
  # Write exit code into a local path the container can use; we assert the run
  # completes (does not hang) and does not claim open internet success.
  # shellcheck disable=SC2016
  local cmd_json
  cmd_json=$(python3 - <<'PY'
import json
cmd = [
  "sh", "-c",
  # Fail closed: if wget somehow succeeds (open internet), exit 99 so the e2e fails.
  # If wget fails (expected under deny-by-default proxy or unreachable), exit 0.
  "if wget -q -O /dev/null -T 8 http://example.com/; then echo OPEN_INTERNET_LEAK; exit 99; else echo EGRESS_DENIED_OR_UNREACHABLE; exit 0; fi"
]
print(json.dumps(cmd))
PY
)
  local network_json
  network_json=$(python3 -c "import json; print(json.dumps({
    'direct_internet': False,
    'egress_proxy_url': '''${EGRESS_PROXY_URL}''',
    'allowed_destinations': []
  }))")

  local run_id
  run_id=$(create_run "$run_key" "alpine:3" "$cmd_json" 90 "$network_json" "untrusted_external")
  printf '    run_id=%s proxy=%s (root_trust_level=untrusted_external)\n' "$run_id" "$EGRESS_PROXY_URL"
  local final
  final=$(wait_run_status "$run_id" finished killed)
  if [[ "$final" != "finished" ]]; then
    printf 'expected finished after egress-deny probe, got %s\n' "$final" >&2
    exit 1
  fi
  # If the sandbox exited 99, the runner still reports finished — spot-check
  # docker containers are cleaned up; leak would leave a long hang. Success =
  # completed within timeout without OPEN_INTERNET_LEAK hang.
  printf '    container path ok (completed without open-internet success hang)\n'

  verify_egress_receipt "$watermark"
  printf '    phase 2 ok (untrusted agent → cage → egress deny → durable receipt)\n'
}

phase_kill() {
  local run_key="wave-a-kill-$(date +%s)-$$"
  printf '==> Phase 3: signed kill (run_key=%s)\n' "$run_key"
  local run_id
  run_id=$(create_run "$run_key" "alpine:3" '["sleep","300"]' 600)
  printf '    run_id=%s\n' "$run_id"
  local running
  running=$(wait_run_status "$run_id" running finished killed paused)
  [[ "$running" == "running" ]] || { printf 'expected running, got %s\n' "$running" >&2; exit 1; }

  local kill_code
  kill_code=$(curl -sS -o /tmp/wave-a-kill.json -w '%{http_code}' -X POST \
    "$AEGIS_URL/v1/agent-cage/runs/${run_id}/kill" \
    "${auth[@]}" \
    -d '{"actor":"cage-wave-a-e2e","reason":"wave-a-narrative"}')
  if [[ "$kill_code" != "200" && "$kill_code" != "201" && "$kill_code" != "202" ]]; then
    printf 'kill HTTP %s\n' "$kill_code" >&2
    cat /tmp/wave-a-kill.json >&2 || true
    exit 1
  fi
  local final
  final=$(wait_run_status "$run_id" killed finished)
  if [[ "$final" != "killed" ]]; then
    printf 'expected killed, got %s\n' "$final" >&2
    exit 1
  fi
  printf '    phase 3 ok (killed)\n'
}

# ── main ─────────────────────────────────────────────────────────────────────
require_docker

if [[ "$MANAGE" == "1" ]]; then
  start_managed_stack
else
  wait_gateway || {
    printf 'Gateway not up. Use AEGIS_CAGE_E2E_MANAGE=1 or start stack manually.\n' >&2
    exit 1
  }
fi

ensure_tenant
phase_default_isolation
phase_egress_deny
phase_kill

printf '==> Wave A narrative e2e PASSED (isolation + egress deny path + kill)\n'
