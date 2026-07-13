#!/usr/bin/env bash
# Long-running node-sensor soak (Implementation_Status.md sensor row:
# "long-lived production-host soak"). Runs the real aegis-node-sensor binary
# against a real gateway on a real Linux host for a sustained period under
# continuous collector workload, signed-kill enforcement round-trips, and a
# mid-soak gateway outage, then asserts the properties only a long run can
# prove:
#
#   1. the sensor process survives the whole soak with zero panics;
#   2. resident memory and open file descriptors stay bounded (no leak
#      slope between the steady-state sample and the final sample);
#   3. spool disk usage stays bounded (steady-state compaction works live,
#      not just in unit tests) and fully drains after the workload stops;
#   4. signed kill commands verify, execute against real host processes,
#      and ACK throughout the soak — including after the gateway outage;
#   5. a gateway outage mid-soak only buffers events (durable spool) and
#      the sensor recovers on its own when the gateway returns.
#
# Linux-only: the collectors read the real /proc. On macOS run it inside a
# Linux container/VM. CI runs this nightly (sensor-soak.yml) with a short
# duration; longer local runs: SOAK_DURATION_SECS=14400 ./scripts/sensor-soak.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# ── knobs ────────────────────────────────────────────────────────────────────
SOAK_DURATION_SECS="${SOAK_DURATION_SECS:-900}"
SAMPLE_INTERVAL_SECS="${SAMPLE_INTERVAL_SECS:-10}"
WORKLOAD_INTERVAL_SECS="${WORKLOAD_INTERVAL_SECS:-5}"
KILL_INTERVAL_SECS="${KILL_INTERVAL_SECS:-60}"
OUTAGE_AT_PCT="${OUTAGE_AT_PCT:-50}"          # gateway outage begins at this % of the soak
OUTAGE_SECS="${OUTAGE_SECS:-45}"
DRAIN_GRACE_SECS="${DRAIN_GRACE_SECS:-30}"    # post-soak window for the spool to drain
MAX_RSS_GROWTH_PCT="${MAX_RSS_GROWTH_PCT:-30}" # allowed RSS growth steady→final
MAX_FD_GROWTH="${MAX_FD_GROWTH:-16}"          # allowed absolute fd-count growth steady→final
KILL_DEADLINE_SECS="${KILL_DEADLINE_SECS:-30}" # discovery + signed kill + real SIGTERM
SPOOL_DISK_BOUND_BYTES="${SPOOL_DISK_BOUND_BYTES:-1048576}" # per-lane on-disk bound (compaction proof)

AEGIS_URL="${AEGIS_URL:-http://127.0.0.1:8080}"
TENANT_ID="${TENANT_ID:-tenant_soak}"
TOKEN="${AEGIS_API_TOKEN:-$TENANT_ID}"
SIGNING_SECRET_HEX="${AEGIS_COMMAND_SIGNING_KEY:-0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20}"
PUBLIC_KEY_HEX="${AEGIS_SENSOR_GATEWAY_PUBLIC_KEY_HEX:-79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664}"
ARTIFACT_DIR="${SOAK_ARTIFACT_DIR:-target/sensor-soak}"

auth=(-H "Authorization: Bearer ${TOKEN}" -H "X-Aegis-Tenant-ID: ${TENANT_ID}" -H "Content-Type: application/json")

if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'sensor-soak requires a real Linux /proc (run in a Linux container/VM on macOS)\n' >&2
  exit 1
fi

mkdir -p "$ARTIFACT_DIR"
SAMPLES_CSV="$ARTIFACT_DIR/samples.csv"
SENSOR_LOG="$ARTIFACT_DIR/sensor.log"
GATEWAY_LOG="$ARTIFACT_DIR/gateway.log"
SUMMARY_JSON="$ARTIFACT_DIR/summary.json"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-sensor-soak-XXXXXX")"
SPOOL_DIR="$WORK_DIR/spool"
DB_PATH="$WORK_DIR/soak.db"

GATEWAY_PID=""
SENSOR_PID=""
WORKLOAD_PIDS=()
cleanup() {
  for pid in "${WORKLOAD_PIDS[@]:-}" "$SENSOR_PID" "$GATEWAY_PID"; do
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT

# ── stack management ─────────────────────────────────────────────────────────
target_dir() {
  cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])'
}

wait_gateway() {
  local _attempt
  for _attempt in $(seq 1 90); do
    if curl -fsS "$AEGIS_URL/livez" >/dev/null 2>&1 || curl -fsS "$AEGIS_URL/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  printf 'gateway not healthy at %s\n' "$AEGIS_URL" >&2
  return 1
}

start_gateway() {
  AEGIS_COMMAND_SIGNING_KEY="$SIGNING_SECRET_HEX" \
    DATABASE_URL="sqlite://${DB_PATH}" \
    CEDAR_POLICY_PATH="${ROOT}/policies.cedar" \
    RUST_LOG="${RUST_LOG:-info}" \
    "$GATEWAY_BIN" >>"$GATEWAY_LOG" 2>&1 &
  GATEWAY_PID=$!
  wait_gateway
}

ensure_tenant() {
  local code
  code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$AEGIS_URL/v1/tenants" \
    -H "Content-Type: application/json" \
    -d "{\"id\":\"${TENANT_ID}\",\"name\":\"Sensor Soak\",\"plan\":\"free\"}" || true)
  if [[ "$code" != "201" && "$code" != "409" && "$code" != "200" ]]; then
    printf 'tenant create HTTP %s (continuing if usable)\n' "$code" >&2
  fi
}

start_sensor() {
  local sensor_toml="$WORK_DIR/aegis-sensor.toml"
  cat >"$sensor_toml" <<TOML
gateway_url = "${AEGIS_URL}"
tenant_id = "${TENANT_ID}"
api_token = "${TOKEN}"
mode = "enforce"
identity_key_path = "${WORK_DIR}/sensor-identity.key"
spool_dir = "${SPOOL_DIR}"
gateway_public_key_hex = "${PUBLIC_KEY_HEX}"
TOML
  RUST_LOG="${RUST_LOG:-info,aegis_node_sensor=info}" \
    "$SENSOR_BIN" --config "$sensor_toml" --node-key "soak-host" >>"$SENSOR_LOG" 2>&1 &
  SENSOR_PID=$!
  sleep 3
  if ! kill -0 "$SENSOR_PID" 2>/dev/null; then
    printf 'sensor exited immediately\n' >&2
    tail -30 "$SENSOR_LOG" >&2 || true
    exit 1
  fi
}

# ── metrics sampling ─────────────────────────────────────────────────────────
rss_kb()   { awk '/^VmRSS:/ {print $2}' "/proc/$SENSOR_PID/status" 2>/dev/null || echo 0; }
fd_count() { find "/proc/$SENSOR_PID/fd" -mindepth 1 2>/dev/null | wc -l | tr -d ' '; }

# pending = file length − persisted ack offset; disk = raw file length.
lane_stat() { # lane_stat <lane-file> -> "pending disk"
  local log="$SPOOL_DIR/$1" state="$SPOOL_DIR/$1.state"
  local len=0 ack=0
  [[ -f "$log" ]] && len=$(stat -c %s "$log")
  [[ -f "$state" ]] && ack=$(cat "$state" 2>/dev/null || echo 0)
  echo "$(( len - ack )) $len"
}

take_sample() {
  local phase="$1" now normal_pending normal_disk critical_pending critical_disk
  now=$(date +%s)
  read -r normal_pending normal_disk <<<"$(lane_stat normal.log)"
  read -r critical_pending critical_disk <<<"$(lane_stat critical.log)"
  printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$now" "$phase" "$(rss_kb)" "$(fd_count)" \
    "$normal_pending" "$normal_disk" "$critical_pending" "$critical_disk" >>"$SAMPLES_CSV"
}

# ── workload ────────────────────────────────────────────────────────────────
# Everything the Wave A collectors watch for, continuously: a tagged host
# process (process + secret collectors), a tagged process holding a real TCP
# connection (net collector), and one holding a real file descriptor (fs
# collector). Short-lived so the workload itself can't leak.
spawn_workload_burst() {
  local run_id
  run_id="soak-wl-$(date +%s%N)"
  AEGIS_RUN_ID="$run_id" GITHUB_TOKEN="soak-fake-secret-value" \
    sleep "$WORKLOAD_INTERVAL_SECS" >/dev/null 2>&1 &
  WORKLOAD_PIDS+=($!)
  AEGIS_RUN_ID="$run_id" bash -c \
    "exec 3<>/dev/tcp/127.0.0.1/${LISTENER_PORT} 2>/dev/null; sleep ${WORKLOAD_INTERVAL_SECS}" \
    >/dev/null 2>&1 &
  WORKLOAD_PIDS+=($!)
  AEGIS_RUN_ID="$run_id" bash -c \
    "exec 3<>'$WORK_DIR/fs-probe.txt'; sleep ${WORKLOAD_INTERVAL_SECS}" \
    >/dev/null 2>&1 &
  WORKLOAD_PIDS+=($!)
  # Reap finished workload pids so the array (and process table) stay small.
  local alive=()
  for pid in "${WORKLOAD_PIDS[@]}"; do
    kill -0 "$pid" 2>/dev/null && alive+=("$pid")
  done
  WORKLOAD_PIDS=("${alive[@]:-}")
}

start_tcp_listener() {
  python3 - <<'PY' >"$WORK_DIR/listener-port.txt" 2>/dev/null &
import socket, sys, threading
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(64)
print(s.getsockname()[1], flush=True)
def serve():
    while True:
        try:
            conn, _ = s.accept()
        except OSError:
            return
        threading.Timer(6.0, conn.close).start()
serve()
PY
  WORKLOAD_PIDS+=($!)
  local _attempt
  for _attempt in $(seq 1 20); do
    LISTENER_PORT="$(cat "$WORK_DIR/listener-port.txt" 2>/dev/null || true)"
    [[ -n "$LISTENER_PORT" ]] && return 0
    sleep 0.5
  done
  printf 'tcp listener failed to start\n' >&2
  exit 1
}

# ── signed-kill enforcement round-trip ──────────────────────────────────────
KILLS_ATTEMPTED=0
KILLS_OK=0
kill_roundtrip() {
  KILLS_ATTEMPTED=$((KILLS_ATTEMPTED + 1))
  local run_key body code json run_id
  run_key="soak-kill-$(date +%s)-$$-${KILLS_ATTEMPTED}"
  body=$(curl -sS -w '\n%{http_code}' -X POST "$AEGIS_URL/v1/agent-cage/runs" \
    "${auth[@]}" \
    -d "{\"run_key\":\"${run_key}\",\"source_component\":\"sensor-soak\",\"mode\":\"observe\"}")
  code=$(printf '%s' "$body" | tail -n1)
  json=$(printf '%s' "$body" | sed '$d')
  if [[ "$code" != "201" ]]; then
    printf 'kill round-trip %s: create run failed HTTP %s\n' "$KILLS_ATTEMPTED" "$code" >&2
    return 0
  fi
  run_id=$(printf '%s' "$json" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')

  AEGIS_RUN_ID="$run_id" sleep 300 >/dev/null 2>&1 &
  local victim=$!
  WORKLOAD_PIDS+=("$victim")

  # The process collector polls /proc every 2s; give it two cycles before
  # issuing the signed kill, then require the real process to die.
  sleep 5
  local kill_code
  kill_code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST \
    "$AEGIS_URL/v1/agent-cage/runs/${run_id}/kill" \
    "${auth[@]}" \
    -d '{"actor":"sensor-soak","reason":"scheduled soak kill"}')
  if [[ "$kill_code" != "200" && "$kill_code" != "201" && "$kill_code" != "202" ]]; then
    printf 'kill round-trip %s: kill HTTP %s\n' "$KILLS_ATTEMPTED" "$kill_code" >&2
    kill "$victim" 2>/dev/null || true
    return 0
  fi

  local deadline=$((SECONDS + KILL_DEADLINE_SECS))
  while (( SECONDS < deadline )); do
    if ! kill -0 "$victim" 2>/dev/null; then
      KILLS_OK=$((KILLS_OK + 1))
      printf '    kill round-trip %s ok (run %s, pid %s died via signed command)\n' \
        "$KILLS_ATTEMPTED" "$run_id" "$victim"
      return 0
    fi
    sleep 1
  done
  printf 'kill round-trip %s: pid %s still alive after %ss\n' \
    "$KILLS_ATTEMPTED" "$victim" "$KILL_DEADLINE_SECS" >&2
  kill "$victim" 2>/dev/null || true
}

# ── build + start ────────────────────────────────────────────────────────────
printf '==> Build gateway + sensor\n'
cargo build -p gateway -p aegis-node-sensor

TD="$(target_dir)"
GATEWAY_BIN="${TD}/debug/gateway"
[[ ! -x "$GATEWAY_BIN" && -x "${TD}/debug/aegis-gateway" ]] && GATEWAY_BIN="${TD}/debug/aegis-gateway"
SENSOR_BIN="${TD}/debug/aegis-node-sensor"
for b in "$GATEWAY_BIN" "$SENSOR_BIN"; do
  [[ -x "$b" ]] || { printf 'missing binary: %s\n' "$b" >&2; exit 1; }
done

printf '==> Start gateway\n'
start_gateway
ensure_tenant
printf '==> Start sensor (enforce mode, spool at %s)\n' "$SPOOL_DIR"
start_sensor
start_tcp_listener

printf 'epoch,phase,rss_kb,fd_count,normal_pending,normal_disk,critical_pending,critical_disk\n' >"$SAMPLES_CSV"

# ── soak loop ────────────────────────────────────────────────────────────────
printf '==> Soak: %ss (outage at %s%% for %ss, kill round-trip every %ss)\n' \
  "$SOAK_DURATION_SECS" "$OUTAGE_AT_PCT" "$OUTAGE_SECS" "$KILL_INTERVAL_SECS"

SOAK_START=$SECONDS
STEADY_AT=$(( SOAK_DURATION_SECS * 20 / 100 ))
OUTAGE_AT=$(( SOAK_DURATION_SECS * OUTAGE_AT_PCT / 100 ))
STEADY_RSS=""
STEADY_FD=""
OUTAGE_DONE=0
POST_OUTAGE_KILL_OK=0
last_sample=0
last_workload=0
last_kill=0

while (( SECONDS - SOAK_START < SOAK_DURATION_SECS )); do
  elapsed=$(( SECONDS - SOAK_START ))

  if ! kill -0 "$SENSOR_PID" 2>/dev/null; then
    printf 'FAIL: sensor died at %ss\n' "$elapsed" >&2
    tail -40 "$SENSOR_LOG" >&2 || true
    exit 1
  fi

  if (( elapsed - last_workload >= WORKLOAD_INTERVAL_SECS )); then
    spawn_workload_burst
    last_workload=$elapsed
  fi

  if (( elapsed - last_sample >= SAMPLE_INTERVAL_SECS )); then
    phase="steady"
    (( OUTAGE_DONE == 0 && elapsed >= OUTAGE_AT )) && phase="outage"
    take_sample "$phase"
    last_sample=$elapsed
  fi

  # Steady-state baseline: the leak assertion compares against this, not
  # against startup (allocator warm-up and first-connection buffers land
  # in the first fifth of the soak).
  if [[ -z "$STEADY_RSS" ]] && (( elapsed >= STEADY_AT )); then
    STEADY_RSS=$(rss_kb)
    STEADY_FD=$(fd_count)
    printf '    steady-state baseline at %ss: rss=%skB fds=%s\n' "$elapsed" "$STEADY_RSS" "$STEADY_FD"
  fi

  # Mid-soak gateway outage: events must buffer durably, the sensor must
  # not crash, and everything must recover unattended after restart.
  if (( OUTAGE_DONE == 0 && elapsed >= OUTAGE_AT )); then
    printf '==> Outage: stopping gateway for %ss (sensor must buffer + survive)\n' "$OUTAGE_SECS"
    kill "$GATEWAY_PID" 2>/dev/null || true
    wait "$GATEWAY_PID" 2>/dev/null || true
    GATEWAY_PID=""
    outage_end=$(( SECONDS + OUTAGE_SECS ))
    while (( SECONDS < outage_end )); do
      spawn_workload_burst
      take_sample "outage"
      sleep "$WORKLOAD_INTERVAL_SECS"
    done
    printf '==> Outage over: restarting gateway\n'
    start_gateway
    OUTAGE_DONE=1
    # Recovery proof: a full signed-kill round-trip must work end-to-end
    # after the outage without touching the sensor.
    sleep 10
    before=$KILLS_OK
    kill_roundtrip
    (( KILLS_OK > before )) && POST_OUTAGE_KILL_OK=1
    last_kill=$(( SECONDS - SOAK_START ))
  fi

  if (( elapsed - last_kill >= KILL_INTERVAL_SECS )); then
    kill_roundtrip
    last_kill=$elapsed
  fi

  sleep 1
done

# ── drain + final assertions ─────────────────────────────────────────────────
printf '==> Soak loop done, letting the spool drain %ss\n' "$DRAIN_GRACE_SECS"
sleep "$DRAIN_GRACE_SECS"
take_sample "final"

FINAL_RSS=$(rss_kb)
FINAL_FD=$(fd_count)
read -r NORMAL_PENDING NORMAL_DISK <<<"$(lane_stat normal.log)"
read -r CRITICAL_PENDING CRITICAL_DISK <<<"$(lane_stat critical.log)"
PANICS=$(grep -c "panicked" "$SENSOR_LOG" || true)
CORRUPTIONS=$(grep -c "spool corruption detected" "$SENSOR_LOG" || true)

fail=0
note() { printf '    %s\n' "$1"; }
check() { # check <ok-condition> <label>
  if eval "$1"; then note "PASS: $2"; else note "FAIL: $2"; fail=1; fi
}

printf '==> Assertions\n'
check "kill -0 $SENSOR_PID 2>/dev/null" "sensor survived the full soak"
check "[[ ${PANICS:-0} -eq 0 ]]" "zero panics in sensor log (found ${PANICS:-0})"
check "[[ ${CORRUPTIONS:-0} -eq 0 ]]" "zero spool corruption events (found ${CORRUPTIONS:-0})"
check "[[ -n \"$STEADY_RSS\" && $FINAL_RSS -le $(( STEADY_RSS * (100 + MAX_RSS_GROWTH_PCT) / 100 )) ]]" \
  "RSS bounded: steady ${STEADY_RSS:-?}kB -> final ${FINAL_RSS}kB (limit +${MAX_RSS_GROWTH_PCT}%)"
check "[[ -n \"$STEADY_FD\" && $FINAL_FD -le $(( STEADY_FD + MAX_FD_GROWTH )) ]]" \
  "fd count bounded: steady ${STEADY_FD:-?} -> final ${FINAL_FD} (limit +${MAX_FD_GROWTH})"
check "[[ $NORMAL_PENDING -eq 0 && $CRITICAL_PENDING -eq 0 ]]" \
  "spool drained after grace (normal pending=${NORMAL_PENDING}, critical pending=${CRITICAL_PENDING})"
check "[[ $NORMAL_DISK -le $SPOOL_DISK_BOUND_BYTES && $CRITICAL_DISK -le $SPOOL_DISK_BOUND_BYTES ]]" \
  "spool disk bounded by live compaction (normal=${NORMAL_DISK}B, critical=${CRITICAL_DISK}B, bound=${SPOOL_DISK_BOUND_BYTES}B)"
check "[[ $KILLS_OK -ge 1 && $KILLS_OK -eq $KILLS_ATTEMPTED ]]" \
  "signed kill round-trips: ${KILLS_OK}/${KILLS_ATTEMPTED} succeeded"
check "[[ $POST_OUTAGE_KILL_OK -eq 1 ]]" "post-outage recovery kill round-trip succeeded"

python3 - "$SUMMARY_JSON" <<PY
import json, sys
json.dump({
    "duration_secs": ${SOAK_DURATION_SECS},
    "steady_rss_kb": ${STEADY_RSS:-0}, "final_rss_kb": ${FINAL_RSS},
    "steady_fds": ${STEADY_FD:-0}, "final_fds": ${FINAL_FD},
    "normal_pending": ${NORMAL_PENDING}, "normal_disk": ${NORMAL_DISK},
    "critical_pending": ${CRITICAL_PENDING}, "critical_disk": ${CRITICAL_DISK},
    "kills_ok": ${KILLS_OK}, "kills_attempted": ${KILLS_ATTEMPTED},
    "post_outage_kill_ok": bool(${POST_OUTAGE_KILL_OK}),
    "panics": ${PANICS:-0}, "spool_corruptions": ${CORRUPTIONS:-0},
    "passed": not bool(${fail}),
}, open(sys.argv[1], "w"), indent=2)
PY

if (( fail )); then
  printf '==> Sensor soak FAILED (artifacts in %s)\n' "$ARTIFACT_DIR" >&2
  exit 1
fi
printf '==> Sensor soak PASSED (%ss; artifacts in %s)\n' "$SOAK_DURATION_SECS" "$ARTIFACT_DIR"
