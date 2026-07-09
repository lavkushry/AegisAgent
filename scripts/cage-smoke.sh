#!/usr/bin/env bash
# Cage claim-path smoke (HTTP) — does NOT require Docker or aegis-cage-runner.
# Exercises: create run with cage_spec → signed start_run exists → claim →
# heartbeat → status running → finished. Second claim returns 409.
#
# Prerequisites:
#   - Gateway listening (default http://127.0.0.1:8080)
#   - Gateway started with AEGIS_COMMAND_SIGNING_KEY set (32-byte seed hex)
#   - curl + python3
#
# Usage:
#   AEGIS_COMMAND_SIGNING_KEY=... cargo run -p gateway --bin gateway &
#   ./scripts/cage-smoke.sh
set -euo pipefail

AEGIS_URL="${AEGIS_URL:-http://127.0.0.1:8080}"
TENANT_ID="${TENANT_ID:-tenant_dev_alpha}"
# Local/dev: tenant-prefixed bearer is accepted when JWT is off.
TOKEN="${AEGIS_API_TOKEN:-$TENANT_ID}"
RUNNER_ID="${AEGIS_CAGE_RUNNER_ID:-cage-smoke-runner}"
RUN_KEY="cage-smoke-$(date +%s)"

auth=(-H "Authorization: Bearer ${TOKEN}" -H "X-Aegis-Tenant-ID: ${TENANT_ID}" -H "Content-Type: application/json")

printf '==> Gateway health at %s\n' "$AEGIS_URL"
if ! curl -fsS "$AEGIS_URL/livez" >/dev/null 2>&1 && ! curl -fsS "$AEGIS_URL/health" >/dev/null 2>&1; then
  printf 'Gateway not reachable at %s\n' "$AEGIS_URL" >&2
  exit 1
fi

printf '==> Ensure tenant %s\n' "$TENANT_ID"
code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$AEGIS_URL/v1/tenants" \
  -H "Content-Type: application/json" \
  -d "{\"id\":\"${TENANT_ID}\",\"name\":\"Cage Smoke\",\"plan\":\"free\"}" || true)
if [[ "$code" != "201" && "$code" != "409" && "$code" != "200" ]]; then
  printf 'tenant create HTTP %s (continuing if tenant already usable)\n' "$code" >&2
fi

printf '==> POST /v1/agent-cage/runs (cage_spec) run_key=%s\n' "$RUN_KEY"
create_body=$(curl -sS -w '\n%{http_code}' -X POST "$AEGIS_URL/v1/agent-cage/runs" \
  "${auth[@]}" \
  -d @- <<JSON
{
  "run_key": "${RUN_KEY}",
  "source_component": "cage-smoke",
  "mode": "observe",
  "cage_spec": {
    "image_ref": "alpine:latest",
    "command": ["echo", "cage-smoke"],
    "working_dir": "/workspace",
    "resources": {
      "cpu_millis": 250,
      "memory_bytes": 134217728,
      "process_limit": 16,
      "timeout_seconds": 30
    },
    "network": { "direct_internet": false }
  }
}
JSON
)
create_code=$(printf '%s' "$create_body" | tail -n1)
create_json=$(printf '%s' "$create_body" | sed '$d')
if [[ "$create_code" == "503" ]]; then
  printf 'Gateway returned 503 — set AEGIS_COMMAND_SIGNING_KEY on the gateway and retry.\n' >&2
  printf '%s\n' "$create_json" >&2
  exit 1
fi
if [[ "$create_code" != "201" ]]; then
  printf 'create run failed HTTP %s\n%s\n' "$create_code" "$create_json" >&2
  exit 1
fi

RUN_ID=$(printf '%s' "$create_json" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
printf '    run_id=%s status=started\n' "$RUN_ID"

printf '==> GET /v1/control/commands (expect start_run issued)\n'
cmds=$(curl -fsS "$AEGIS_URL/v1/control/commands?limit=50" "${auth[@]}")
printf '%s' "$cmds" | python3 -c "
import json, sys
run_id = '''${RUN_ID}'''
rows = json.load(sys.stdin)
assert isinstance(rows, list), type(rows)
found = False
for c in rows:
    if c.get('target_id') == run_id and c.get('action') == 'start_run':
        found = True
        assert c.get('status') == 'issued', c
        assert c.get('signature'), 'start_run must be signed'
        print(f\"    start_run command_id={c.get('command_id')} ok\")
        break
assert found, f'no start_run for {run_id} in {len(rows)} commands'
"

printf '==> POST claim as %s\n' "$RUNNER_ID"
claim=$(curl -sS -w '\n%{http_code}' -X POST "$AEGIS_URL/v1/agent-cage/runs/${RUN_ID}/claim" \
  "${auth[@]}" \
  -d "{\"runner_id\":\"${RUNNER_ID}\"}")
claim_code=$(printf '%s' "$claim" | tail -n1)
claim_json=$(printf '%s' "$claim" | sed '$d')
if [[ "$claim_code" != "200" ]]; then
  printf 'claim failed HTTP %s\n%s\n' "$claim_code" "$claim_json" >&2
  exit 1
fi
printf '%s' "$claim_json" | python3 -c 'import sys,json; r=json.load(sys.stdin); assert r["status"]=="claimed", r; assert r.get("claimed_by"); print("    claimed_by=", r["claimed_by"])'

printf '==> Second claim must 409\n'
code2=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$AEGIS_URL/v1/agent-cage/runs/${RUN_ID}/claim" \
  "${auth[@]}" \
  -d '{"runner_id":"other-runner"}')
if [[ "$code2" != "409" ]]; then
  printf 'expected 409 on second claim, got %s\n' "$code2" >&2
  exit 1
fi
printf '    conflict ok\n'

printf '==> Heartbeat\n'
hb=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$AEGIS_URL/v1/agent-cage/runs/${RUN_ID}/heartbeat" \
  "${auth[@]}" \
  -d "{\"runner_id\":\"${RUNNER_ID}\"}")
[[ "$hb" == "200" ]] || { printf 'heartbeat HTTP %s\n' "$hb" >&2; exit 1; }

printf '==> Status running → finished\n'
for st in running finished; do
  extra=""
  [[ "$st" == "finished" ]] && extra=', "finished_at": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"'
  code=$(curl -sS -o /tmp/cage-smoke-status.json -w '%{http_code}' -X POST \
    "$AEGIS_URL/v1/agent-cage/runs/${RUN_ID}/status" \
    "${auth[@]}" \
    -d "{\"runner_id\":\"${RUNNER_ID}\",\"status\":\"${st}\"${extra}}")
  [[ "$code" == "200" ]] || { printf 'status %s HTTP %s\n' "$st" "$code" >&2; cat /tmp/cage-smoke-status.json >&2; exit 1; }
  python3 -c "import json; r=json.load(open('/tmp/cage-smoke-status.json')); assert r['status']=='$st', r"
  printf '    %s ok\n' "$st"
done

printf '==> Cage claim-path smoke PASSED (run_id=%s)\n' "$RUN_ID"
