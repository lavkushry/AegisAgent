#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

AEGIS_URL="${AEGIS_URL:-http://127.0.0.1:8080}"
TENANT_ID="${TENANT_ID:-tenant_123}"
AGENT_KEY="${AGENT_KEY:-coding-agent-prod}"
HEALTH_RETRIES="${AEGIS_DEMO_HEALTH_RETRIES:-60}"
LOG_DIR="${AEGIS_DEMO_LOG_DIR:-.aegis-demo}"
PROMPT_LOG="$LOG_DIR/prompt-injection.log"
APPROVAL_LOG="$LOG_DIR/approval-integrity.log"

if [ -z "${PYTHON_BIN:-}" ]; then
  if [ -x "$ROOT_DIR/.venv/bin/python" ]; then
    PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
  else
    PYTHON_BIN="python3"
  fi
fi

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'Missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

print_step() {
  printf '\n==> %s\n' "$1"
}

require_command docker
require_command curl
if ! docker info >/dev/null 2>&1; then
  printf 'Docker daemon is not running. Start Docker Desktop or dockerd, then run `make demo` again.\n' >&2
  exit 1
fi
if ! "$PYTHON_BIN" --version >/dev/null 2>&1; then
  printf 'Python command is not runnable: %s\n' "$PYTHON_BIN" >&2
  exit 1
fi

mkdir -p "$LOG_DIR"

print_step "Starting local AegisAgent gateway"
docker compose up --build -d

print_step "Waiting for gateway health at $AEGIS_URL"
healthy=0
for attempt in $(seq 1 "$HEALTH_RETRIES"); do
  if curl -fsS "$AEGIS_URL/health" >/dev/null 2>&1; then
    healthy=1
    break
  fi
  printf '  waiting (%s/%s)\n' "$attempt" "$HEALTH_RETRIES"
  sleep 2
done

if [ "$healthy" != "1" ]; then
  printf 'Gateway did not become healthy. Recent Docker logs:\n' >&2
  docker compose logs --tail=120 gateway >&2 || true
  exit 1
fi

print_step "Seeding demo tenant, coding agent, GitHub tool, and MCP metadata"
AEGIS_URL="$AEGIS_URL" TENANT_ID="$TENANT_ID" AGENT_KEY="$AGENT_KEY" \
  bash scripts/seed-demo.sh

print_step "Demo 1: prompt-injected GitHub issue cannot drive a dangerous merge"
AEGIS_URL="$AEGIS_URL" TENANT_ID="$TENANT_ID" AGENT_KEY="$AGENT_KEY" \
  "$PYTHON_BIN" examples/github-attack-demo.py 2>&1 | tee "$PROMPT_LOG"
grep -q "AegisAgent blocked the malicious merge attempt" "$PROMPT_LOG"

print_step "Demo 2: approval is bound to exact parameters and swapped action_hash fails closed"
AEGIS_URL="$AEGIS_URL" TENANT_ID="$TENANT_ID" AGENT_KEY="$AGENT_KEY" \
  "$PYTHON_BIN" examples/approve_then_swap_demo.py 2>&1 | tee "$APPROVAL_LOG"
grep -q "Gateway rejected the swapped claimed_action_hash" "$APPROVAL_LOG"
grep -q "Replay Blocked" "$APPROVAL_LOG"

print_step "Receipt chain head"
curl -fsS \
  -H "Authorization: Bearer $TENANT_ID" \
  "$AEGIS_URL/v1/receipts/chain-head" | "$PYTHON_BIN" -m json.tool

print_step "Server-side receipt range verification"
verify_response="$(
  curl -fsS -X POST \
    -H "Authorization: Bearer $TENANT_ID" \
    -H "Content-Type: application/json" \
    -d '{}' \
    "$AEGIS_URL/v1/receipts/verify-range"
)"
printf '%s\n' "$verify_response" | "$PYTHON_BIN" -m json.tool
printf '%s\n' "$verify_response" | "$PYTHON_BIN" -c '
import json
import sys

payload = json.load(sys.stdin)
if not payload.get("verified") or payload.get("count", 0) < 1:
    raise SystemExit("receipt range did not verify with at least one receipt")
'

print_step "Proof links"
printf 'Audit events:   %s/v1/audit/events\n' "$AEGIS_URL"
printf 'Receipts:       %s/v1/receipts\n' "$AEGIS_URL"
printf 'Chain head:     %s/v1/receipts/chain-head\n' "$AEGIS_URL"
printf 'Demo logs:      %s\n' "$LOG_DIR"

printf '\nAegisAgent killer demo completed successfully.\n'
