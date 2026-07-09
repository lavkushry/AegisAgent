#!/usr/bin/env bash
# Smoke-test docker-compose.llm-e2e.yml once the stack is healthy.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GW="${AEGIS_GATEWAY_URL:-http://127.0.0.1:8080}"
LLM="${AEGIS_LLM_GATEWAY_URL:-http://127.0.0.1:8090}"
TENANT="${AEGIS_API_TOKEN:-tenant_docker_e2e}"

echo "==> wait for gateway"
for i in $(seq 1 60); do
  if curl -sf "$GW/livez" >/dev/null; then
    echo "gateway live (${i}s)"
    break
  fi
  sleep 1
done
curl -sf "$GW/livez" | head -c 200
echo

echo "==> ensure tenant $TENANT"
curl -sf -X POST "$GW/v1/tenants" \
  -H 'Content-Type: application/json' \
  -d "{\"id\":\"$TENANT\",\"name\":\"Docker E2E\",\"plan\":\"free\"}" \
  >/dev/null || true

echo "==> chat completions via llm-gateway"
RESP=$(curl -sf -X POST "$LLM/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello docker e2e lineage"}]}')
echo "$RESP"
echo "$RESP" | python3 -c 'import sys,json; d=json.load(sys.stdin); assert "docker-e2e-ok" in d["choices"][0]["message"]["content"]; print("proxy OK")'

echo "==> inspect model_call_events in container volume"
DB="$ROOT/data-e2e/aegis.db"
if command -v sqlite3 >/dev/null && [[ -f "$DB" ]]; then
  sleep 1
  sqlite3 "$DB" "SELECT tenant_id, provider, model, status, token_counts_json, run_id FROM model_call_events ORDER BY received_at DESC LIMIT 3;"
  sqlite3 "$DB" "SELECT count(*) AS model_calls FROM model_call_events; SELECT count(*) AS prompts FROM prompt_events;"
else
  echo "(sqlite3 or $DB missing — check docker logs for llm-gateway ship)"
  docker compose -f "$ROOT/docker-compose.llm-e2e.yml" logs --tail=30 llm-gateway
fi

echo "==> e2e smoke passed"
