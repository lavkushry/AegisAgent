#!/usr/bin/env bash
# Verify backend API + frontend console + LLM proxy on docker-compose.stack.yml
set -euo pipefail
GW="${AEGIS_GATEWAY_URL:-http://127.0.0.1:8080}"
LLM="${AEGIS_LLM_GATEWAY_URL:-http://127.0.0.1:8090}"
TENANT="${AEGIS_API_TOKEN:-tenant_docker_e2e}"

echo "==> backend /livez"
curl -sf "$GW/livez" | tee /dev/stderr | grep -q alive

echo "==> backend /v1/stats (as $TENANT)"
curl -sf "$GW/v1/stats" -H "Authorization: Bearer $TENANT" | tee /dev/stderr | grep -q total_decisions

echo "==> frontend /dashboard/"
code=$(curl -sf -o /tmp/aegis-dash.html -w '%{http_code}' "$GW/dashboard/")
test "$code" = "200"
grep -q 'csrf-token' /tmp/aegis-dash.html
# Next static assets must load for hydration
chunk=$(grep -oE '/dashboard/_next/static/[^"]+\.js' /tmp/aegis-dash.html | head -1 || true)
if [[ -n "$chunk" ]]; then
  ccode=$(curl -sf -o /dev/null -w '%{http_code}' "$GW$chunk")
  echo "frontend asset $chunk -> $ccode"
  test "$ccode" = "200"
fi

echo "==> LLM proxy chat completions"
RESP=$(curl -sf -X POST "$LLM/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"stack smoke"}]}')
echo "$RESP" | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d["choices"][0]["message"]["content"]'
echo "LLM proxy OK"

echo ""
echo "Stack smoke passed."
echo "  Frontend: $GW/dashboard/"
echo "  Backend:  $GW/v1/..."
echo "  LLM proxy: $LLM"
echo "  In Settings set Gateway URL=$GW and Bearer/Tenant=$TENANT"
