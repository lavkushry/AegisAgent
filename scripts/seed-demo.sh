#!/usr/bin/env bash
set -euo pipefail

AEGIS_URL="${AEGIS_URL:-http://127.0.0.1:8080}"
TENANT_ID="${TENANT_ID:-tenant_123}"
AGENT_KEY="${AGENT_KEY:-coding-agent-prod}"

printf '==> Checking AegisAgent gateway at %s\n' "$AEGIS_URL"
curl -fsS "$AEGIS_URL/health" >/dev/null
printf '==> Gateway is healthy\n'

printf '==> Ensuring tenant (%s) exists\n' "$TENANT_ID"
tenant_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$AEGIS_URL/v1/tenants" \
  -H "Content-Type: application/json" \
  -d "{\"id\": \"$TENANT_ID\", \"name\": \"Demo Tenant\", \"plan\": \"free\"}")
if [ "$tenant_status" != "201" ] && [ "$tenant_status" != "409" ]; then
  printf 'Failed to create tenant %s (HTTP %s)\n' "$TENANT_ID" "$tenant_status" >&2
  exit 1
fi

printf '==> Registering demo agent (%s)\n' "$AGENT_KEY"
curl -fsS -X POST "$AEGIS_URL/v1/agents/register" \
  -H "Authorization: Bearer $TENANT_ID" \
  -H "Content-Type: application/json" \
  -d @- >/dev/null <<JSON
{
  "agent_key": "$AGENT_KEY",
  "name": "Production Coding Agent",
  "owner_team": "platform",
  "environment": "production",
  "framework": "demo-script",
  "model_provider": "mock",
  "model_name": "mock-agent",
  "risk_tier": "high",
  "purpose": "Local GitHub attack demo"
}
JSON

printf '==> Registering mock GitHub tool actions\n'
curl -fsS -X POST "$AEGIS_URL/v1/tools" \
  -H "Authorization: Bearer $TENANT_ID" \
  -H "Content-Type: application/json" \
  -d @- >/dev/null <<'JSON'
{
  "skill_key": "github",
  "name": "Mock GitHub Client",
  "type": "static",
  "auth_type": "mock",
  "owner_team": "platform",
  "default_risk": "medium",
  "actions": [
    {
      "action_key": "read_issue",
      "description": "Read a GitHub issue",
      "risk": "low",
      "mutates_state": false,
      "data_access": "repository_metadata",
      "approval_required": false,
      "default_decision": "policy"
    },
    {
      "action_key": "merge_pull_request",
      "description": "Merge a pull request into a base branch",
      "risk": "high",
      "mutates_state": true,
      "data_access": "repository_write",
      "approval_required": true,
      "default_decision": "policy"
    }
  ]
}
JSON

printf '==> Registering demo MCP server and manifest\n'
curl -fsS -X POST "$AEGIS_URL/v1/mcp/servers" \
  -H "Authorization: Bearer $TENANT_ID" \
  -H "Content-Type: application/json" \
  -d @- >/dev/null <<'JSON'
{
  "server_key": "github-mcp-demo",
  "name": "GitHub MCP Demo",
  "owner_team": "platform",
  "transport": "streamable_http",
  "source": "local-demo",
  "trust_level": "trusted_internal_signed",
  "endpoint": "http://127.0.0.1:9001/mcp"
}
JSON

curl -fsS -X POST "$AEGIS_URL/v1/mcp/servers/github-mcp-demo/tools" \
  -H "Authorization: Bearer $TENANT_ID" \
  -H "Content-Type: application/json" \
  -d @- >/dev/null <<'JSON'
{
  "tools": [
    {
      "tool_key": "create_issue",
      "name": "Create issue",
      "description": "Create a GitHub issue through MCP",
      "input_schema": {"type": "object"},
      "risk": "medium",
      "mutates_state": true,
      "approval_required": false
    }
  ]
}
JSON

printf '==> Default policy pack: %s\n' "${CEDAR_POLICY_PATH:-policies.cedar}"
printf '==> Demo seed complete. Run: python3 examples/github-attack-demo.py\n'
