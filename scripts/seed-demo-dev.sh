#!/bin/sh
# #1203: dev-only seed script for docker-compose.dev.yml. Unlike
# scripts/seed-demo.sh (one tenant/agent, used by CI's Docker Compose E2E
# and the github-attack-demo.py walkthrough), this seeds enough data that the
# SOC dashboard has something to show immediately after `docker compose -f
# docker-compose.dev.yml up`: 2 tenants, 3 agents, the demo tool/policy
# registrations, and a real deny_storm incident (not a canned fixture --
# triggered through the actual /v1/authorize + correlation pipeline).
#
# POSIX sh, not bash: runs both on a developer's host and inside the
# curlimages/curl (Alpine/ash) container docker-compose.dev.yml uses to seed
# automatically.
set -eu

AEGIS_URL="${AEGIS_URL:-http://127.0.0.1:8080}"
TENANT_ALPHA="${TENANT_ALPHA:-tenant_dev_alpha}"
TENANT_BETA="${TENANT_BETA:-tenant_dev_beta}"

printf '==> Checking AegisAgent gateway at %s\n' "$AEGIS_URL"
curl -fsS "$AEGIS_URL/health" >/dev/null
printf '==> Gateway is healthy\n'

create_tenant() {
  tenant_id="$1"
  name="$2"
  printf '==> Ensuring tenant (%s) exists\n' "$tenant_id"
  status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$AEGIS_URL/v1/tenants" \
    -H "Content-Type: application/json" \
    -d "{\"id\": \"$tenant_id\", \"name\": \"$name\", \"plan\": \"free\"}")
  if [ "$status" != "201" ] && [ "$status" != "409" ]; then
    printf 'Failed to create tenant %s (HTTP %s)\n' "$tenant_id" "$status" >&2
    exit 1
  fi
}

register_github_tool() {
  tenant_id="$1"
  printf '==> Registering mock GitHub tool actions for %s\n' "$tenant_id"
  curl -fsS -X POST "$AEGIS_URL/v1/tools" \
    -H "Authorization: Bearer $tenant_id" \
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
}

# Registers an agent and prints its plaintext agent_token on stdout (the only
# output of this function -- callers capture it via command substitution).
register_agent() {
  tenant_id="$1"
  agent_key="$2"
  name="$3"
  response=$(curl -fsS -X POST "$AEGIS_URL/v1/agents/register" \
    -H "Authorization: Bearer $tenant_id" \
    -H "Content-Type: application/json" \
    -d "{\"agent_key\": \"$agent_key\", \"name\": \"$name\", \"owner_team\": \"platform\", \"environment\": \"production\", \"framework\": \"demo-script\", \"model_provider\": \"mock\", \"model_name\": \"mock-agent\", \"risk_tier\": \"medium\", \"purpose\": \"docker-compose.dev.yml seed\"}")
  printf '%s' "$response" | sed -n 's/.*"agent_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

create_tenant "$TENANT_ALPHA" "Dev Tenant Alpha"
create_tenant "$TENANT_BETA" "Dev Tenant Beta"

register_github_tool "$TENANT_ALPHA"
register_github_tool "$TENANT_BETA"

printf '==> Registering 3 demo agents (2 in alpha, 1 in beta)\n'
ALPHA_TOKEN_1=$(register_agent "$TENANT_ALPHA" "coding-agent-alpha-1" "Alpha Coding Agent 1")
register_agent "$TENANT_ALPHA" "coding-agent-alpha-2" "Alpha Coding Agent 2" >/dev/null
register_agent "$TENANT_BETA" "coding-agent-beta-1" "Beta Coding Agent 1" >/dev/null

# #1203 (AC #2): trigger a real deny_storm incident through the actual
# /v1/authorize + correlation pipeline, not a canned fixture. The global
# Cedar policy (policies.cedar) denies any mutating action under
# malicious_suspected trust -- 5 of those for the same agent inside the
# correlation engine's 60s window crosses correlate.rs's DENY_STORM_N
# threshold and raises a HIGH incident, visible immediately via
# GET /v1/incidents and the SOC dashboard.
printf '==> Triggering a deny_storm incident for coding-agent-alpha-1 (5 denied merge attempts under malicious_suspected trust)\n'
i=1
while [ "$i" -le 5 ]; do
  curl -fsS -X POST "$AEGIS_URL/v1/authorize" \
    -H "Authorization: Bearer $ALPHA_TOKEN_1" \
    -H "X-Aegis-Tenant-ID: $TENANT_ALPHA" \
    -H "Content-Type: application/json" \
    -d "{\"agent\": {\"id\": \"coding-agent-alpha-1\", \"environment\": \"production\"}, \"tool_call\": {\"tool\": \"github\", \"action\": \"merge_pull_request\", \"resource\": \"repo/example/pull/$i\", \"mutates_state\": true, \"parameters\": {}}, \"context\": {\"source_trust\": \"malicious_suspected\", \"contains_sensitive_data\": false}}" \
    >/dev/null
  i=$((i + 1))
done

printf '==> Demo seed complete:\n'
printf '    Tenants: %s, %s\n' "$TENANT_ALPHA" "$TENANT_BETA"
printf '    Agents: coding-agent-alpha-1, coding-agent-alpha-2, coding-agent-beta-1\n'
printf '    Incidents: a deny_storm should now be visible at %s/v1/incidents?kind=deny_storm\n' "$AEGIS_URL"
printf '    Dashboard: %s/dashboard/\n' "$AEGIS_URL"
