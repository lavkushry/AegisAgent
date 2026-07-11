# Runbook: Deny Storm

**Incident kind:** `deny_storm` · **Severity:** `high` · **Detection rule:** `correlate::rule_deny_storm`

> **Status:** Implemented deterministic correlation. Automatic freeze depends on the tenant's configured SOC autonomy level.

## Overview

Use this runbook when one agent repeatedly receives deny decisions in a short window. The usual cause is a retry loop or stale integration, but varied actions/resources may indicate active probing. Preserve the evidence, stop the loop, distinguish defect from compromise, and restore only after the caller is corrected.

## Symptoms

- A SOC alert/incident with `kind: "deny_storm"` appears in `GET /v1/incidents` or the live `GET /v1/ws/events` feed.
- An outbound Slack/webhook notification fires (see [`slack-integration.md`](../slack-integration.md) §3) — `deny` decisions are always high-signal.
- One agent accumulates **5 or more `deny` decisions within 60 seconds** (`DENY_STORM_N` / `DENY_STORM_WINDOW_SECS`, `lib/soc/src/correlate.rs`) — the rule fires exactly once, at the threshold crossing, not on every subsequent deny.

This is distinct from auto risk-tier escalation (#1296): that mechanism uses a separate, slower default threshold (5 denials within a rolling **60 minutes**, configurable via `GET|PUT /v1/tenants/risk-escalation`) and tightens `agents.risk_tier`, which is real authorization state. A `deny_storm` incident can fire well before risk-tier escalation would trigger.

## Before you start: check whether this already auto-resolved

The Response Engine (`lib/soc/src/respond.rs`) maps `deny_storm` → **freeze the agent**, but only runs at SOC autonomy level `L3`/`L4`. The default is `L1` (notify only — no auto-freeze). Check the tenant's effective level first:

```bash
# No HTTP API exists for this yet — it's read from `tenants.soc_autonomy_level`
# (DB override) or the AEGIS_SOC_AUTONOMY_LEVEL env var, default "L1".
sqlite3 db/aegisagent.db "SELECT id, soc_autonomy_level FROM tenants WHERE id = '<tenant_id>';"
```

If the level is `L3`/`L4`, the agent is **already frozen** — skip to Investigation; remediation is to confirm the freeze was correct, not to perform it yourself.

## Investigation

1. **Find the incident:**
   ```bash
   curl -s -H "Authorization: Bearer $AGENT_TOKEN" \
     "http://127.0.0.1:8080/v1/incidents?severity=high&status=open" | jq '.[] | select(.kind=="deny_storm")'
   ```
2. **Pull its evidence graph** (every decision behind it, with `risk_score`/`reason` and matched policies):
   ```bash
   curl -s -H "Authorization: Bearer $AGENT_TOKEN" \
     "http://127.0.0.1:8080/v1/graph/incident/<incident_id>"
   ```
   See [`evidence-graph.md`](../evidence-graph.md) for the full investigation workflow (incident → run → agent history → receipt verification).
3. **List the raw denied decisions** for the agent to see the actual tool/action pattern:
   ```bash
   curl -s -H "Authorization: Bearer $AGENT_TOKEN" \
     "http://127.0.0.1:8080/v1/decisions?agent_id=<agent_id>&decision=deny"
   ```
4. **Generate an RCA narrative** (sandboxed LLM summarizer, post-decision only — Design Law 2):
   ```bash
   curl -s -H "Authorization: Bearer $AGENT_TOKEN" \
     "http://127.0.0.1:8080/v1/incidents/<incident_id>/narrate"
   ```
5. Determine the cause: a **misconfigured agent** (e.g. retrying a denied action in a loop, wrong tool/action name) is the common case; an **active attacker** probing for an allowed action is rarer but more urgent — look for varied `action`/`resource` values across the denied decisions as a signal of probing rather than a single repeated mistake.

## Remediation

- **Misconfigured agent:** freeze while you fix the caller, then unfreeze:
  ```bash
  curl -s -X POST -H "Authorization: Bearer $AGENT_TOKEN" \
    "http://127.0.0.1:8080/v1/agents/<agent_id>/freeze" -d '{"reason": "deny storm — investigating retry loop"}'
  # ... fix the calling code/config ...
  curl -s -X POST -H "Authorization: Bearer $AGENT_TOKEN" \
    "http://127.0.0.1:8080/v1/agents/<agent_id>/unfreeze"
  ```
- **Suspected attack/compromise:** revoke instead of unfreezing, and rotate the token if it may have leaked (see [`agent-token-rotation.md`](agent-token-rotation.md)):
  ```bash
  curl -s -X POST -H "Authorization: Bearer $AGENT_TOKEN" \
    "http://127.0.0.1:8080/v1/agents/<agent_id>/revoke"
  ```
- Close the incident once handled:
  ```bash
  curl -s -X POST -H "Authorization: Bearer $AGENT_TOKEN" \
    "http://127.0.0.1:8080/v1/incidents/<incident_id>/close"
  ```

## Verification

- `GET /v1/agents/:id` shows the expected `status` (`active` after unfreeze, or `revoked`).
- `GET /v1/incidents/<incident_id>` shows `status: "closed"`.
- No new `deny_storm` incident for the same agent within the next `DENY_STORM_WINDOW_SECS` (60s) window after remediation.
- If you rotated the token, confirm the old token is rejected: a `/v1/authorize` call with the old token now returns `401`.

## Security and Failure Handling

- Do not change policy to allow the denied action merely to stop alert noise.
- Use a separate operator credential for containment when the agent token may be compromised.
- Tenant autonomy state is currently read from configuration/storage; direct SQLite inspection is a local single-node diagnostic, not the preferred enterprise control path.
- A deny storm can exhaust quotas and obscure other activity. Preserve the incident evidence before clearing or restarting clients.
- If freeze/revoke fails, disable the workload and revoke its upstream credentials outside AegisAgent.

## Rollback and Recovery

For a confirmed configuration defect, deploy the corrected client while the agent remains frozen, perform one controlled authorization check, then unfreeze. For suspected compromise, revocation is not rolled back; register or re-establish identity only after investigation and credential rotation.

## References

- [Agent Token Rotation](agent-token-rotation.md)
- [Evidence Graph](../evidence-graph.md)
- [Data Exfiltration](data-exfiltration.md)
- [Fail-Closed Behavior](../fail-closed-behavior.md)
- [SOC Engine](../components/SOC_Engine.md)
