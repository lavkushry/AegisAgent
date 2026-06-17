# Runbook: Rotating a Leaked Agent Token

**Endpoints:** `POST /v1/agents/:id/rotate-token` · `POST /v1/agents/:id/report-leaked-token` (#1295)

## Symptoms

- A token appeared somewhere it shouldn't have (a log line, a public repo commit, a Slack message, a CI artifact, a support ticket screenshot).
- A `deny_storm` or `data_exfil_pattern` incident (see those runbooks) suggests the agent may be compromised, even without direct evidence of a leaked token.
- An `agent_token_leak_detected` SOC event appeared in the audit/event stream from an automated leak-detection integration (e.g. a secret scanner webhook feeding `POST /v1/ingest`).

## Investigation

1. **Confirm which agent owns the token** and its current status:
   ```bash
   curl -s -H "Authorization: Bearer $AGENT_TOKEN" "http://127.0.0.1:8080/v1/agents/<agent_id>"
   ```
2. **Check the tenant's auto-rotate setting.** `report-leaked-token` only rotates automatically if `tenants.auto_rotate_token_on_leak_enabled` is true (default: **enabled**). If it's disabled, reporting records the leak but does **not** rotate — you must call `rotate-token` explicitly afterward.
3. **Review recent decisions for this agent** to scope the blast radius before rotating (rotation doesn't retroactively undo anything the leaked token already did):
   ```bash
   curl -s -H "Authorization: Bearer $AGENT_TOKEN" \
     "http://127.0.0.1:8080/v1/decisions?agent_id=<agent_id>"
   ```

## Remediation

There are two entry points depending on whether you already know it's compromised or are reporting a signal:

- **You know the token leaked — rotate immediately** (always allowed, no leak-policy gating):
  ```bash
  curl -s -X POST -H "Authorization: Bearer $AGENT_TOKEN" \
    "http://127.0.0.1:8080/v1/agents/<agent_id>/rotate-token" \
    -d '{"reason": "token found in public commit abc123"}'
  ```
  The response includes the **new plaintext token exactly once** — capture it immediately and update the agent's deployed configuration. AegisAgent never re-displays it and never pushes it anywhere (not over a webhook, not in logs) — store it yourself right away or you'll need to rotate again to get a fresh one.

- **An automated signal detected a possible leak — report it** (lets the tenant's auto-rotate policy decide):
  ```bash
  curl -s -X POST -H "Authorization: Bearer $AGENT_TOKEN" \
    "http://127.0.0.1:8080/v1/agents/<agent_id>/report-leaked-token" \
    -d '{"reason": "gitleaks CI scan flagged a match"}'
  ```
  This always emits an `agent_token_leak_detected` SOC event (so it's visible to the SOC regardless of the rotation outcome), and rotates the token only if auto-rotate is enabled for the tenant.

The **old token is rejected immediately** on rotation — there is no grace period, so make sure you have the new token ready to deploy before (or immediately after) rotating to avoid an outage for the legitimate agent process.

## Verification

- The old token is rejected on the very next `/v1/authorize` call using it: `401`.
- `GET /v1/audit/events?agent_id=<agent_id>` shows an `agent_token_rotated` event with your `reason`.
- The legitimate agent process, reconfigured with the new token, successfully calls `/v1/authorize` again.
- If you used `report-leaked-token` and auto-rotate was disabled, confirm you followed up with an explicit `rotate-token` call — the leak report alone does not protect you.
