# Runbook: Data Exfiltration Pattern

**Incident kind:** `data_exfil_pattern` · **Severity:** `high` · **Detection rule:** `correlate::rule_data_exfil`

## Symptoms

- A SOC alert/incident with `kind: "data_exfil_pattern"` appears in `GET /v1/incidents`.
- The pattern: a **Source** action (`gateway/src/correlate.rs`'s `SOURCE_TOKENS` — names containing `read`/`get`/`fetch`/`list`/`download`/`query`/`select`/`export`/`dump`/`cat`) is followed within `EXFIL_WINDOW_SECS` (120s) by a **Sink** action for the *same agent* (`SINK_TOKENS` — names containing `send`/`post`/`upload`/`email`/`webhook`/`push`/`publish`/`write_external`/`share`/`transfer`, or any action literally named `exfil`). Matching is substring-based and case-insensitive on the action name only, so it's a heuristic, not a content-aware DLP scan.
- This is the canonical real-world pattern from the Invariant Labs GitHub-MCP disclosure (T-B2 in [`AegisAgent_Threat_Model.md`](../AegisAgent_Threat_Model.md)): a malicious issue tricks an agent into reading private data, then pushing it somewhere public/external.

## Before you start: check whether this already auto-resolved

`data_exfil_pattern` maps to **freeze the agent + a critical-severity notification** in the Response Engine (`gateway/src/respond.rs`), but only runs at SOC autonomy level `L3`/`L4` (default is `L1`, notify-only). Check the tenant's effective level the same way as in [`deny-storm.md`](deny-storm.md) before assuming containment already happened.

## Investigation

1. **Find the incident and its evidence graph** (same as the deny-storm runbook):
   ```bash
   curl -s -H "Authorization: Bearer $AGENT_TOKEN" \
     "http://127.0.0.1:8080/v1/incidents?severity=high&status=open" | jq '.[] | select(.kind=="data_exfil_pattern")'
   curl -s -H "Authorization: Bearer $AGENT_TOKEN" \
     "http://127.0.0.1:8080/v1/graph/incident/<incident_id>"
   ```
2. **Identify the Source and Sink decisions** specifically — the incident's `source_event_ids` link to exactly two decisions (the paired read and the paired write). Resolve each event to its decision via `GET /v1/decisions/:id` to see the actual `tool`/`action`/`resource` and `risk_score`.
3. **Check the triggering context's trust level.** Was the run triggered by `untrusted_external`/`semi_trusted_customer` content (e.g. a public issue, an email)? If so this strongly corroborates T-B1/T-B2 (confused-deputy via provenance) rather than a benign coincidence — cross-check `GET /v1/decisions/:id`'s recorded `trust_level`/`root_trust_level`.
4. **Check what was actually read and where it went.** The decision's `resource` field (e.g. a file path, a repo, a record id) tells you the blast radius — was it a single record or a bulk export? Where did the sink action send it (an external webhook URL, a public repo, an email address outside the org)?
5. **Generate an RCA narrative:**
   ```bash
   curl -s -H "Authorization: Bearer $AGENT_TOKEN" \
     "http://127.0.0.1:8080/v1/incidents/<incident_id>/narrate"
   ```

## Remediation

This pattern is higher-confidence-malicious than a deny storm — default to containment first, investigation second:

1. **Freeze (or revoke, if you're confident this is a real compromise) immediately:**
   ```bash
   curl -s -X POST -H "Authorization: Bearer $AGENT_TOKEN" \
     "http://127.0.0.1:8080/v1/agents/<agent_id>/freeze" -d '{"reason": "data_exfil_pattern — possible exfiltration"}'
   ```
2. **Rotate the agent's token** regardless of root cause — even a false positive doesn't hurt from rotating, and a true positive may mean the token is already compromised (see [`agent-token-rotation.md`](agent-token-rotation.md)):
   ```bash
   curl -s -X POST -H "Authorization: Bearer $AGENT_TOKEN" \
     "http://127.0.0.1:8080/v1/agents/<agent_id>/rotate-token" -d '{"reason": "data_exfil_pattern containment"}'
   ```
3. **If the sink was an external destination you control** (e.g. your own webhook endpoint, a repo), check whether the data actually arrived there and needs to be deleted/revoked at the destination — AegisAgent's containment stops the *agent*, not data already in flight or already delivered.
4. **If the source was triggered by untrusted content** (a malicious issue/email/ticket), consider whether the underlying confused-deputy gate needs tightening — e.g. an explicit `forbid` policy for this specific tool/action combination under untrusted provenance, beyond the default `mutates_state && untrusted_external` rule (a read-then-external-write chain may not always trip `mutates_state` on the read half).
5. Close the incident once handled:
   ```bash
   curl -s -X POST -H "Authorization: Bearer $AGENT_TOKEN" \
     "http://127.0.0.1:8080/v1/incidents/<incident_id>/close"
   ```

## Verification

- `GET /v1/agents/:id` shows `status: "revoked"` or `"active"` with a confirmed-rotated token.
- The old token is rejected on the next `/v1/authorize` call (`401`).
- `GET /v1/incidents/<incident_id>` shows `status: "closed"`.
- If a destination cleanup was needed, confirm directly against that external system (outside AegisAgent's scope) — note this in the incident close reason for the audit trail.
- No repeat `data_exfil_pattern` incident for the same agent in the following `EXFIL_WINDOW_SECS` (120s) window.
