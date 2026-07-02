# Onboarding: SOC Analyst

**Goal:** investigate an agent incident end-to-end in ~10 minutes.

## 1. Your surfaces

- **Console:** `http(s)://<gateway>/dashboard` — overview, fleet, integrity, approvals dashboards; live event stream.
- **CLI:** `pip install aegisagent` → `aegis status`, `aegis soc-summary`, `aegis freeze-agent`, `aegis verify-receipts`, `aegis export-audit` (all support `--format json`).
- **API:** everything the console shows is `GET/POST /v1/...` — see [../api-reference.md](../api-reference.md).

## 2. Mental model

Every agent action produced a **decision** (allow/deny/approval). Decisions stream into detections; detections correlate into **incidents**; every incident links to hash-chained **receipts** — your evidence is cryptographic, not screenshots. Containment is a ladder: **freeze → quarantine → revoke** (reversible → reversible → re-credential).

## 3. The 10-minute investigation loop

```text
1. Triage      GET /v1/soc/summary            what's hot?
2. Scope       GET /v1/incidents/:id          which agent, which window?
3. Narrative   GET /v1/incidents/:id/narrate  the story, generated from evidence
4. Timeline    GET /v1/runs/:id/timeline      prompt → decision → approval → receipt
5. Pivot       POST /v1/soc/query             {"decision":"deny","last":"1h","group_by":"agent_id"}
6. Prove       GET /v1/receipts/:id/verify    (or verify-range around the window)
7. Contain     POST /v1/agents/:id/freeze     (or quarantine / revoke)
8. Close       POST /v1/incidents/:id/close   with disposition
```

Evidence graph pivot: `GET /v1/graph/agent/:agent_id` shows everything connected to one agent.

## 4. Patterns you'll see (and their runbooks)

| Signal | Meaning | Runbook |
|---|---|---|
| Deny-storm | repeated denials — injection attempts or a broken/hijacked agent | [../runbooks/deny-storm.md](../runbooks/deny-storm.md) |
| `approval_hash_mismatch_total` rising | approve-then-swap being attempted | check `/metrics`; treat as active attack |
| Exfiltration pattern | reads followed by external sends | [../runbooks/data-exfiltration.md](../runbooks/data-exfiltration.md) |
| `mcp_manifest_drift` (high = tool added/removed) | MCP supply-chain change | [../components/MCP_Gateway.md](../components/MCP_Gateway.md) |
| Token concerns | rotate without downtime | [../runbooks/agent-token-rotation.md](../runbooks/agent-token-rotation.md) |

## 5. Containment cheat sheet

```bash
aegis freeze-agent --agent-id $ID          # reversible, instant fail-closed
curl -X POST $AEGIS/v1/agents/$ID/revoke   # kill the token
# playbooks can do this automatically — POST /v1/playbooks/:id/test to dry-run
```

Frozen/quarantined/revoked agents cannot authenticate — containment is enforced at auth, not by asking the agent.

## 6. Proving it afterwards

`GET /v1/compliance/evidence-pack` for the export; `aegis verify-receipts export.json` for third-party-verifiable integrity. How the proof works: [../flows/Receipt_Flow.md](../flows/Receipt_Flow.md).

## 7. Read next

[../components/SOC_Engine.md](../components/SOC_Engine.md) · [../AegisAgent_Agent_SOC_Design.md](../AegisAgent_Agent_SOC_Design.md) · [../flows/Ban_Quarantine_Flow.md](../flows/Ban_Quarantine_Flow.md) · [../runbooks/index.md](../runbooks/index.md)
