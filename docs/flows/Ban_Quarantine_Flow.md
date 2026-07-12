# Ban & Quarantine Model

**Status: ✅ Implemented (beta)** — agent-level containment (freeze/quarantine/revoke) ✅; first-class ban/quarantine stores ✅; choke-point enforcement (authorize, broker execute, cage create/claim, egress) ✅; agent bans propagate to live runs as signed `kill_run` commands ✅. Remaining: `fingerprint`/`image_digest`/`prompt_hash` target types are stored but not yet consulted; sensor-local ban cache (bans holding while the gateway is unreachable) 📐.

## 1. One-sentence summary

Containment in AegisAgent is a ladder — freeze → quarantine → revoke → ban — where every rung makes the agent's authentication or execution fail closed, and every rung leaves evidence.

## 2. Why it exists

Detection without containment is a dashboard, not a control. When an agent misbehaves (or its credentials leak), someone — human or playbook — must be able to stop it *now*, in a way the agent can't talk its way out of.

## 3. Mental model

Security badges in a building: freeze = badge temporarily disabled; quarantine = escorted to a holding room (still observable); revoke = badge shredded; ban = name on the no-entry list at every door, including doors that haven't been built yet (future runs).

## 4. The containment ladder

| Rung | Effect | How | Status |
|---|---|---|---|
| **Freeze** | agent's authorize calls are denied; reversible | `POST /v1/agents/:id/freeze` / `unfreeze` (also CLI `aegis freeze-agent`) | ✅ |
| **Quarantine** | agent marked quarantined; `get_agent_by_token` refuses it (401); reversible via restore | SOC respond playbooks (`lib/soc/src/respond.rs`) or agent routes; `quarantine_records` store (migration 0030, #1679) adds first-class records with reason/scope | ✅ status-level / 🟡 records wired |
| **Revoke** | token invalidated; agent must be re-credentialed (`rotate-token` for benign rotation) | `POST /v1/agents/:id/revoke` / `restore` | ✅ |
| **Ban** | durable, listable ban independent of agent row state; gates future *and* running work | `agent_bans` store (migration 0029, #1678); enforced at `POST /v1/authorize` (agent + tool → durable deny), `POST /v1/broker/execute` (tool → 403 before approval consumption), `POST /v1/agent-cage/runs` create + claim (agent → 403; claim re-checks late bans), `POST /v1/egress/check` (destination); `POST /v1/bans` for an agent also issues signed `kill_run` commands for its active runs | ✅ choke points + live-run propagation; `fingerprint`/`image_digest`/`prompt_hash` types 📐 |
| **Kill / workspace quarantine** (unknown agents) | terminate sandbox, preserve workspace as evidence | signed control commands to node sensor / cage runner (`ProcessEnforcer` host kill proven on a real Linux host) | ✅ kill (beta); workspace evidence-freeze 📐 ([AegisAgent_Control_Command_Protocol.md](../AegisAgent_Control_Command_Protocol.md), [AegisAgent_Agent_Cage.md](../AegisAgent_Agent_Cage.md)) |

## 5. Who pulls the trigger

```mermaid
flowchart LR
    DET[Detection: deny-storm,<br/>exfil pattern, drift] --> RESP[respond.rs playbooks]
    ANA[SOC analyst<br/>console or CLI] --> API[agent containment routes]
    RESP --> API
    API --> ST[(agent status + ban/quarantine records)]
    ST --> AUTH[get_agent_by_token excludes<br/>quarantined & deleted → 401]
    ST --> CMD[signed control command] --> SENSOR[node sensor kills/aborts run]
    API --> EV[audit event + SOC event + receipt trail]
```

Fail-closed detail worth knowing: `get_agent_by_token` / `get_agent_by_mtls_cn` exclude `status='quarantined'` **and** `status='deleted'` (a gap where deleted agents could still authenticate was closed in the #1193 work).

## 6. APIs

`POST /v1/agents/:id/{freeze,unfreeze,revoke,restore,rotate-token}` · quarantine via respond playbooks and agent routes · `GET /v1/agents` shows status · CLI: `aegis freeze-agent`, `aegis unfreeze-agent`, `aegis status`. Ban/quarantine record APIs ride the runtime data-plane route work (see [Implementation_Status.md](../Implementation_Status.md)).

## 7. Storage

`agents.status` (active/frozen/quarantined/revoked/deleted) · `agent_bans` (0029) · `quarantine_records` (0030) · every transition writes an audit event. Tenant-scoped, parameterized.

## 8. Security guarantees & failure behavior

- Containment is enforced at **authentication and authorization**, not by asking the agent nicely — a contained agent's requests fail closed with 401/deny.
- Transitions are audited and SOC-visible; un-quarantining is an explicit, logged action.
- Bans gate `POST /v1/agent-cage/runs` registration **and** claim (a ban created after registration still blocks the moment execution would start), `POST /v1/authorize`, `POST /v1/broker/execute` (before approval consumption, so a denial never burns a valid approval) and egress; a storage error at any choke point blocks (fail-closed), never allows.
- Planned: sensor-local ban cache so bans hold even if the gateway is briefly unreachable (📐 design).

## 9. Example

```bash
aegis freeze-agent --agent-id $ID --format json
curl -s -X POST $AEGIS/v1/agents/$ID/revoke -H "Authorization: Bearer $TOKEN"
# the agent's next authorize:
# → 401 Unauthorized (fail closed), SOC event recorded
```

## 10. Common mistakes

- Using revoke when you meant freeze (revoke forces re-credentialing).
- Forgetting quarantine is reversible state, not deletion — GDPR deletion is `DELETE /v1/tenants/:id` scope.
- Assuming a ban only affects *future* work — banning an agent also issues signed `kill_run` commands for its live runs (requires `AEGIS_COMMAND_SIGNING_KEY`; without it the ban still blocks at every choke point but live runs only die on their next gateway interaction).

## 11. Debugging

Agent unexpectedly 401? Check `GET /v1/agents/:id` status first — you may be contained, not broken. Token rotated? See [runbooks/agent-token-rotation.md](../runbooks/agent-token-rotation.md).

## 12. Related code

`src/src/routes/agents.rs` · `lib/soc/src/respond.rs` · `lib/storage/src/db/{agents,agent_bans,quarantine}.rs` · migrations `0029`, `0030` · `sdk-python/aegisagent/cli.py`.

## 13. Related docs

[components/SOC_Engine.md](../components/SOC_Engine.md) · [AegisAgent_Control_Command_Protocol.md](../AegisAgent_Control_Command_Protocol.md) · [flows/Control_Command_Flow.md](Control_Command_Flow.md) · [runbooks/deny-storm.md](../runbooks/deny-storm.md) · [Implementation_Status.md](../Implementation_Status.md)
