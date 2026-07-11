# Flow: Control Command (Kill / Pause / Quarantine)

**Status: 🟡 Partial.** Storage, canonical signing, gateway issue/poll/ACK routes, sensor verification, and host process enforcement exist. Complete collector-driven registration, command semantics, and force-path operations remain unfinished. Gateway-status containment is in [Ban/Quarantine Flow](Ban_Quarantine_Flow.md).

```mermaid
sequenceDiagram
    autonumber
    participant A as SOC analyst / respond playbook
    participant GW as Gateway
    participant ST as control_commands store ✅
    participant NS as Node sensor 🟡
    participant SB as Sandbox 🟡
    A->>GW: click "kill run" (console) / playbook fires
    GW->>GW: build command {id, tenant, target run/agent,<br/>type=kill, nonce, issued_at, expires_at}
    GW->>GW: canonicalize (aegis-command-jcs-1) → sign 🟡
    GW->>ST: persist command (idempotency anchor) ✅
    NS->>GW: poll commands 🟡
    GW-->>NS: signed command
    NS->>NS: verify: signature (pinned key), tenant binding,<br/>target binding, expiry, unseen nonce
    alt any check fails
        NS-->>GW: NACK (fail closed - nothing executes)
    else verified
        NS->>SB: typed handler: kill sandbox
        NS-->>GW: signed ACK {result, evidence}
        GW->>GW: runtime event + receipt + timeline update ✅ storage
    end
```

## Why every field exists

| Field / check | Attack it stops |
|---|---|
| Ed25519 signature over canonical bytes | forged commands from anyone but the gateway |
| Tenant binding | cross-tenant control (tenant A killing tenant B's run) |
| Target binding (run/agent/sandbox id) | retargeting a legitimate command |
| `expires_at` | stale command replayed later |
| Nonce + command id | replay; re-delivery resolves idempotently (same id → same ACK) |
| Typed handlers only | payload smuggling arbitrary shell to the sensor |
| ACK/NACK + receipts | silent failure; disputes about what was enforced |

Key management (rotation, `kid`, grace windows, emergency re-registration) is specified in [../AegisAgent_Control_Command_Protocol.md](../AegisAgent_Control_Command_Protocol.md) §3.

## Command types

`start_run` · `pause` · `resume` · `kill` · `snapshot` · `quarantine_workspace` · `ban_agent` · `update_sensor_config`. Each execution emits runtime events and rides the receipt chain, so *the act of containment is itself evidence*.

## Remaining work

1. Complete collector-driven run/PID discovery and runner/sensor integration.
2. Apply payload `grace_period` and finish every typed command semantic.
3. Exercise replay, expiry, wrong-tenant, sensor loss, and kill/quarantine end to end.

## Example

```bash
cargo test -p aegis-node-sensor process_enforcer
```

The focused tests exercise typed host process controls. Use cage Docker E2E for a broader signed-kill path; neither proves complete fleet enforcement.

## Security

Invalid, unsigned, expired, replayed, wrong-tenant, or wrong-target commands execute nothing. Sensors accept typed operations only, keep the gateway verification key pinned/rotatable, and produce ACK/NACK evidence. If the sensor is silent, the orchestrator must isolate the workload rather than assume containment succeeded.

## Related docs

[../AegisAgent_Control_Command_Protocol.md](../AegisAgent_Control_Command_Protocol.md) (normative design) · [../components/Node_Sensor.md](../components/Node_Sensor.md) · [Unknown_Agent_Cage_Flow.md](Unknown_Agent_Cage_Flow.md) · [../Implementation_Status.md](../Implementation_Status.md) · [../AegisAgent_Phased_PR_Plan.md](../AegisAgent_Phased_PR_Plan.md)
