# Node Sensor (`aegis-node-sensor`)

**Status: 📐 Planned (Phase 3)** — the gateway-side APIs and storage it will talk to exist (🟡); the sensor binary does not exist in this repository yet. Nothing on this page describes shipped runtime behavior unless marked ✅.

## 1. One-sentence summary

The node sensor is the planned host-local agent of the control plane: it watches runtime activity (process, filesystem, network intents), ships runtime events to the gateway, and enforces signed control commands (pause/kill/quarantine) near the workload.

## 2. Why it exists

SDK controls only work for cooperative agents. An unknown or hostile agent needs an enforcement point it cannot opt out of, running *outside* the agent's own process — on the host, as a Kubernetes DaemonSet, or as a CI sidecar.

## 3. Mental model

A trusted site guard with a radio: it observes everything at its site, reports upstream over a durable channel, and only obeys orders that are signed, addressed to its site, fresh, and never-seen-before.

## 4. Responsibilities (target design)

- Register with the gateway per tenant/host; maintain identity keys.
- Observe: process exec, workspace file activity, network intents from caged workloads.
- Ship runtime events durably: local queue → `POST /v1/ingest/runtime-events` ✅ *(this ingest endpoint and the `runtime_events` store exist at HEAD — migration 0027, PR #1681)*.
- Poll/receive control commands; verify signature, tenant binding, target binding, expiry, nonce (protocol: [AegisAgent_Control_Command_Protocol.md](../AegisAgent_Control_Command_Protocol.md), storage 0028 ✅).
- Execute typed handlers only (start/pause/resume/kill/snapshot/quarantine/ban/config) — never arbitrary shell from a payload.
- ACK/NACK results (optionally signed) → receipts + timeline.
- Launch sandboxes via `aegis-cage-runner` ([AegisAgent_Agent_Cage.md](../AegisAgent_Agent_Cage.md), Phase 4).

## 5. What exists today vs. missing

| Piece | Status |
|---|---|
| `runtime_events` table + ingest route + run timeline API | ✅ (0027, #1681; route layer under revision) |
| `agent_runs` registry (`POST /v1/agent-cage/runs`) | ✅ (0026, #1681) |
| `control_commands` store | ✅ (0028) |
| Command signing (`aegis-command-jcs-1`), dispatch/poll API, ACK path | 📐 |
| The sensor binary (observation, queue, enforcement) | 📐 |
| Sensor identity/registration, key pinning & rotation | 📐 |

## 6. Security posture (design goals)

Fail closed on any invalid/unsigned/expired/replayed command; tenant- and target-bound commands; least-privilege typed handlers; every accepted command becomes evidence (runtime event + receipt). Bypass reality: a workload that avoids the sensor's host is out of scope for the sensor — that's why caged execution forces workloads onto sensor-monitored hosts.

## 7. Related code & docs

Code (gateway side): `lib/storage/src/db/{runtime_events,agent_runs,control_commands}.rs` · `src/src/routes/runtime.rs` (at HEAD) · migrations 0026–0028.
Design: [AegisAgent_Runtime_Data_Plane.md](../AegisAgent_Runtime_Data_Plane.md) · [AegisAgent_Agent_Cage.md](../AegisAgent_Agent_Cage.md) · [AegisAgent_Control_Command_Protocol.md](../AegisAgent_Control_Command_Protocol.md) · roadmap: [AegisAgent_Phased_PR_Plan.md](../AegisAgent_Phased_PR_Plan.md) §Phase 3 · status: [Implementation_Status.md](../Implementation_Status.md) · flows: [flows/Unknown_Agent_Cage_Flow.md](../flows/Unknown_Agent_Cage_Flow.md), [flows/Control_Command_Flow.md](../flows/Control_Command_Flow.md)
