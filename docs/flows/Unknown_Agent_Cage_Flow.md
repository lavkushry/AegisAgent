# Flow: Anonymous Agent in the Cage

**Status: 🟡 Partial.** Control-plane APIs/storage, sensor and cage binaries, process enforcement, minimal collectors, egress/broker components, packaging, and selected Docker E2E exist. Forced egress, mandatory broker, complete sensor/runner integration, and the full untrusted-to-incident narrative remain unfinished.

```mermaid
sequenceDiagram
    autonumber
    participant U as Submitter
    participant GW as Gateway
    participant NS as Node sensor 🟡
    participant CR as Cage runner 🟡
    participant SB as Sandboxed agent 🟡
    participant SOC
    U->>GW: POST /v1/agent-cage/runs ✅
    GW->>GW: preflight: policy, ban check, quota, sandbox spec
    GW->>NS: signed start_run command 📐 (store ✅)
    NS->>NS: verify sig, tenant, target, expiry, nonce
    NS->>CR: launch disposable sandbox
    CR->>SB: isolated workspace, no host FS,<br/>no raw creds, no direct internet
    SB->>SB: network → egress proxy 📐<br/>tools → tool broker 📐<br/>MCP → MCP gateway ✅
    SB-->>NS: runtime telemetry
    NS->>GW: POST /v1/ingest/runtime-events ✅ (idempotent)
    GW->>SOC: detect dangerous behavior ✅
    SOC->>GW: respond: kill / quarantine / ban
    GW->>NS: signed kill/quarantine command 📐
    NS-->>GW: ACK → receipt + timeline ✅ storage
```

## What works today

| Step | API / code |
|---|---|
| Register a controlled run | `POST /v1/agent-cage/runs`, `GET /v1/agent-cage/runs[/:id]` — `src/src/routes/runtime.rs` (#1681), store `lib/storage/src/db/agent_runs.rs` (migration 0026). *Route file under reorganization on an active branch — verify before deep-linking.* |
| Ingest runtime events (idempotent) | `POST /v1/ingest/runtime-events` — store `db/runtime_events.rs` (0027) |
| Read a run's runtime timeline | `GET /v1/runtime/runs/:id/events` |
| Signed control path | command store/routes, sensor verification, ACK, and host process enforcement; full semantics/integration remain |
| Cage execution | `bins/aegis-cage-runner`, Docker runtime, packaging, claim lifecycle and selected Docker E2E |
| Runtime collection | sensor spool/shipper plus minimal process/filesystem/network/secret collectors |
| Bans / quarantine records | `db/agent_bans.rs` (0029, #1678), `db/quarantine.rs` (0030, #1679) |
| SOC detection over ingested events | `lib/soc/src/*` |

## Remaining force-path work

1. Force every cage network path through the egress proxy, including controlled DNS.
2. Force privileged provider calls through the broker without placing raw credentials in the workload.
3. Complete runner/sensor IPC, identity rotation, collector coverage, and command semantics.
4. Enforce bans/quarantine consistently at every supported choke point.
5. Pass the untrusted workload → denied egress → incident → signed containment → verified evidence E2E.

## The security argument

The cage doesn't try to out-argue a hostile agent — it removes the ambient environment. Filesystem, network, secrets, tools, and MCP all *only* work through Aegis choke points, so "bypassing Aegis" means "having nothing to act with." Dangerous behavior that is attempted anyway becomes runtime events → detections → kill/quarantine/ban, each step receipted.

That argument is the target guarantee. Until the remaining force paths pass, deployments must state which paths are enforced and which are only observed.

## Example

```bash
docker compose --profile cage up --build -d
bash scripts/cage-docker-e2e.sh
```

The current E2E proves selected claim/finish and signed-kill behavior. It does not yet prove transparent forced egress or broker-only credentials.

## Security

Run untrusted workloads only on approved cage hosts, harden Docker/runner privileges, keep secrets out of the sandbox, reject invalid controls, preserve workspaces/evidence, and stop scheduling when sensor/runner/egress enforcement is unavailable. Sandbox escape and Docker socket compromise remain critical residual risks.

## Related docs

[../AegisAgent_Agent_Cage.md](../AegisAgent_Agent_Cage.md) · [../AegisAgent_Runtime_Data_Plane.md](../AegisAgent_Runtime_Data_Plane.md) · [../flows/Ban_Quarantine_Flow.md](../flows/Ban_Quarantine_Flow.md) · [../Implementation_Status.md](../Implementation_Status.md) · roadmap [../AegisAgent_Phased_PR_Plan.md](../AegisAgent_Phased_PR_Plan.md)
