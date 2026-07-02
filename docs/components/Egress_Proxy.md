# Egress Proxy (`aegis-egress-proxy`)

**Status: 📐 Planned (Phase 5)** — no proxy code exists in this repository yet. This page records the target design so the choke point has a stable home in the docs; implementation tracking: [Implementation_Status.md](../Implementation_Status.md).

## 1. One-sentence summary

The egress proxy is the planned network choke point for caged workloads: sandboxed agents get **no direct internet** — every outbound connection must traverse the proxy, where tenant policy allows, blocks, and evidences it.

## 2. Why it exists

Data exfiltration is the endgame of most agent attacks (secrets to attacker domains, prompt-injected "post this to pastebin"). Filtering text is evadable; removing the network path is not. The proxy makes egress *observable and deniable by policy*.

## 3. Mental model

A shipping dock with a customs desk: the warehouse (sandbox) has no other doors. Every parcel is logged, checked against the manifest (allowlist), and refused if the destination isn't approved — and refused parcels are themselves evidence.

## 4. Target design

- Deployment shapes: host proxy, sidecar, DaemonSet, or service-mesh egress hop ([AegisAgent_Runtime_Data_Plane.md](../AegisAgent_Runtime_Data_Plane.md) §2).
- Enforcement modes: **observe** (log all), **enforce** (allowlist), **lockdown** (deny all except Aegis control endpoints).
- Policy source: tenant egress rules from the gateway (domains/CIDRs/ports per run or agent).
- Every allow/deny emits a runtime event (`network_egress` type) → `POST /v1/ingest/runtime-events` ✅ (ingest path exists) → SOC detections (e.g. repeated blocked egress = exfil attempt alert).
- Cage integration: `aegis-cage-runner` wires sandbox networking so the proxy is the only route ([AegisAgent_Agent_Cage.md](../AegisAgent_Agent_Cage.md)); DNS is resolved/controlled at the proxy to stop DNS tunneling of destinations.
- Fail closed: if the proxy can't reach the gateway for policy, enforce/lockdown modes deny-by-default.

## 5. Honest scope

The proxy only controls traffic **forced through it**. A workload outside the cage with its own network path is not controlled by this component — that is exactly why anonymous agents are only ever run caged, and why sensor telemetry watching for non-proxy traffic is a detection signal.

## 6. Related docs

[AegisAgent_Agent_Cage.md](../AegisAgent_Agent_Cage.md) · [AegisAgent_Runtime_Data_Plane.md](../AegisAgent_Runtime_Data_Plane.md) · [components/Node_Sensor.md](Node_Sensor.md) · [flows/Unknown_Agent_Cage_Flow.md](../flows/Unknown_Agent_Cage_Flow.md) · roadmap: [AegisAgent_Phased_PR_Plan.md](../AegisAgent_Phased_PR_Plan.md) §Phase 5 · threat context: [AegisAgent_Threat_Model.md](../AegisAgent_Threat_Model.md), [runbooks/data-exfiltration.md](../runbooks/data-exfiltration.md)
