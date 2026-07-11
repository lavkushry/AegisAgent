# Flow: Egress Block

> **Status: Partial.** The egress binary, decision route, tests, and packaging exist; forced transparent cage networking remains incomplete. Normative component guide: [Egress Proxy](../components/Egress_Proxy.md).

## Overview

A caged agent has exactly one road to the internet: the egress proxy. Allowed destinations pass. Everything else is blocked — and every block becomes evidence.

## Visual

```mermaid
flowchart LR
    SB[caged agent] -->|target forced route 🟡| EP[egress proxy]
    EP --> MODE{mode}
    MODE -->|observe| LOG[log + forward]
    MODE -->|enforce| CHK{allowlisted?}
    MODE -->|lockdown| ALL[deny all but control plane]
    CHK -->|yes| NET[destination]
    CHK -->|no| BLK[block]
    BLK & LOG & ALL --> EVT[runtime event → SOC]
```

## Step by step

1. The cage runner wires sandbox networking so the proxy is the only route (DNS included, to stop tunneling).
2. Tenant egress policy (domains/CIDRs/ports per run or agent) comes from the gateway.
3. Three modes: **observe** (log everything), **enforce** (allowlist), **lockdown** (deny all except Aegis control endpoints).
4. Every allow/deny emits a `network_egress` runtime event → `POST /v1/ingest/runtime-events` (this ingest path exists today).
5. Repeated blocked egress = exfiltration-attempt detection in the SOC.
6. If the proxy can't reach the gateway for policy, enforce/lockdown deny by default (fail closed).

## Why this matters

Exfiltration is the endgame of most agent attacks. You can't reliably filter *content*; you can remove the *path*.

## Honest scope

The proxy controls traffic forced through it. A workload outside the cage with its own network path is out of scope — which is why unknown agents only run caged, and why non-proxy traffic seen by the sensor is itself a detection signal.

## Example

```bash
cargo test -p aegis-egress
cargo test -p aegis-egress-proxy
```

These tests prove policy/proxy behavior, not transparent network force. The full acceptance test must demonstrate that a caged workload cannot reach a destination around the proxy.

## Security

Enforce/lockdown deny when policy is unavailable, normalize and validate destinations, control DNS, block metadata/loopback bypasses as policy requires, redact credentials/bodies, and alert on any direct-network observation.

## Related docs

[../components/Egress_Proxy.md](../components/Egress_Proxy.md) · [Unknown_Agent_Cage_Flow.md](Unknown_Agent_Cage_Flow.md) · [../runbooks/data-exfiltration.md](../runbooks/data-exfiltration.md) · [../Implementation_Status.md](../Implementation_Status.md)
