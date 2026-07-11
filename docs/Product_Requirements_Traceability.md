# Product Requirements Traceability

## Overview

This matrix connects every capability requirement in the [Product Requirements Document](AegisAgent_PRD.md) to its owning documentation, implementation evidence, tests, and current delivery state.

!!! warning "Status rule"
    The [Implementation Status](Implementation_Status.md) ledger is authoritative. This matrix explains traceability; it must not independently promote a capability to Implemented.

## Why This Exists

Requirements fail when they live only in prose. A feature may ship without operational documentation, a roadmap diagram may be mistaken for working enforcement, or an implementation may have no acceptance evidence. Traceability makes those gaps visible before release.

## Status Vocabulary

| Status | Meaning |
|---|---|
| Implemented | Source and tests exist; production readiness may still be beta |
| Partial | A meaningful path exists, but required force path, parity, packaging, or operations remain |
| Planned | Design exists; the required product behavior does not ship |
| Missing | Required behavior and an actionable implementation path are absent |

## Integrity and Provenance

| Requirement | Owning docs | Implementation evidence | Verification evidence | Status |
|---|---|---|---|---|
| INT-001 Canonical action | [Canonicalization ADR](adr/0003-aegis-jcs-1-canonicalization.md), [SDK](components/SDK.md) | `src/canon/`, SDK canonicalizers | `tests/canonical_action_vectors.json`, fuzz/SDK parity | Implemented |
| INT-002 Approval binding | [Approval Engine](components/Approval_Engine.md), [Approval Flow](flows/Approval_Flow.md) | `src/src/routes/approval.rs`, approval storage/migrations | integration tests, approve-then-swap demo | Implemented |
| INT-003 Atomic consume | [Approval Engine](components/Approval_Engine.md), [Fail-Closed Behavior](fail-closed-behavior.md) | approval consume route + storage transaction | integration and SDK tests | Implemented |
| INT-004 Fail-closed SDK | [SDK](components/SDK.md), [Known Agent Flow](flows/Known_Agent_Flow.md) | Python/TypeScript/Go protect/client implementations | SDK unit tests and demos | Implemented |
| PROV-001 Six trust levels | [Policy Engine](components/Policy_Engine.md), [Architecture Overview](Architecture_Overview.md) | `lib/policy/src/trust_chain.rs` | policy/trust unit tests | Implemented |
| PROV-002 Tighten only | [Threat Model](AegisAgent_Threat_Model.md), [Known Agent Flow](flows/Known_Agent_Flow.md) | trust-chain propagation and ingest labeling | multi-hop/trust unit tests | Implemented |

## Receipts and API

| Requirement | Owning docs | Implementation evidence | Verification evidence | Status |
|---|---|---|---|---|
| RCPT-001 Receipt chain | [Receipt Specification](action-receipt-spec.md), [Receipt Engine](components/Receipt_Engine.md) | authorize receipt path + storage append | property tests, concurrent append tests | Implemented |
| RCPT-002 Verification | [Receipt Flow](flows/Receipt_Flow.md), [Verification Runbook](runbooks/receipt-chain-verification.md) | receipt verify routes and SDK verifiers | `tests/receipt_chain_vectors.json` across four languages | Implemented |
| RCPT-003 Signing | [Receipt Engine](components/Receipt_Engine.md), [Signing ADR](adr/0004-ed25519-receipt-signing.md) | `src/src/sign.rs`, `kms_receipt_signer.rs` | signer unit tests | Implemented / beta |
| AUTH-001 Dual protocol | [Architecture Patterns](architecture.md), [API Reference](api-reference.md) | protobuf, REST routes, `src/src/grpc.rs` | route parity + tonic integration tests | Implemented; continuous obligation |
| AUTH-002 Tenant isolation | [Storage](components/Storage.md), [Security Model](security-model.md) | tenant-bound `StorageBackend` methods | isolation tests and security review | Implemented; continuous audit |

## SOC and Evidence

| Requirement | Owning docs | Implementation evidence | Verification evidence | Status |
|---|---|---|---|---|
| SOC-001 Async events | [SOC Engine](components/SOC_Engine.md), [SOC Incident Flow](flows/SOC_Incident_Flow.md) | `lib/soc/src/events.rs`, authorize event emission | unit/integration and drop-counter tests | Implemented |
| SOC-002 Deterministic detection | [Agent SOC Design](AegisAgent_Agent_SOC_Design.md), [Event Schema](event-schema.md) | `lib/soc/src/detect.rs` | rule unit tests | Implemented |
| SOC-003 Incidents | [SOC Engine](components/SOC_Engine.md), [SOC Incident Flow](flows/SOC_Incident_Flow.md) | correlation, narration, incident routes | correlation and route tests | Implemented |
| SOC-004 Evidence export | [Evidence Graph](evidence-graph.md), [Receipt Specification](action-receipt-spec.md) | evidence export route, checkpoints, UI integrity panel | unit + mocked UI tests | Implemented / beta |

## Runtime Control

| Requirement | Owning docs | Implementation evidence | Remaining acceptance evidence | Status |
|---|---|---|---|---|
| RSP-001 Agent control | [Control Command Protocol](AegisAgent_Control_Command_Protocol.md), [Control Flow](flows/Control_Command_Flow.md) | signed command store/routes, sensor receiver, process enforcer | collector-driven PID discovery, complete command semantics | Partial |
| RSP-002 Choke-point enforcement | [Ban and Quarantine Flow](flows/Ban_Quarantine_Flow.md) | ban/quarantine stores and selected status gates | prove propagation and denial at every supported choke point | Partial |
| RUN-001 Unknown-agent cage | [Agent Cage](components/Agent_Cage.md), [Unknown Agent Flow](flows/Unknown_Agent_Cage_Flow.md) | cage runner, Docker runtime, Helm/Compose | full untrusted-to-incident narrative E2E | Partial |
| RUN-002 Forced egress | [Egress Proxy](components/Egress_Proxy.md), [Egress Flow](flows/Egress_Block_Flow.md) | egress binary, check API, packaging | transparent cage network force path | Partial |
| RUN-003 Runtime telemetry | [Node Sensor](components/Node_Sensor.md), [Runtime Data Plane](AegisAgent_Runtime_Data_Plane.md) | sensor spool/shipper/receiver | real process/filesystem/network/secret collectors | Partial |
| BRK-001 Credential broker | [Tool Broker](components/Tool_Broker.md), [Broker Flow](flows/Tool_Broker_Flow.md) | broker core/connectors and route | standalone packaging and mandatory privileged path | Partial |

## Experience and Operations

| Requirement | Owning docs | Implementation evidence | Remaining acceptance evidence | Status |
|---|---|---|---|---|
| UX-001 SOC console | [Console UI](components/Console_UI.md), [Console Design](AegisAgent_SOC_UI_Design.md) | `ui-next` system boards/pages/panels | richer incident and prompt/model query experiences | Implemented / beta |
| OPS-001 Single-node production | [Deployment Guide](deployment-guide.md), [Production Hardening](production-hardening.md) | gateway image, Helm/Compose, probes, metrics, JWT/TLS | continuing release and restore exercises | Implemented / prod for known-agent path |
| OPS-002 Multi-replica HA | [Operational Design](AegisAgent_Operational_Design.md), [Storage](components/Storage.md) | PostgreSQL feature and migrations | GA operations path, load/failover/receipt validation | Partial |
| IAM-001 Human SSO | [Implementation Status](Implementation_Status.md), [Production Hardening](production-hardening.md) | JWT/admin controls | OIDC/SAML login and role mapping | Planned |

## Release Use

Before changing a status:

1. pass the PRD acceptance criterion for the requirement;
2. name current source files and tests in `Implementation_Status.md`;
3. update the owning guide, API reference, architecture map, and runbook;
4. verify REST/gRPC and SDK parity where applicable;
5. run `node scripts/validate-docs.mjs` and the relevant build/test suites.

## References

- [Product Requirements Document](AegisAgent_PRD.md)
- [Implementation Status](Implementation_Status.md)
- [Documentation Quality Report](Documentation_Quality_Report.md)
- [Repository Knowledge Map](Repo_Knowledge_Map.md)
- [Architecture Patterns](architecture.md)
