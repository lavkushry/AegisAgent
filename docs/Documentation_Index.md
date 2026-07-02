# Documentation Index

The clean map of all AegisAgent documentation, organized by how deep you want to go. Start at [START_HERE.md](START_HERE.md) if you're new.

## Start here (Level 1 — anyone)

| Doc | What it gives you |
|---|---|
| [START_HERE.md](START_HERE.md) | The front door: three reading paths by role |
| [The_One_Minute_Tour.md](The_One_Minute_Tour.md) | The whole idea in 60 seconds |
| [What_Is_AegisAgent.md](What_Is_AegisAgent.md) | What it is (and is not) |
| [Why_AegisAgent.md](Why_AegisAgent.md) | The three problems it solves |
| [How_It_Works.md](How_It_Works.md) | The mechanism, step by step |
| [Product_Overview.md](Product_Overview.md) | The full product framing |
| [Glossary.md](Glossary.md) | Every term, simple + technical |
| [faq.md](faq.md) | 25 honest questions and answers |

## Product understanding

[Last_Mile_System_Walkthrough.md](Last_Mile_System_Walkthrough.md) (the whole system as one story) · [concepts.md](concepts.md) · [mission.md](mission.md) · [getting-started.md](getting-started.md) · [current-vs-roadmap.md](current-vs-roadmap.md)

## Flows (Level 2 — visual understanding)

| Flow | Status |
|---|---|
| [Known agent](flows/Known_Agent_Flow.md) | Implemented |
| [Approval](flows/Approval_Flow.md) | Implemented |
| [Receipt](flows/Receipt_Flow.md) | Implemented |
| [SOC incident](flows/SOC_Incident_Flow.md) | Implemented |
| [Ban & quarantine](flows/Ban_Quarantine_Flow.md) | Partial |
| [MCP gateway](flows/MCP_Gateway_Flow.md) | Implemented |
| [Prompt-to-action lineage](flows/Prompt_To_Action_Lineage.md) | Partial |
| [Unknown agent (cage)](flows/Unknown_Agent_Cage_Flow.md) | Partial/Planned |
| [Control command](flows/Control_Command_Flow.md) | Partial/Planned |
| [Tool broker](flows/Tool_Broker_Flow.md) | Planned |
| [Egress block](flows/Egress_Block_Flow.md) | Planned |

## Architecture (Level 3 — engineers & architects)

[Architecture_Overview.md](Architecture_Overview.md) (HLD of the current system) · [AegisAgent_Technical_Design.md](AegisAgent_Technical_Design.md) · [security-model.md](security-model.md) · [AegisAgent_Threat_Model.md](AegisAgent_Threat_Model.md) · [fail-closed-behavior.md](fail-closed-behavior.md) (failure model) · [database-schema.md](database-schema.md) (data model) · [runtime-authorization-api.md](runtime-authorization-api.md) + [api-reference.md](api-reference.md) (API model) · [event-schema.md](event-schema.md) (event model) · [action-receipt-spec.md](action-receipt-spec.md) (receipt model) · [evidence-graph.md](evidence-graph.md) · [AegisAgent_Runtime_Data_Plane.md](AegisAgent_Runtime_Data_Plane.md) · target designs: [AegisAgent_World_Class_HLD.md](AegisAgent_World_Class_HLD.md), [AegisAgent_World_Class_LLD.md](AegisAgent_World_Class_LLD.md), [AegisAgent_Agent_Cage.md](AegisAgent_Agent_Cage.md), [AegisAgent_Control_Command_Protocol.md](AegisAgent_Control_Command_Protocol.md) · decisions: [adr/index.md](adr/index.md)

## Components (Level 4 — maintainers)

[Gateway](components/Gateway.md) · [SDK](components/SDK.md) · [Policy engine](components/Policy_Engine.md) · [Approval engine](components/Approval_Engine.md) · [Receipt engine](components/Receipt_Engine.md) · [SOC engine](components/SOC_Engine.md) · [MCP gateway](components/MCP_Gateway.md) · [Storage](components/Storage.md) · [Console UI](components/Console_UI.md) · [Prompt & model capture](components/Prompt_Model_Capture.md) · planned: [Agent cage](components/Agent_Cage.md) · [Node sensor](components/Node_Sensor.md) · [Egress proxy](components/Egress_Proxy.md) · [Tool broker](components/Tool_Broker.md)

## Developer docs (Level 5)

[Local_Development.md](Local_Development.md) · [quickstart.md](quickstart.md) · [installation.md](installation.md) · [onboarding/For_SDK_Developer.md](onboarding/For_SDK_Developer.md) (SDK integration) · [sdk-parity-status.md](sdk-parity-status.md) · [api-versioning.md](api-versioning.md) · demos: [approve-then-swap-demo.md](approve-then-swap-demo.md), [demo-github-attack.md](demo-github-attack.md)

## Operator docs (Level 5)

[deployment-guide.md](deployment-guide.md) · [production-hardening.md](production-hardening.md) (production checklist) · [AegisAgent_Operational_Design.md](AegisAgent_Operational_Design.md) · [runbooks/index.md](runbooks/index.md) · [AegisAgent_Debugging_Guide.md](AegisAgent_Debugging_Guide.md) · [performance-baseline.md](performance-baseline.md) · [performance-tuning-guide.md](performance-tuning-guide.md) · integrations: [github-integration.md](github-integration.md), [slack-integration.md](slack-integration.md), [qdrant-integration.md](qdrant-integration.md)

## Onboarding (per role)

[New engineer](onboarding/For_New_Engineer.md) · [Security architect](onboarding/For_Security_Architect.md) · [SOC analyst](onboarding/For_SOC_Analyst.md) · [SDK developer](onboarding/For_SDK_Developer.md) · [Frontend engineer](onboarding/For_Frontend_Engineer.md) · [DevOps engineer](onboarding/For_DevOps_Engineer.md)

## Maintainer docs (Level 6)

[Repo_Knowledge_Map.md](Repo_Knowledge_Map.md) (repo map + code flow) · [Implementation_Status.md](Implementation_Status.md) (the honest ledger) · [AegisAgent_Diagram_Index.md](AegisAgent_Diagram_Index.md) + [diagrams/](https://github.com/lavkushry/AegisAgent/tree/main/docs/diagrams) · [architecture-map.json](architecture-map.json) (machine-readable system map) · [explorer/index.html](explorer/index.html) (optional interactive map) · [Documentation_Audit.md](Documentation_Audit.md) · [Documentation_Redesign_Plan.md](Documentation_Redesign_Plan.md) · [feature_history.md](feature_history.md) · [architecture.md](architecture.md) (mandatory code patterns) · PR workflow: [CONTRIBUTING.md](https://github.com/lavkushry/AegisAgent/blob/main/CONTRIBUTING.md) · backlog process: [Issue_Backlog_Execution_Plan.md](Issue_Backlog_Execution_Plan.md)

## Internal strategy (not published to the docs site)

[AegisAgent_Gap_Reassessment_2026-06.md](AegisAgent_Gap_Reassessment_2026-06.md) (source of truth) · AegisAgent_Vision / PRD / Problem_Definition / Market_Gap_Analysis / Product_Research / GTM — see [docs/README.md](https://github.com/lavkushry/AegisAgent/blob/main/docs/README.md) for the full internal list.

## Archive

Superseded documents live in [archive/](archive/README.md) with a note explaining what replaced them.
