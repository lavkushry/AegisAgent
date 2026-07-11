# Documentation Quality Report

> **Generated:** `node scripts/audit-doc-quality.mjs --write`  
> **Scope:** active Markdown under `docs/`; `docs/archive/` excluded  
> **Meaning:** structural teaching coverage, not factual correctness or implementation status

This inventory makes the all-documentation improvement program measurable. Each page is scored against its own profile: a runbook is not penalized for lacking a class diagram, and a generated reference is not treated like a tutorial.

## Summary

| Profile | Pages | Average | Below 75 |
|---|---:|---:|---:|
| authoring | 2 | 90% | 0 |
| component | 15 | 96% | 0 |
| decision | 7 | 64% | 6 |
| flow | 11 | 95% | 0 |
| guide | 52 | 62% | 42 |
| landing | 10 | 93% | 0 |
| onboarding | 6 | 100% | 0 |
| product | 1 | 100% | 0 |
| reference | 11 | 69% | 5 |
| runbook | 7 | 100% | 0 |

**Total:** 122 active Markdown pages · **Migration backlog:** 53 pages below 75%.

## Scoring signals

The audit looks for: title, contextual overview, why/problem framing, implementation status or scope, relevant diagrams, runnable examples, security/failure treatment, operations/recovery treatment, and references. Required signals vary by profile.

A = 90–100 · B = 75–89 · C = 60–74 · D = below 60.

## Priority migration backlog

Pages are sorted by structural coverage, then path. Improve factual accuracy and current-vs-roadmap honesty before adding visual polish.

| Page | Profile | Score | Missing signals |
|---|---|---:|---|
| [AegisAgent_SOC_Console_Design_System.md](AegisAgent_SOC_Console_Design_System.md) | guide | D · 33% | Why/reason, Diagram, Runnable/example, Security/failure, Operations, References/links |
| [api-versioning.md](api-versioning.md) | guide | D · 33% | Why/reason, Status/scope, Diagram, Security/failure, Operations, References/links |
| [database-schema.md](database-schema.md) | reference | D · 40% | Status/scope, Runnable/example, References/links |
| [sdk-parity-status.md](sdk-parity-status.md) | reference | D · 40% | Status/scope, Runnable/example, References/links |
| [AegisAgent_Integration_Connectivity.md](AegisAgent_Integration_Connectivity.md) | guide | D · 44% | Why/reason, Status/scope, Diagram, Security/failure, Operations |
| [AegisAgent_Market_Gap_Analysis.md](AegisAgent_Market_Gap_Analysis.md) | guide | D · 44% | Why/reason, Status/scope, Diagram, Operations, References/links |
| [AegisAgent_Phased_PR_Plan.md](AegisAgent_Phased_PR_Plan.md) | guide | D · 44% | Why/reason, Diagram, Security/failure, Operations, References/links |
| [AegisAgent_Product_Research.md](AegisAgent_Product_Research.md) | guide | D · 44% | Why/reason, Status/scope, Diagram, Security/failure, Operations |
| [approve-then-swap-demo.md](approve-then-swap-demo.md) | guide | D · 44% | Why/reason, Status/scope, Diagram, Security/failure, Operations |
| [architecture.md](architecture.md) | guide | D · 44% | Why/reason, Diagram, Security/failure, Operations, References/links |
| [evidence-graph.md](evidence-graph.md) | guide | D · 44% | Why/reason, Status/scope, Diagram, Security/failure, Operations |
| [Issue_Backlog_Execution_Plan.md](Issue_Backlog_Execution_Plan.md) | guide | D · 44% | Why/reason, Diagram, Security/failure, Operations, References/links |
| [Local_Development.md](Local_Development.md) | guide | D · 44% | Why/reason, Status/scope, Diagram, Security/failure, Operations |
| [mission.md](mission.md) | guide | D · 44% | Why/reason, Status/scope, Diagram, Security/failure, Operations |
| [performance-baseline.md](performance-baseline.md) | guide | D · 44% | Why/reason, Diagram, Security/failure, Operations, References/links |
| [adr/0004-ed25519-receipt-signing.md](adr/0004-ed25519-receipt-signing.md) | decision | D · 50% | Status/scope, Security/failure, References/links |
| [adr/index.md](adr/index.md) | decision | D · 50% | Why/reason, Status/scope, Security/failure |
| [AegisAgent_Agent_SOC_Design.md](AegisAgent_Agent_SOC_Design.md) | guide | D · 56% | Why/reason, Diagram, Operations, References/links |
| [AegisAgent_Agent_Workflow.md](AegisAgent_Agent_Workflow.md) | guide | D · 56% | Why/reason, Status/scope, Diagram, Operations |
| [AegisAgent_Agent_Workforce_Governance.md](AegisAgent_Agent_Workforce_Governance.md) | guide | D · 56% | Why/reason, Status/scope, Diagram, Security/failure |
| [AegisAgent_Cage_Docker_Security.md](AegisAgent_Cage_Docker_Security.md) | guide | D · 56% | Why/reason, Diagram, Operations, References/links |
| [AegisAgent_Debugging_Guide.md](AegisAgent_Debugging_Guide.md) | guide | D · 56% | Status/scope, Diagram, Security/failure, Operations |
| [AegisAgent_Diagram_Index.md](AegisAgent_Diagram_Index.md) | guide | D · 56% | Why/reason, Runnable/example, Security/failure, Operations |
| [AegisAgent_Problem_Definition.md](AegisAgent_Problem_Definition.md) | guide | D · 56% | Diagram, Security/failure, Operations, References/links |
| [AegisAgent_SOC_Console_HLD_LLD.md](AegisAgent_SOC_Console_HLD_LLD.md) | guide | D · 56% | Diagram, Runnable/example, Security/failure, Operations |
| [AegisAgent_Vision.md](AegisAgent_Vision.md) | guide | D · 56% | Why/reason, Status/scope, Diagram, Operations |
| [AegisAgent_World_Class_LLD.md](AegisAgent_World_Class_LLD.md) | guide | D · 56% | Why/reason, Security/failure, Operations, References/links |
| [github-integration.md](github-integration.md) | guide | D · 56% | Why/reason, Status/scope, Diagram, Security/failure |
| [qdrant-integration.md](qdrant-integration.md) | guide | D · 56% | Diagram, Security/failure, Operations, References/links |
| [runtime-authorization-api.md](runtime-authorization-api.md) | guide | D · 56% | Why/reason, Status/scope, Diagram, Operations |
| [api-reference.md](api-reference.md) | reference | C · 60% | Status/scope, Runnable/example |
| [event-schema.md](event-schema.md) | reference | C · 60% | Status/scope, References/links |
| [feature_history.md](feature_history.md) | reference | C · 60% | Runnable/example, References/links |
| [adr/0002-sqlite-first-storage.md](adr/0002-sqlite-first-storage.md) | decision | C · 67% | Status/scope, Security/failure |
| [adr/0003-aegis-jcs-1-canonicalization.md](adr/0003-aegis-jcs-1-canonicalization.md) | decision | C · 67% | Security/failure, References/links |
| [adr/0005-fail-closed-defaults.md](adr/0005-fail-closed-defaults.md) | decision | C · 67% | Security/failure, References/links |
| [adr/template.md](adr/template.md) | decision | C · 67% | Security/failure, References/links |
| [AegisAgent_Control_Command_Protocol.md](AegisAgent_Control_Command_Protocol.md) | guide | C · 67% | Why/reason, Operations, References/links |
| [AegisAgent_Gap_Reassessment_2026-06.md](AegisAgent_Gap_Reassessment_2026-06.md) | guide | C · 67% | Diagram, Runnable/example, Operations |
| [AegisAgent_GTM_Document.md](AegisAgent_GTM_Document.md) | guide | C · 67% | Diagram, Operations, References/links |
| [AegisAgent_Operational_Design.md](AegisAgent_Operational_Design.md) | guide | C · 67% | Why/reason, Diagram, References/links |
| [AegisAgent_Runtime_Data_Plane.md](AegisAgent_Runtime_Data_Plane.md) | guide | C · 67% | Why/reason, Operations, References/links |
| [AegisAgent_SOC_UI_Design.md](AegisAgent_SOC_UI_Design.md) | guide | C · 67% | Why/reason, Diagram, Security/failure |
| [AegisAgent_Technical_Design.md](AegisAgent_Technical_Design.md) | guide | C · 67% | Why/reason, Diagram, Operations |
| [AegisAgent_Threat_Model.md](AegisAgent_Threat_Model.md) | guide | C · 67% | Why/reason, Diagram, Operations |
| [AegisAgent_World_Class_HLD.md](AegisAgent_World_Class_HLD.md) | guide | C · 67% | Why/reason, Operations, References/links |
| [Architecture_Overview.md](Architecture_Overview.md) | guide | C · 67% | Why/reason, Runnable/example, Operations |
| [Documentation_Redesign_Plan.md](Documentation_Redesign_Plan.md) | guide | C · 67% | Why/reason, Security/failure, Operations |
| [Last_Mile_System_Walkthrough.md](Last_Mile_System_Walkthrough.md) | guide | C · 67% | Why/reason, Security/failure, Operations |
| [mcp-defense-architecture.md](mcp-defense-architecture.md) | guide | C · 67% | Status/scope, Diagram, Operations |
| [Repo_Knowledge_Map.md](Repo_Knowledge_Map.md) | guide | C · 67% | Why/reason, Security/failure, Operations |
| [security-model.md](security-model.md) | guide | C · 67% | Why/reason, Diagram, Operations |
| [slack-integration.md](slack-integration.md) | guide | C · 67% | Why/reason, Diagram, Security/failure |

## Complete inventory

| Page | Profile | Lines | Grade | Score |
|---|---|---:|:---:|---:|
| [action-receipt-spec.md](action-receipt-spec.md) | reference | 135 | B | 80% |
| [adr/0001-cedar-policy-engine.md](adr/0001-cedar-policy-engine.md) | decision | 68 | B | 83% |
| [adr/0002-sqlite-first-storage.md](adr/0002-sqlite-first-storage.md) | decision | 63 | C | 67% |
| [adr/0003-aegis-jcs-1-canonicalization.md](adr/0003-aegis-jcs-1-canonicalization.md) | decision | 71 | C | 67% |
| [adr/0004-ed25519-receipt-signing.md](adr/0004-ed25519-receipt-signing.md) | decision | 71 | D | 50% |
| [adr/0005-fail-closed-defaults.md](adr/0005-fail-closed-defaults.md) | decision | 80 | C | 67% |
| [adr/index.md](adr/index.md) | decision | 24 | D | 50% |
| [adr/template.md](adr/template.md) | decision | 34 | C | 67% |
| [AegisAgent_Agent_Cage.md](AegisAgent_Agent_Cage.md) | guide | 581 | B | 78% |
| [AegisAgent_Agent_SOC_Design.md](AegisAgent_Agent_SOC_Design.md) | guide | 757 | D | 56% |
| [AegisAgent_Agent_Workflow.md](AegisAgent_Agent_Workflow.md) | guide | 214 | D | 56% |
| [AegisAgent_Agent_Workforce_Governance.md](AegisAgent_Agent_Workforce_Governance.md) | guide | 252 | D | 56% |
| [AegisAgent_Cage_Docker_Security.md](AegisAgent_Cage_Docker_Security.md) | guide | 155 | D | 56% |
| [AegisAgent_Control_Command_Protocol.md](AegisAgent_Control_Command_Protocol.md) | guide | 671 | C | 67% |
| [AegisAgent_Debugging_Guide.md](AegisAgent_Debugging_Guide.md) | guide | 69 | D | 56% |
| [AegisAgent_Diagram_Index.md](AegisAgent_Diagram_Index.md) | guide | 39 | D | 56% |
| [AegisAgent_Gap_Reassessment_2026-06.md](AegisAgent_Gap_Reassessment_2026-06.md) | guide | 217 | C | 67% |
| [AegisAgent_GTM_Document.md](AegisAgent_GTM_Document.md) | guide | 242 | C | 67% |
| [AegisAgent_Integration_Connectivity.md](AegisAgent_Integration_Connectivity.md) | guide | 150 | D | 44% |
| [AegisAgent_Market_Gap_Analysis.md](AegisAgent_Market_Gap_Analysis.md) | guide | 170 | D | 44% |
| [AegisAgent_Operational_Design.md](AegisAgent_Operational_Design.md) | guide | 123 | C | 67% |
| [AegisAgent_Phased_PR_Plan.md](AegisAgent_Phased_PR_Plan.md) | guide | 930 | D | 44% |
| [AegisAgent_PRD.md](AegisAgent_PRD.md) | product | 851 | A | 100% |
| [AegisAgent_Problem_Definition.md](AegisAgent_Problem_Definition.md) | guide | 225 | D | 56% |
| [AegisAgent_Product_Research.md](AegisAgent_Product_Research.md) | guide | 192 | D | 44% |
| [AegisAgent_Runtime_Data_Plane.md](AegisAgent_Runtime_Data_Plane.md) | guide | 599 | C | 67% |
| [AegisAgent_SOC_Console_Design_System.md](AegisAgent_SOC_Console_Design_System.md) | guide | 606 | D | 33% |
| [AegisAgent_SOC_Console_HLD_LLD.md](AegisAgent_SOC_Console_HLD_LLD.md) | guide | 528 | D | 56% |
| [AegisAgent_SOC_UI_Design.md](AegisAgent_SOC_UI_Design.md) | guide | 280 | C | 67% |
| [AegisAgent_Technical_Design.md](AegisAgent_Technical_Design.md) | guide | 375 | C | 67% |
| [AegisAgent_Threat_Model.md](AegisAgent_Threat_Model.md) | guide | 167 | C | 67% |
| [AegisAgent_Vision.md](AegisAgent_Vision.md) | guide | 197 | D | 56% |
| [AegisAgent_World_Class_HLD.md](AegisAgent_World_Class_HLD.md) | guide | 777 | C | 67% |
| [AegisAgent_World_Class_LLD.md](AegisAgent_World_Class_LLD.md) | guide | 973 | D | 56% |
| [api-reference.md](api-reference.md) | reference | 11 | C | 60% |
| [api-versioning.md](api-versioning.md) | guide | 75 | D | 33% |
| [approve-then-swap-demo.md](approve-then-swap-demo.md) | guide | 227 | D | 44% |
| [Architecture_Overview.md](Architecture_Overview.md) | guide | 137 | C | 67% |
| [architecture.md](architecture.md) | guide | 262 | D | 44% |
| [components/Agent_Cage.md](components/Agent_Cage.md) | component | 69 | A | 100% |
| [components/Approval_Engine.md](components/Approval_Engine.md) | component | 100 | B | 89% |
| [components/Console_UI_Bun_Contracts.md](components/Console_UI_Bun_Contracts.md) | component | 189 | B | 89% |
| [components/Console_UI.md](components/Console_UI.md) | component | 153 | A | 100% |
| [components/Egress_Proxy.md](components/Egress_Proxy.md) | component | 61 | A | 100% |
| [components/Gateway.md](components/Gateway.md) | component | 875 | A | 100% |
| [components/MCP_Gateway.md](components/MCP_Gateway.md) | component | 60 | B | 78% |
| [components/Node_Sensor.md](components/Node_Sensor.md) | component | 72 | A | 100% |
| [components/Policy_Engine.md](components/Policy_Engine.md) | component | 68 | A | 100% |
| [components/Prompt_Model_Capture.md](components/Prompt_Model_Capture.md) | component | 70 | A | 100% |
| [components/Receipt_Engine.md](components/Receipt_Engine.md) | component | 91 | A | 100% |
| [components/SDK.md](components/SDK.md) | component | 113 | B | 89% |
| [components/SOC_Engine.md](components/SOC_Engine.md) | component | 105 | B | 89% |
| [components/Storage.md](components/Storage.md) | component | 70 | A | 100% |
| [components/Tool_Broker.md](components/Tool_Broker.md) | component | 63 | A | 100% |
| [concepts.md](concepts.md) | guide | 415 | B | 78% |
| [contributing/documentation-standard.md](contributing/documentation-standard.md) | authoring | 222 | B | 80% |
| [current-vs-roadmap.md](current-vs-roadmap.md) | reference | 145 | A | 100% |
| [database-schema.md](database-schema.md) | reference | 274 | D | 40% |
| [demo-github-attack.md](demo-github-attack.md) | guide | 220 | B | 78% |
| [deployment-guide.md](deployment-guide.md) | guide | 298 | A | 100% |
| [Documentation_Audit.md](Documentation_Audit.md) | reference | 91 | B | 80% |
| [Documentation_Index.md](Documentation_Index.md) | reference | 69 | B | 80% |
| [Documentation_Redesign_Plan.md](Documentation_Redesign_Plan.md) | guide | 114 | C | 67% |
| [event-schema.md](event-schema.md) | reference | 294 | C | 60% |
| [evidence-graph.md](evidence-graph.md) | guide | 169 | D | 44% |
| [fail-closed-behavior.md](fail-closed-behavior.md) | guide | 147 | A | 100% |
| [faq.md](faq.md) | landing | 341 | B | 86% |
| [feature_history.md](feature_history.md) | reference | 118 | C | 60% |
| [flows/Approval_Flow.md](flows/Approval_Flow.md) | flow | 59 | A | 100% |
| [flows/Ban_Quarantine_Flow.md](flows/Ban_Quarantine_Flow.md) | flow | 82 | A | 100% |
| [flows/Control_Command_Flow.md](flows/Control_Command_Flow.md) | flow | 68 | A | 100% |
| [flows/Egress_Block_Flow.md](flows/Egress_Block_Flow.md) | flow | 56 | A | 100% |
| [flows/Known_Agent_Flow.md](flows/Known_Agent_Flow.md) | flow | 69 | B | 86% |
| [flows/MCP_Gateway_Flow.md](flows/MCP_Gateway_Flow.md) | flow | 55 | B | 86% |
| [flows/Prompt_To_Action_Lineage.md](flows/Prompt_To_Action_Lineage.md) | flow | 48 | B | 86% |
| [flows/Receipt_Flow.md](flows/Receipt_Flow.md) | flow | 57 | B | 86% |
| [flows/SOC_Incident_Flow.md](flows/SOC_Incident_Flow.md) | flow | 58 | A | 100% |
| [flows/Tool_Broker_Flow.md](flows/Tool_Broker_Flow.md) | flow | 53 | A | 100% |
| [flows/Unknown_Agent_Cage_Flow.md](flows/Unknown_Agent_Cage_Flow.md) | flow | 72 | A | 100% |
| [getting-started.md](getting-started.md) | landing | 80 | B | 86% |
| [github-integration.md](github-integration.md) | guide | 125 | D | 56% |
| [Glossary.md](Glossary.md) | landing | 100 | A | 100% |
| [How_It_Works.md](How_It_Works.md) | landing | 75 | A | 100% |
| [Implementation_Status.md](Implementation_Status.md) | reference | 106 | B | 80% |
| [index.md](index.md) | landing | 109 | B | 86% |
| [installation.md](installation.md) | guide | 127 | A | 100% |
| [Issue_Backlog_Execution_Plan.md](Issue_Backlog_Execution_Plan.md) | guide | 208 | D | 44% |
| [Last_Mile_System_Walkthrough.md](Last_Mile_System_Walkthrough.md) | guide | 147 | C | 67% |
| [Local_Development.md](Local_Development.md) | guide | 87 | D | 44% |
| [mcp-defense-architecture.md](mcp-defense-architecture.md) | guide | 145 | C | 67% |
| [mission.md](mission.md) | guide | 153 | D | 44% |
| [onboarding/For_DevOps_Engineer.md](onboarding/For_DevOps_Engineer.md) | onboarding | 77 | A | 100% |
| [onboarding/For_Frontend_Engineer.md](onboarding/For_Frontend_Engineer.md) | onboarding | 75 | A | 100% |
| [onboarding/For_New_Engineer.md](onboarding/For_New_Engineer.md) | onboarding | 88 | A | 100% |
| [onboarding/For_SDK_Developer.md](onboarding/For_SDK_Developer.md) | onboarding | 81 | A | 100% |
| [onboarding/For_Security_Architect.md](onboarding/For_Security_Architect.md) | onboarding | 71 | A | 100% |
| [onboarding/For_SOC_Analyst.md](onboarding/For_SOC_Analyst.md) | onboarding | 79 | A | 100% |
| [performance-baseline.md](performance-baseline.md) | guide | 535 | D | 44% |
| [performance-tuning-guide.md](performance-tuning-guide.md) | guide | 201 | B | 78% |
| [Product_Overview.md](Product_Overview.md) | landing | 73 | B | 86% |
| [Product_Requirements_Traceability.md](Product_Requirements_Traceability.md) | reference | 90 | B | 80% |
| [production-hardening.md](production-hardening.md) | guide | 196 | A | 100% |
| [qdrant-integration.md](qdrant-integration.md) | guide | 112 | D | 56% |
| [quickstart.md](quickstart.md) | guide | 182 | A | 100% |
| [README.md](README.md) | guide | 107 | B | 78% |
| [Repo_Knowledge_Map.md](Repo_Knowledge_Map.md) | guide | 238 | C | 67% |
| [runbooks/agent-token-rotation.md](runbooks/agent-token-rotation.md) | runbook | 80 | A | 100% |
| [runbooks/backup-and-restore.md](runbooks/backup-and-restore.md) | runbook | 79 | A | 100% |
| [runbooks/data-exfiltration.md](runbooks/data-exfiltration.md) | runbook | 88 | A | 100% |
| [runbooks/deny-storm.md](runbooks/deny-storm.md) | runbook | 103 | A | 100% |
| [runbooks/index.md](runbooks/index.md) | runbook | 72 | A | 100% |
| [runbooks/receipt-chain-verification.md](runbooks/receipt-chain-verification.md) | runbook | 88 | A | 100% |
| [runbooks/secret-rotation.md](runbooks/secret-rotation.md) | runbook | 88 | A | 100% |
| [runtime-authorization-api.md](runtime-authorization-api.md) | guide | 331 | D | 56% |
| [sdk-parity-status.md](sdk-parity-status.md) | reference | 35 | D | 40% |
| [security-model.md](security-model.md) | guide | 214 | C | 67% |
| [slack-integration.md](slack-integration.md) | guide | 192 | C | 67% |
| [START_HERE.md](START_HERE.md) | landing | 69 | B | 86% |
| [templates/component-page.md](templates/component-page.md) | authoring | 145 | A | 100% |
| [The_One_Minute_Tour.md](The_One_Minute_Tour.md) | landing | 59 | A | 100% |
| [What_Is_AegisAgent.md](What_Is_AegisAgent.md) | landing | 67 | A | 100% |
| [Why_AegisAgent.md](Why_AegisAgent.md) | landing | 67 | A | 100% |

## Migration rules

1. Verify claims against code and `Implementation_Status.md` before rewriting.
2. Start with high-trust entry points, security guarantees, deployment, and runbooks.
3. Use the appropriate profile; do not add irrelevant empty sections.
4. Add or update diagrams only when they improve understanding; explain each diagram.
5. Run the docs validator and strict MkDocs build after each batch.

## References

- [Documentation Standard](contributing/documentation-standard.md)
- [Component Page Template](templates/component-page.md)
- [Documentation Audit](Documentation_Audit.md)
- [Implementation Status](Implementation_Status.md)

