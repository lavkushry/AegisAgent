# Documentation Audit

**Date:** 2026-07-03 · **Scope:** every file under `docs/` (plus root `README.md`) · **Method:** each file checked against the code at committed HEAD (route table in `src/src/main.rs`, storage modules in `lib/storage/src/db/`, migrations 0001–0030, SDKs, `ui/`, CI workflows).

**Actions:** Keep (accurate, in place) · Rewrite (kept but reworked) · Merge (content folded into another doc) · Move (relocated in the new hierarchy) · Archive (superseded, kept for history in `docs/archive/`) · Delete (nothing was deleted in this pass — see policy note at the bottom).

**Audience codes:** A=anyone · D=developer · S=security/SOC · M=maintainer · O=operator · I=internal/strategy.

## Level-1 / product docs

| File | Current purpose | Accuracy | Audience | Problem | Action | Reason |
|---|---|---|---|---|---|---|
| README.md (docs/) | Folder index + publishing notes | Good | M | Was missing new-system links | Rewrite (updated) | Now points at START_HERE + Documentation_Index |
| START_HERE.md | Front door | Good | A | Was route-map heavy | Rewrite | Now 3 reading paths ("new / developer / security"), simple-first |
| What_Is_AegisAgent.md · Why_AegisAgent.md · The_One_Minute_Tour.md · How_It_Works.md | Simple product understanding | Good | A | Didn't exist | **New** | Level 1 of the hierarchy; 60-second comprehension |
| Product_Overview.md | Full product framing | Good | A/D | — | Keep | Bridges simple docs and architecture |
| Last_Mile_System_Walkthrough.md | Whole system as one story | Good | A/D/S | — | Keep | The flagship narrative doc |
| Glossary.md | Vocabulary | Good | A | Single-column meanings | Rewrite (extended) | Added simple+technical dual table; renamed from AegisAgent_Glossary.md |
| faq.md | Q&A | Good | A | Missing 9 required questions | Rewrite (extended) | Added fail-closed, containment, cage/sensor/broker, how-to Qs |
| concepts.md | Plain-English core ideas | Good | A | Overlaps Glossary/What_Is slightly | Keep | Different depth; harmless overlap, linked from index |
| index.md | MkDocs landing page | Good | A | — | Keep | Site home |
| getting-started.md · quickstart.md · installation.md | Getting started | Good | D | — | Keep | Canonical onboarding trio |
| mission.md | Mission page | Good | A | Links to internal Vision doc (excluded from site) | Keep | Known MkDocs INFO, acceptable |
| current-vs-roadmap.md | Public status summary | Good | A | Overlaps Implementation_Status.md | Keep | Public-facing summary vs. maintainer ledger; each links the other |

## Flows & components (new hierarchy)

| File | Current purpose | Accuracy | Audience | Problem | Action | Reason |
|---|---|---|---|---|---|---|
| flows/Known_Agent_Flow.md | End-to-end authorize flow | Good | D/S | — | Move (was Known_Agent_Action_Flow) | Level-2 naming |
| flows/Unknown_Agent_Cage_Flow.md | Cage flow, ✅/📐 marked | Good | S/M | — | Move (was Anonymous_Agent_Cage_Flow) | Level-2 naming |
| flows/Approval_Flow.md · SOC_Incident_Flow.md · MCP_Gateway_Flow.md | Short visual flows | Good | D/S | Didn't exist | **New** | Small, mobile-readable flow pages over the deep component docs |
| flows/Receipt_Flow.md | Receipt chain + verification | Good | D/S | — | Move (was Receipt_Chain_Verification) | Level-2 naming |
| flows/Ban_Quarantine_Flow.md | Containment ladder | Good | S | — | Move (was AegisAgent_Ban_Quarantine_Model) | It *is* the flow; avoids a duplicate page |
| flows/Tool_Broker_Flow.md · Egress_Block_Flow.md | Planned flows, clearly labeled | Good (as design) | S/M | Didn't exist | **New** | Choke points get stable homes; status stated first |
| flows/Prompt_To_Action_Lineage.md · Control_Command_Flow.md | Lineage / signed commands | Good | S/M | — | Keep | Honest ✅/📐 marking throughout |
| components/Approval_Engine.md · Receipt_Engine.md · SOC_Engine.md · MCP_Gateway.md · SDK.md · Console_UI.md · Node_Sensor.md · Egress_Proxy.md · Tool_Broker.md · Prompt_Model_Capture.md | Component references | Good | M | — | Move (from AegisAgent_* names) | Level-4 hierarchy; all follow the standard page format |
| components/Gateway.md · Policy_Engine.md · Storage.md · Agent_Cage.md | Component references | Good | M | Didn't exist | **New** | Completes the component set; Agent_Cage is a status page over the design doc |

## Architecture & security

| File | Current purpose | Accuracy | Audience | Problem | Action | Reason |
|---|---|---|---|---|---|---|
| Architecture_Overview.md | HLD of the *current* system (choke points, planes, boundaries) | Good | D/S/M | — | Keep | Serves the "HLD" role for what exists; links target designs |
| AegisAgent_Technical_Design.md | Two-plane technical design | Good | M | Long | Keep | Depth doc; linked, not duplicated |
| AegisAgent_Threat_Model.md | T-A…T-D threat model | Good | S | — | Keep | Canonical threat model |
| security-model.md | Security guarantees/boundaries | Good | S | Dated header (v1.0, 2026-06-16) | Keep | Still accurate; refresh date next touch |
| fail-closed-behavior.md | Failure model | Good | D/S | — | Keep | Canonical "Failure_Model" |
| database-schema.md · event-schema.md · action-receipt-spec.md · runtime-authorization-api.md · api-reference.md · api-versioning.md · evidence-graph.md | Data/Event/Receipt/API models | Good (api-reference is generated) | D/M | — | Keep | Canonical Level-3 reference set |
| AegisAgent_World_Class_HLD.md · _LLD.md · AegisAgent_Runtime_Data_Plane.md · AegisAgent_Agent_Cage.md · AegisAgent_Control_Command_Protocol.md · AegisAgent_Phased_PR_Plan.md | Target designs (runtime data plane) | Good **as designs** | M | Must never read as shipped | Keep | Clearly labeled "target design"; component pages carry the status |
| adr/*.md (7) | Decision records | Good | M | — | Keep | Standard ADR set |
| mcp-defense-architecture.md | MCP defense deep design | Good | S/M | — | Keep | Deep companion to components/MCP_Gateway.md |
| AegisAgent_Agent_Workflow.md · AegisAgent_Agent_SOC_Design.md · AegisAgent_SOC_UI_Design.md · AegisAgent_SOC_Console_Design_System.md · AegisAgent_SOC_Console_HLD_LLD.md · AegisAgent_Agent_Workforce_Governance.md · AegisAgent_Integration_Connectivity.md · AegisAgent_Operational_Design.md | Product/SOC/UI design set | Good | S/M | Some overlap between SOC docs | Keep | Merge candidates for a later pass (see Redesign Plan Phase 3); not worth churn now |

## Developer / operator / maintainer

| File | Current purpose | Accuracy | Audience | Problem | Action | Reason |
|---|---|---|---|---|---|---|
| Local_Development.md · AegisAgent_Debugging_Guide.md | Build/run/debug | Good | D/O | — | Keep | Canonical Level-5 docs |
| deployment-guide.md · production-hardening.md · performance-baseline.md · performance-tuning-guide.md | Deploy/operate/tune | Good | O | Two stale links fixed | Keep (link fixes) | Canonical operator set |
| runbooks/*.md (7) | Incident runbooks | Good | O/S | — | Keep | Canonical "Runbook" |
| onboarding/*.md (6) | Role onboarding | Good | all | — | Keep | The persona layer |
| github-integration.md · slack-integration.md · qdrant-integration.md | Integrations | Good | O | qdrant had a dead `file:///` link + old `gateway/` path (fixed) | Keep (fixed) | — |
| Repo_Knowledge_Map.md | Maintainer repo map | Good | M | — | Keep | Serves "Repo_Map" + "Code_Flow_Map" |
| Implementation_Status.md | Honest capability ledger | Good | M | Emoji statuses | Rewrite (renamed from Implementation_Status_Matrix.md) | Status values now Implemented/Partial/Planned/Missing; validated by script |
| AegisAgent_Diagram_Index.md + diagrams/*.mmd (19) | Diagram inventory | Good | all | — | Keep (renamed several .mmd) | Diagram-as-code, validated |
| architecture-map.json + explorer/index.html | Machine-readable map + optional interactive view | Good | M | — | Keep | JSON is source of truth; explorer is optional with 2D fallback |
| feature_history.md · sdk-parity-status.md · Issue_Backlog_Execution_Plan.md | History/status/process | Good | M | — | Keep | Referenced from CLAUDE.md and index |
| architecture.md | **Mandatory code patterns** (Qdrant-inspired), not product architecture | Good | M | Name collides with product architecture | Keep | Rename to CODE_PATTERNS.md proposed for a later pass (it is referenced by tooling) |
| _config.yml | Legacy Jekyll config | Stale | — | Superseded by mkdocs.yml | Keep for now | Harmless; delete when GitHub Pages fully on mkdocs (Phase 3) |

## Internal strategy docs (not published)

| File | Action | Reason |
|---|---|---|
| AegisAgent_Gap_Reassessment_2026-06.md (source of truth) · AegisAgent_Vision.md · AegisAgent_PRD.md · AegisAgent_Problem_Definition.md · AegisAgent_Market_Gap_Analysis.md · AegisAgent_Product_Research.md · AegisAgent_GTM_Document.md | Keep (excluded from site) | Intentionally internal; listed in `mkdocs.yml → exclude_docs` |

## Archived in this pass

| File | Why | Replaced by |
|---|---|---|
| archive/dashboard-mock.html | Design-era static console mock; real console ships in `ui/` | components/Console_UI.md |

## Deletion policy note

Nothing was deleted. Everything questionable was either archived with an explanation (`docs/archive/README.md`) or kept with a merge/rename recommendation recorded in [Documentation_Redesign_Plan.md](Documentation_Redesign_Plan.md). Root `README.md` (repo) was audited as accurate but quickstart details should be re-verified next touch.

## Related docs

[Documentation_Redesign_Plan.md](Documentation_Redesign_Plan.md) · [Documentation_Index.md](Documentation_Index.md) · [Implementation_Status.md](Implementation_Status.md)
