# Documentation Redesign Plan

**Goal:** simple first, visual second, technical depth third, code traceability always — without duplicating, faking, or over-engineering anything.
**Inputs:** [Documentation_Audit.md](Documentation_Audit.md) (per-file decisions) and the code at committed HEAD.

## 1. Audience map

| Audience | Needs | Served by | Target time |
|---|---|---|---|
| New visitor | understand the product | The_One_Minute_Tour → What_Is → Why | 60 seconds |
| Developer | integrate the SDK | onboarding/For_SDK_Developer + Local_Development | 5–10 min |
| Security architect | trust boundaries | onboarding/For_Security_Architect + Architecture_Overview §5–6 + Threat_Model | 10–15 min |
| SOC analyst | incidents/timeline/evidence | onboarding/For_SOC_Analyst + flows/SOC_Incident_Flow + runbooks | 10 min |
| Backend maintainer | API → policy → storage → receipt | Repo_Knowledge_Map + components/* + flows/Known_Agent_Flow | 30 min to trace |
| Frontend maintainer | UI → API → state → panels | onboarding/For_Frontend_Engineer + components/Console_UI | 30 min |
| DevOps engineer | deploy, configure, operate, debug | onboarding/For_DevOps_Engineer + deployment-guide + production-hardening + runbooks + Debugging_Guide | — |
| Contributor | repo + PR workflow | CONTRIBUTING.md + onboarding/For_New_Engineer + architecture.md (code patterns) | first week |
| Investor / product reviewer | honest capability picture | Product_Overview + Implementation_Status + current-vs-roadmap | 15 min |

## 2. The documentation hierarchy (as built)

```text
Level 1  Simple           START_HERE · What_Is · Why · One_Minute_Tour · How_It_Works · Glossary · faq
Level 2  Flows            flows/ (11 flow pages, each with a small diagram)
Level 3  Architecture     Architecture_Overview · security-model · Threat_Model · fail-closed-behavior
                          data/event/receipt/API models · Runtime_Data_Plane + target designs (HLD/LLD/Cage/CCP)
Level 4  Components       components/ (14 pages, standard format, honest status)
Level 5  Build/run/operate Local_Development · quickstart · deployment-guide · production-hardening
                          runbooks/ · Debugging_Guide · onboarding/ (6 personas)
Level 6  Maintainer       Repo_Knowledge_Map · Implementation_Status · Diagram_Index · architecture-map.json
                          Documentation_{Index,Audit,Redesign_Plan}
```

## 3. Requested-name → canonical-file mapping

Where a conventional name would duplicate an existing accurate doc, the existing doc is canonical (one page per topic, ever):

| Conventional name | Canonical file | Note |
|---|---|---|
| architecture/HLD.md | [Architecture_Overview.md](Architecture_Overview.md) (current system) + [AegisAgent_World_Class_HLD.md](AegisAgent_World_Class_HLD.md) (target design) | Two docs on purpose: what *is* vs. what is *designed* |
| architecture/LLD.md | [Repo_Knowledge_Map.md](Repo_Knowledge_Map.md) + [AegisAgent_Technical_Design.md](AegisAgent_Technical_Design.md) + [AegisAgent_World_Class_LLD.md](AegisAgent_World_Class_LLD.md) | Crates, APIs, storage, flows |
| architecture/Security_Model.md | [security-model.md](security-model.md) | |
| architecture/Threat_Model.md | [AegisAgent_Threat_Model.md](AegisAgent_Threat_Model.md) | |
| architecture/Failure_Model.md | [fail-closed-behavior.md](fail-closed-behavior.md) | |
| architecture/Data_Model.md | [database-schema.md](database-schema.md) | |
| architecture/API_Model.md | [api-reference.md](api-reference.md) (generated) + [runtime-authorization-api.md](runtime-authorization-api.md) | Never hand-maintain the route list |
| architecture/Event_Model.md | [event-schema.md](event-schema.md) | |
| architecture/Receipt_Model.md | [action-receipt-spec.md](action-receipt-spec.md) | |
| architecture/Runtime_Data_Plane.md | [AegisAgent_Runtime_Data_Plane.md](AegisAgent_Runtime_Data_Plane.md) | |
| developer/Local_Development.md | [Local_Development.md](Local_Development.md) | |
| developer/SDK_Integration.md | [onboarding/For_SDK_Developer.md](onboarding/For_SDK_Developer.md) + [components/SDK.md](components/SDK.md) | |
| developer/API_Guide.md | [api-reference.md](api-reference.md) + [api-versioning.md](api-versioning.md) | |
| developer/Testing.md | [Local_Development.md](Local_Development.md) §4 + CI docs in [Repo_Knowledge_Map.md](Repo_Knowledge_Map.md) §9 | |
| operator/Deployment.md | [deployment-guide.md](deployment-guide.md) | |
| operator/Production_Checklist.md | [production-hardening.md](production-hardening.md) | |
| operator/Runbook.md | [runbooks/index.md](runbooks/index.md) | |
| operator/Debugging.md | [AegisAgent_Debugging_Guide.md](AegisAgent_Debugging_Guide.md) | |
| maintainer/Repo_Map.md, Code_Flow_Map.md | [Repo_Knowledge_Map.md](Repo_Knowledge_Map.md) §2/§11 | |
| maintainer/PR_Guide.md | `CONTRIBUTING.md` (repo root) | |
| maintainer/Issue_Backlog_Process.md | [Issue_Backlog_Execution_Plan.md](Issue_Backlog_Execution_Plan.md) | |
| Implementation_Status.md | [Implementation_Status.md](Implementation_Status.md) | Renamed from Implementation_Status_Matrix.md |

## 4. Moves, merges, archives, deletions in this pass

- **Moved:** 10 component docs → `components/`, 3 flow docs renamed, Ban/Quarantine model → `flows/Ban_Quarantine_Flow.md`, Glossary + Implementation_Status renamed, 7 `.mmd` diagrams renamed to flow-named files. All internal links rewritten and validated.
- **Merged:** FAQ additions merged into `faq.md` (no second FAQ); dual-format terms merged into `Glossary.md`.
- **Archived:** `dashboard-mock.html` → `archive/` (see [archive/README.md](archive/README.md)).
- **Deleted:** nothing.

## 5. Docs-site decision (deliberately not a new Next.js app)

The repo already ships **MkDocs Material** deployed to GitHub Pages by `.github/workflows/docs.yml`, with search, sidebar navigation, dark mode, copyable code blocks, and (as of this pass) native Mermaid rendering. Building a parallel `docs-site/` Next.js app would duplicate that pipeline, add a JS build to maintain, and violate "do not over-engineer the docs-site." The optional interactive map exists as a single self-contained page (`explorer/index.html`, 2D fallback, no build step). If a premium marketing-grade site is wanted later, that is Phase 4 below — a product decision, not a docs necessity.

## 6. What must stay simple vs. deep vs. reference-only

- **Simple (no jargon, < 2 min each):** Level 1 docs.
- **Visual:** every flow page = one small diagram + steps; diagrams stay mobile-readable (validated inventory in [AegisAgent_Diagram_Index.md](AegisAgent_Diagram_Index.md)).
- **Deep:** components/, Threat_Model, Technical_Design, target designs (HLD/LLD/Cage/CCP), production-hardening.
- **Reference-only (generated or tabular, never narrative):** api-reference.md, database-schema.md, sdk-parity-status.md, Implementation_Status.md, architecture-map.json.

## 7. Phased documentation PR plan

| Phase | PR | Content |
|---|---|---|
| 1 (this PR) | docs: last-mile documentation system | Audit, plan, Level-1 docs, flows/components hierarchy, status ledger, diagrams, explorer, validation script, mkdocs nav |
| 2 | docs: SOC doc consolidation | Merge overlap between Agent_SOC_Design / SOC_Console_HLD_LLD / SOC_UI_Design into components/SOC_Engine + Console_UI; refresh security-model.md date |
| 3 | docs: naming + cleanup | Rename `architecture.md` → `CODE_PATTERNS.md` (update tooling references), drop legacy `_config.yml`, delete empty `gateway/` dir, refresh root README quickstart |
| 4 (optional) | docs-site: guided visual walkthrough | Only if wanted: a `/see-aegisagent` guided product walkthrough (8 scenes: act → check → decide → approve → execute → receipt → investigate → stop); reuse architecture-map.json; keep 3D optional |
| ongoing | every feature PR | Update Implementation_Status.md + architecture-map.json in the same PR; `node scripts/validate-docs.mjs` enforces inventory |

## 8. Validation

`node scripts/validate-docs.mjs` (also `make docs-validate`) checks: required docs exist · internal links resolve · architecture-map.json valid (nodes, edges, flows, related docs/files) · diagram inventory matches the index · Implementation_Status.md contains every required capability with valid status words · explorer wiring. `mkdocs build` must pass warning-free.

The repository-wide writing contract is [contributing/documentation-standard.md](contributing/documentation-standard.md). New or substantially rewritten component pages start from [templates/component-page.md](templates/component-page.md). [components/Gateway.md](components/Gateway.md) is the canonical worked example; validation checks its required section order so the template and real documentation cannot silently drift apart.

## 9. PRD and all-docs convergence (July 2026)

The current [Product Requirements Document](AegisAgent_PRD.md) replaces the stale June MVP plan with stable requirement IDs, Now/Next/Later scope, negative security acceptance criteria, and release gates. [Product Requirements Traceability](Product_Requirements_Traceability.md) maps those IDs to owning docs, source, verification, and the authoritative implementation ledger.

The generated [Documentation Quality Report](Documentation_Quality_Report.md) inventories every active Markdown page using profile-specific signals. Migration order is:

1. Security guarantees, fail-closed behavior, deployment, and incident runbooks.
2. Product entry points and persona onboarding.
3. Implemented component and flow guides.
4. Partial runtime-control guides, with force-path gaps stated first.
5. Reference, ADR, and internal strategy cleanup.

The report is a structural prioritization tool, not an accuracy certificate. Every migrated page still requires code/status verification.

## Related docs

[Documentation_Audit.md](Documentation_Audit.md) · [Documentation_Index.md](Documentation_Index.md) · [START_HERE.md](START_HERE.md)
