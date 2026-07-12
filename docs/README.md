# AegisAgent — Documentation

**The integrity layer for AI agent actions — delivered as an integrity-anchored Agent SOC.**
Open, self-hostable, framework-neutral.

> *Make the approval trustworthy. Trust the source, not the text. Run the SOC on the proof.*

This folder is the **single source for AegisAgent product documentation**. It renders on GitHub today; it is structured so it can later be published to a docs website (see [Publishing](#publishing)) without moving files.

---

## 🧭 Start Here (the last-mile documentation system)

**New to the repo? Begin at [START_HERE.md](START_HERE.md)** — persona-based reading paths, the full docs map, and the naming table for canonical docs.

| Entry point | What it gives you |
|---|---|
| [START_HERE.md](START_HERE.md) | The front door: pick your path by role |
| [Product_Overview.md](Product_Overview.md) | What/why in plain language |
| [Last_Mile_System_Walkthrough.md](Last_Mile_System_Walkthrough.md) | The entire system as one story |
| [Architecture_Overview.md](Architecture_Overview.md) | The 11 choke points, trust boundaries, fail-closed paths |
| [../ARCHITECTURE.md](../ARCHITECTURE.md) + [LLD.md](LLD.md) | Canonical target HLD/LLD and benchmark contract |
| [../MIGRATION_MATRIX.md](../MIGRATION_MATRIX.md) | Repository-backed current-to-target audit and cutover gates |
| [Implementation_Status.md](Implementation_Status.md) | **Honest ledger**: implemented vs. partial vs. planned |
| [Repo_Knowledge_Map.md](Repo_Knowledge_Map.md) | Maintainer's map: every layer → files → flows → doc gaps |
| [onboarding/](onboarding/For_New_Engineer.md) | Six role-specific onboarding guides |
| [flows/](flows/Known_Agent_Flow.md) | Five end-to-end flow deep-dives |
| [AegisAgent_Diagram_Index.md](AegisAgent_Diagram_Index.md) + [diagrams/](diagrams/) | Every diagram as Mermaid source |
| [explorer/index.html](explorer/index.html) | Interactive 3D system map (2D fallback, driven by [architecture-map.json](architecture-map.json)) |
| [Glossary.md](Glossary.md) | Shared vocabulary |
| [contributing/documentation-standard.md](contributing/documentation-standard.md) | Required teaching, evidence, diagram, code, security, and operations standard for docs authors |
| [templates/component-page.md](templates/component-page.md) | Copyable structure for production-grade component pages |

Docs hygiene: `node scripts/validate-docs.mjs` checks required docs, internal links, diagram inventory, and `architecture-map.json` references. `architecture-map.json` is the machine-readable source of truth for the explorer and layered diagrams — update it when components change.

---

## 📖 Product Documentation
*User-facing — safe to publish.*

| Doc | What it covers |
|---|---|
| [Integration & Connectivity](AegisAgent_Integration_Connectivity.md) | **Start here.** How agents connect from anywhere, how actions are collected, how rules are applied (SDK / proxy / agentless) |
| [Agent SOC Design](AegisAgent_Agent_SOC_Design.md) | The SOC: collect → detect → correlate → alert → respond, anchored on verifiable evidence |
| [SOC Console UI](AegisAgent_SOC_UI_Design.md) | The dashboard (Kibana + Grafana model) — overview, explore, incidents, approvals |
| [Agent Workforce Governance](AegisAgent_Agent_Workforce_Governance.md) | Govern your AI agents as a digital workforce — directory, lifecycle, fleet rollup |
| [Action Receipt Spec](action-receipt-spec.md) | The open, hash-chained verifiable-receipt format (the evidence standard) |
| [SDK Parity Status](sdk-parity-status.md) | Feature matrix for Python, Go, and TypeScript SDKs |

---

## 🏗 Architecture & Security
*Technical reference.*

| Doc | What it covers |
|---|---|
| [Technical Design](AegisAgent_Technical_Design.md) | Gateway, SDKs, the two-plane architecture, data model, APIs |
| [Agent Workflow](AegisAgent_Agent_Workflow.md) | The seven workflows: authorization, approval integrity, audit, SOC |
| [Threat Model](AegisAgent_Threat_Model.md) | T-A approval manipulation · T-B confused deputy · T-C evidence tampering · T-D attacks on the SOC |
| [Operational Design](AegisAgent_Operational_Design.md) | Deployment, SLOs, fail-closed behavior, canonicalization & receipt-chain ops |
| [Production Hardening](production-hardening.md) | Auth modes, public-bind safety, admin gating, replay store, receipt durability & verification endpoints, SOC query — config reference + checklist |
| [Database Schema (ERD)](database-schema.md) | Entity-relationship diagram and migration notes |

---

## 🧭 Strategy & Product Management
*Internal — **keep out of the public docs site** when you publish.*

| Doc | What it covers |
|---|---|
| [Gap Reassessment (June 2026)](AegisAgent_Gap_Reassessment_2026-06.md) | **Source of truth** — market reset + the SOC-on-moat thesis |
| [Vision](AegisAgent_Vision.md) | North star, phases, what we will and won't become |
| [PRD](AegisAgent_PRD.md) | Product requirements, MVP scope, success metrics |
| [Problem Definition](AegisAgent_Problem_Definition.md) | The problem, personas, validation |
| [Market Gap Analysis](AegisAgent_Market_Gap_Analysis.md) | Deep competitive landscape |
| [Product Research](AegisAgent_Product_Research.md) | Research foundation + 90-day plan |
| [GTM](AegisAgent_GTM_Document.md) | Positioning, ICP, pricing, launch |

---

## 🎨 Assets
- [archive/dashboard-mock.html](archive/dashboard-mock.html) — archived design-era SOC Console mock (superseded by the real console in `ui/`).

---

## Reading order (new to AegisAgent)
1. [Integration & Connectivity](AegisAgent_Integration_Connectivity.md) — how it attaches and enforces
2. [Agent SOC Design](AegisAgent_Agent_SOC_Design.md) — what it monitors
3. [Technical Design](AegisAgent_Technical_Design.md) — how it's built
4. [Action Receipt Spec](action-receipt-spec.md) — the evidence
5. [Gap Reassessment](AegisAgent_Gap_Reassessment_2026-06.md) — *why* it's shaped this way (internal)

---

## Publishing

The documentation is published to **<https://lavkushry.github.io/AegisAgent/>** using **MkDocs Material**. The site is auto-deployed on every push to `main` via the [`.github/workflows/docs.yml`](../.github/workflows/docs.yml) workflow.

**Published sections:** 📖 Product Documentation + 🏗 Architecture & Security. **Excluded:** 🧭 Strategy & PM docs (those are internal and listed in `mkdocs.yml` → `exclude_docs`). No files need to move — publishing is just a nav config over this folder.

To build and preview locally:

```bash
pip install -r requirements-docs.txt
mkdocs serve
```
