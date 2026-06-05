# AegisAgent — Documentation

**The integrity layer for AI agent actions — delivered as an integrity-anchored Agent SOC.**
Open, self-hostable, framework-neutral.

> *Make the approval trustworthy. Trust the source, not the text. Run the SOC on the proof.*

This folder is the **single source for AegisAgent product documentation**. It renders on GitHub today; it is structured so it can later be published to a docs website (see [Publishing](#publishing)) without moving files.

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

---

## 🏗 Architecture & Security
*Technical reference.*

| Doc | What it covers |
|---|---|
| [Technical Design](AegisAgent_Technical_Design.md) | Gateway, SDKs, the two-plane architecture, data model, APIs |
| [Agent Workflow](AegisAgent_Agent_Workflow.md) | The seven workflows: authorization, approval integrity, audit, SOC |
| [Threat Model](AegisAgent_Threat_Model.md) | T-A approval manipulation · T-B confused deputy · T-C evidence tampering · T-D attacks on the SOC |
| [Operational Design](AegisAgent_Operational_Design.md) | Deployment, SLOs, fail-closed behavior, canonicalization & receipt-chain ops |

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
- [dashboard-mock.html](dashboard-mock.html) — static SOC Console mock (overview + provable incident timeline).

---

## Reading order (new to AegisAgent)
1. [Integration & Connectivity](AegisAgent_Integration_Connectivity.md) — how it attaches and enforces
2. [Agent SOC Design](AegisAgent_Agent_SOC_Design.md) — what it monitors
3. [Technical Design](AegisAgent_Technical_Design.md) — how it's built
4. [Action Receipt Spec](action-receipt-spec.md) — the evidence
5. [Gap Reassessment](AegisAgent_Gap_Reassessment_2026-06.md) — *why* it's shaped this way (internal)

---

## Publishing

**Now (GitHub):** this folder is the docs home — every doc is plain Markdown and renders on GitHub. Browsing to `docs/` shows this index.

**Later (website):** point a static-site generator at this folder — the section headings above become the site nav:
- **MkDocs + Material** (lightest: a `mkdocs.yml` listing the Product + Architecture docs), or
- **Docusaurus** (richer: versioned docs, search, blog).

When you publish, include **📖 Product Documentation** + **🏗 Architecture & Security**, and **exclude 🧭 Strategy & PM** (those are internal). No files need to move — publishing is just a nav config over this folder.
