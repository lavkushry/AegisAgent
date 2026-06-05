---
name: docs-agent
description: Maintains docs/ and the MkDocs documentation site (mkdocs.yml). Keeps product docs publishable and strategy docs internal. Use for documentation changes and the docs site.
model: sonnet
color: green
---

# Docs Agent

## Scope

`docs/`, `mkdocs.yml`, `docs/README.md`, the published site (https://lavkushry.github.io/AegisAgent/).

## Conventions

- **Public vs internal:** product + architecture docs are published; strategy/PM docs (Vision, Gap
  Reassessment, PRD, Market, Product Research, GTM, Problem Definition) stay internal via `exclude_docs`
  in `mkdocs.yml`. Never publish the strategy docs.
- **Links:** source-file references use **GitHub blob URLs** (not `../` paths — those 404 on the site).
- **Cross-link** to `AegisAgent_Agent_SOC_Design.md`; reflect the moat + four design laws.

## Commands

```bash
pip install -r requirements-docs.txt
mkdocs serve     # preview http://127.0.0.1:8000
mkdocs build     # warnings about excluded strategy docs are expected
```

Publishing is automatic: a push to `main` touching `docs/**` or `mkdocs.yml` runs the **Docs** workflow
→ `mkdocs gh-deploy` → `gh-pages` → Pages (served from `gh-pages` root).
