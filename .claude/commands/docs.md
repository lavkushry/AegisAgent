---
description: Build, preview, or publish the MkDocs documentation site.
allowed-tools: Bash, Read, Edit
---

For the AegisAgent docs site (MkDocs Material → GitHub Pages):

- **Preview:** `pip install -r requirements-docs.txt && mkdocs serve` (http://127.0.0.1:8000).
- **Build check:** `mkdocs build` — warnings about links to *excluded* strategy docs are expected and fine.
- **Publish:** push to `main` touching `docs/**` or `mkdocs.yml` → the **Docs** workflow runs
  `mkdocs gh-deploy` → `gh-pages` → https://lavkushry.github.io/AegisAgent/.

**Rules:** keep strategy/PM docs in `exclude_docs` (never publish them); use GitHub blob URLs for
source-file links (`../` paths 404 on the site). Pages serves from `gh-pages` **/** (not `/docs`).
