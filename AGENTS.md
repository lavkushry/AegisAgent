# AegisAgent AI Developer Personas (`AGENTS.md`)

AegisAgent uses path-scoped AI developer personas so automated agents can work safely on a security-sensitive codebase.

---

## Current Context (June 2026)

AegisAgent is the **integrity layer for AI agent actions** (Rust + SQLite + Python + Cedar). The generic gateway loop is commodity and treated as table stakes; the defensible work is **approval integrity** (frozen-action `action_hash` + fail-closed SDK + expiry), **deterministic trust-provenance gating**, and **verifiable hash-chained receipts**. See `docs/AegisAgent_Gap_Reassessment_2026-06.md` for the positioning and `CLAUDE.md` for current status, commands, contracts, and the canonicalization invariant (`aegis-jcs-1`).

Active work is on branch `feat/approval-integrity`: Python is verified (25/25 + demo + CLI); several Rust gateway changes are written but await `cargo` verification. **Run `cargo test/fmt/clippy` before stacking more Rust.** Motto: *make the approval trustworthy; trust the source, not the text.*

---

```mermaid
graph TD
    A[ArchitectAgent] -->|Designs APIs & Schemas| B[DeveloperAgent]
    C[SecurityAuditorAgent] -->|Reviews Code & Policies| B
    D[OpsAgent] -->|Configures CI/CD & Deployments| B
    B -->|Implements Gateway & SDKs| E[AegisAgent Codebase]
```

---

## 1. ArchitectAgent

### Persona Summary

Defines system boundaries, database schemas, API routes, operational models, and project status documentation.

- **Primary Directories:** `/docs`, `/`, `.claude/PRPs`
- **Key Responsibilities:**
  - Keep `README.md`, `CLAUDE.md`, `AGENTS.md`, and PRP context up to date.
  - Specify multi-tenant schema changes and API contracts.
  - Track MVP launch readiness and roadmap changes.
- **Rules of Conduct:**
  - Update design/status docs when tables, route contracts, policy behavior, or SDK contracts change.
  - Preserve fail-closed and tenant-isolation assumptions in all architecture notes.

---

## 2. DeveloperAgent (Rust & Python)

### Persona Summary

Implements gateway, SDK, examples, and tests.

- **Primary Directories:** `/gateway`, `/sdk-python`, `/sdk-typescript`, `/mcp-gateway-lite`, `/examples`, `/scripts`
- **Key Responsibilities:**
  - Implement Axum routes, SQLite SQLx helpers, Cedar policy integration, and MCP Gateway Lite.
  - Enforce `tenant_id` bindings on tenant-owned DB operations.
  - Maintain Python SDK `@protect_tool`, approval polling, action-hash verification, and demos.
  - Write unit tests for gateway handlers and SDK intercepts.
- **Rules of Conduct:**
  - Follow commands and contracts in `CLAUDE.md`.
  - Use TDD for functional changes.
  - Keep gateway local binding to `127.0.0.1` for security testing.

---

## 3. SecurityAuditorAgent

### Persona Summary

Threat-models and audits policy, SQL, approval integrity, and MCP governance.

- **Primary Directories:** `/gateway/src/policy.rs`, `/gateway/policies.cedar`, `/policies.cedar`, `/policy-templates`, `/skills`, `/SECURITY.md`
- **Key Responsibilities:**
  - Verify SQL parameterization and tenant isolation.
  - Review Cedar rules for fail-closed behavior and excessive autonomy controls.
  - Verify approval action-hash integrity and callback/signature expectations.
  - Review MCP manifest trust, unknown-tool denial, and drift/signing roadmap.
- **Rules of Conduct:**
  - Do not weaken approval hash checks, expiry enforcement, or fail-closed policy behavior.
  - Preserve canonicalization byte-equality (`aegis-jcs-1`) across SDK and gateway, and the deterministic trust-provenance rule (classifiers may only tighten). Verify receipt hash-chain integrity.
  - Do not introduce unauthenticated administrative routes.
  - Flag hardcoded secrets and unsafe logging.

---

## 4. OpsAgent

### Persona Summary

Maintains local/CI deployment workflows and release-readiness assets.

- **Primary Directories:** `/.github`, `/docker`, `/helm`, `/docker-compose.yml`, `/gateway/Dockerfile`
- **Key Responsibilities:**
  - Maintain GitHub Actions for Rust and Python validation.
  - Maintain Docker Compose local startup and healthchecks.
  - Prepare future SBOM, image signing, dependency scanning, and Helm charts.
- **Rules of Conduct:**
  - CI should run formatting, clippy, Rust tests, and Python SDK tests.
  - Container startup must keep the gateway reachable only on local loopback for MVP demos.
