# AegisAgent AI Developer Rules, Context & Harness Walkthrough

This walkthrough documents the refined AI developer context files, the new workspace rules files, and the installation/harness script configured in the repository.

---

## Refined Components

### 1. Refined AI Context files
- **[CLAUDE.md](file:///home/ems/AegisAgent/CLAUDE.md):** Added coding standards for **Multi-Tenant Isolation** (binding `tenant_id` on all database operations) and **OpenTelemetry Instrumentation** (using Rust `tracing` and propagating traceparent context). Included context harness commands.
- **[AGENTS.md](file:///home/ems/AegisAgent/AGENTS.md):** Aligned scopes to include `/mcp-gateway-lite` and `/policy-templates`. Assigned ownership of tenant partitioning and context trust labeling to active agent roles.
- **skills/ runbooks:**
  - [skills/security_scan.md](file:///home/ems/AegisAgent/skills/security_scan.md): Added Multi-Tenant Data Isolation Audit section (filtering database operations by `tenant_id`, testing cross-tenant queries).
  - [skills/cedar_policy_authoring.md](file:///home/ems/AegisAgent/skills/cedar_policy_authoring.md): Added guides and policies for Context Trust Labeling (`untrusted_external`, `trusted_internal`, etc.) and MCP Tool Hashing/Drift Check.
  - [skills/database_migration.md](file:///home/ems/AegisAgent/skills/database_migration.md): Added indexing guidelines for the `tenant_id` column to ensure sub-millisecond query performance.

### 2. Created Rules Harness Script (`scripts/setup_agent_harness.sh`)
An automation script (`scripts/setup_agent_harness.sh`) that dynamically configures workspace rules depending on active development requirements (ECC-style selective profile loading).
- **Commands:**
  - `bash scripts/setup_agent_harness.sh --profile <architect|developer|auditor|ops>`: Configures context-targeted rules inside the `.claude/rules/` folder and updates root `.cursorrules`/`.clauderules`.
  - `bash scripts/setup_agent_harness.sh --all`: Installs all personas.
  - `bash scripts/setup_agent_harness.sh --clean`: Clears generated rules in `.claude/rules/` and resets root configurations.

### 3. Created Rules Files
- **[.cursorrules](file:///home/ems/AegisAgent/.cursorrules):** Automatically updated by the harness script to prompt developer agents to load relevant active profiles and style guidelines.
- **[.clauderules](file:///home/ems/AegisAgent/.clauderules):** Keeps Claude Code aligned with active profile boundaries.

---

## Workspace Layout
```text
AegisAgent/
├── .claude/
│   └── rules/             # Path-scoped & active profile rules (harness-generated)
│       ├── architect.md
│       ├── developer.md
│       ├── auditor.md
│       ├── ops.md
│       ├── database_migration.md
│       ├── sdk_testing.md
│       ├── security_scan.md
│       └── cedar_policy_authoring.md
├── .clauderules          # Claude Code active rules file
├── .cursorrules           # Cursor/Codex active rules file
├── CLAUDE.md              # Global build/test commands & style guidelines
├── AGENTS.md              # Developer AI persona mapping and scopes
├── scripts/
│   └── setup_agent_harness.sh # ECC-style rules harness script
├── skills/                # Base developer runbooks
│   ├── security_scan.md
│   ├── cedar_policy_authoring.md
│   ├── database_migration.md
│   └── sdk_testing.md
├── docs/                  # System design, PRD, operational specs
└── README.md
```

---

## Verification Performed
- Made the script executable and ran `bash scripts/setup_agent_harness.sh --all` to pre-initialize the rule assets.
- Ran `git status` to verify all generated folders and configs are correctly structured within the `/home/ems/AegisAgent` workspace.
