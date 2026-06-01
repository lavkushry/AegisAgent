# AegisAgent AI Developer Rules, Context & Harness Walkthrough

This walkthrough documents the refined AI developer context files, the new workspace rules files, and the installation/harness script configured in the repository.

---

## Refined Components

### 1. Refined AI Context files
- **[CLAUDE.md](file:///home/ems/AegisAgent/CLAUDE.md):** Added coding standards for **Multi-Tenant Isolation** (binding `tenant_id` on all database operations) and **OpenTelemetry Instrumentation** (using Rust `tracing` and propagating traceparent context). Included context harness commands, standard **API endpoints**, and **reliability SLO targets** from the PRD/Operational design.
- **[AGENTS.md](file:///home/ems/AegisAgent/AGENTS.md):** Aligned scopes to include `/mcp-gateway-lite` and `/policy-templates`. Assigned ownership of tenant partitioning and context trust labeling to active agent roles.
- **skills/ runbooks:**
  - [skills/security_scan.md](file:///home/ems/AegisAgent/skills/security_scan.md): Added Multi-Tenant Data Isolation Audit section (filtering database operations by `tenant_id`), a comprehensive **Secure Defaults (Fail-Closed) checklist** for validating unknown endpoints, actions, and token callbacks, and the **AgentShield Configuration Security Audit** rules.
  - [skills/cedar_policy_authoring.md](file:///home/ems/AegisAgent/skills/cedar_policy_authoring.md): Added guides and policies for **six specific Context Trust Levels** (`trusted_internal_signed`, `trusted_internal_unsigned`, `semi_trusted_customer`, `untrusted_external`, `malicious_suspected`, `unknown`) and MCP Tool Hashing/Drift Check.
  - [skills/database_migration.md](file:///home/ems/AegisAgent/skills/database_migration.md): Added indexing guidelines for the `tenant_id` column to ensure sub-millisecond query performance.
  - [skills/skill_comply.md](file:///home/ems/AegisAgent/skills/skill_comply.md): Added **Automated Compliance Measurement** runbook to guide agents in self-auditing code changes (CWE checks, formatting, telemetry, task/walkthrough syncing).
  - [skills/rust_standards.md](file:///home/ems/AegisAgent/skills/rust_standards.md): Added Rust standard coding rules (Tokio async time-outs, custom strong error propagation, Serde derivations, clippy checks).
  - [skills/python_standards.md](file:///home/ems/AegisAgent/skills/python_standards.md): Added Python SDK standards (PEP 8, type hints, custom subclasses exceptions, unittest patch mock verifications).
  - [skills/axum_patterns.md](file:///home/ems/AegisAgent/skills/axum_patterns.md): Added Axum API patterns (state injection, request/json extraction, custom IntoResponse application error mappings).
  - [skills/sqlite_usage.md](file:///home/ems/AegisAgent/skills/sqlite_usage.md): Added SQLite SQLx usage guidelines (WAL mode pool tuning, transactions lifecycle scopes, compile-timeChecked queries).
  - [skills/prompt_optimizer.md](file:///home/ems/AegisAgent/skills/prompt_optimizer.md): Added **Prompt & Rule Optimizer** skill to help agents write concise Cedar rules, format payload requests, and keep token context sizes optimized.
  - [skills/project_flow_ops.md](file:///home/ems/AegisAgent/skills/project_flow_ops.md): Added **Project Flow & Release Operations** skill covering local setup baselines, test running pipelines, pre-release offline compilation checks, and Helm lints.
  - **[NEW] [skills/token_budget_advisor.md](file:///home/ems/AegisAgent/skills/token_budget_advisor.md):** Added **Token Budget Advisor** skill to proactively evaluate task complexity (Simple, Medium, Complex, Extreme), estimate token counts, prevent context window bloat, and select response depth.
  - **[NEW] [skills/tdd_workflow.md](file:///home/ems/AegisAgent/skills/tdd_workflow.md):** Added **TDD Workflow** runbook enforcing the Red-Green-Refactor cycle, 80%+ code coverage, framework testing commands, and git checkpoints.

### 2. Created/Updated Rules Harness Script (`scripts/setup_agent_harness.sh`)
An automation script (`scripts/setup_agent_harness.sh`) that dynamically configures workspace rules depending on active development requirements (ECC-style selective profile loading).
- **Updates:** Copied new skills (`token_budget_advisor.md`, `tdd_workflow.md`) as common skills, and referenced them inside `developer` and `auditor` profiles.
- **Commands:**
  - `bash scripts/setup_agent_harness.sh --profile <architect|developer|auditor|ops>`: Configures context-targeted rules inside the `.claude/rules/` folder and updates root `.cursorrules`/`.clauderules`.
  - `bash scripts/setup_agent_harness.sh --all`: Installs all pipelines.
  - `bash scripts/setup_agent_harness.sh --clean`: Clears generated rules in `.claude/rules/` and resets root configurations.

### 3. Created Rules Files
- **[.cursorrules](file:///home/ems/AegisAgent/.cursorrules):** Automatically updated by the harness script to prompt developer agents to load relevant active profiles and style guidelines.
- **[.clauderules](file:///home/ems/AegisAgent/.clauderules):** Keeps Claude Code aligned with active profile boundaries.

---

## Workspace Layout
```text
AegisAgent/
├── .claude/
│   ├── settings.json      # Max thinking tokens & project metadata (harness-generated)
│   ├── PRPs/              # Standard planning subdirectories (harness-generated)
│   │   ├── prds/          # Product Requirement Documents
│   │   ├── plans/         # Implementation plans
│   │   ├── tasks/         # Tasks
│   │   └── reports/       # Walkthroughs and reports
│   └── rules/             # Path-scoped & active profile rules (harness-generated)
│       ├── architect.md
│       ├── developer.md
│       ├── auditor.md
│       ├── ops.md
│       ├── database_migration.md
│       ├── sdk_testing.md
│       ├── security_scan.md
│       ├── cedar_policy_authoring.md
│       ├── context_keeper.md
│       ├── code_tour.md
│       ├── blueprint.md
│       ├── skill_comply.md
│       ├── rust_standards.md
│       ├── python_standards.md
│       ├── axum_patterns.md
│       ├── sqlite_usage.md
│       ├── prompt_optimizer.md
│       ├── project_flow_ops.md
│       ├── tdd_workflow.md
│       └── token_budget_advisor.md
├── .clauderules          # Claude Code active rules file
├── .cursorrules           # Cursor/Codex active rules file
├── CLAUDE.md              # Global build/test commands & style guidelines
├── AGENTS.md              # Developer AI persona mapping and scopes
├── scripts/
│   ├── setup_agent_harness.sh # ECC-style rules harness script
│   └── scan_project_plan.py   # Python-native plan scanner
├── skills/                # Base developer runbooks
│   ├── security_scan.md
│   ├── cedar_policy_authoring.md
│   ├── database_migration.md
│   ├── sdk_testing.md
│   ├── context_keeper.md
│   ├── code_tour.md
│   ├── blueprint.md
│   ├── skill_comply.md
│   ├── rust_standards.md
│   ├── python_standards.md
│   ├── axum_patterns.md
│   ├── sqlite_usage.md
│   ├── prompt_optimizer.md
│   ├── project_flow_ops.md
│   ├── tdd_workflow.md
│   └── token_budget_advisor.md
├── docs/                  # System design, PRD, operational specs
│   ├── AgentGuard_Product_Research.md
│   └── AegisAgent_PRD.md
└── README.md
```

---

## Verification Performed
- Ran `bash scripts/setup_agent_harness.sh --all` to copy all skills to `.claude/rules/` and compile the `.cursorrules` and `.clauderules` successfully.
- Verified file existence and contents of settings, rules, and compiled files.
