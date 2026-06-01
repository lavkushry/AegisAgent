# AegisAgent AI Developer Harness & .claude/ Workspace Structure Plan

This implementation plan details the addition of a comprehensive **`.claude/` workspace structure** (modeled after the `affaan-m/ECC` architecture) that serves as the central control plane for Claude Code, Cursor, and Codex, with the harness script managing the lifecycles and selective profiling.

---

## User Review Required

> [!IMPORTANT]
> **Workspace Restructuring (.claude/PRPs):**
> - All agent planning documents (PRD, implementation plans, tasks, and walkthroughs) are structured under `.claude/PRPs/` inside subdirectories (`prds/`, `plans/`, `tasks/`, `reports/`) to follow the standard agentic engineering layout.
> - The harness script (`scripts/setup_agent_harness.sh`) is updated to automate the creation of these directories and copy files dynamically.

---

## Proposed Changes

### 1. Refined .claude/ Directory Architecture
We will set up the following directory structure:
- **`.claude/settings.json`**: Project-level configurations (e.g. max thinking tokens, preferred models, and default permissions).
- **`.claude/PRPs/prds/`**: Holds Product Requirements Documents.
- **`.claude/PRPs/plans/`**: Holds Implementation Plans.
- **`.claude/PRPs/tasks/`**: Holds Task lists.
- **`.claude/PRPs/reports/`**: Holds walkthroughs and verification reports.
- **`.claude/rules/`**: Modular rules for profiles and domains.

### 2. Update the Harness Script (`scripts/setup_agent_harness.sh`)
Refactor the shell script to:
- Generate `.claude/settings.json` with safe defaults:
  ```json
  {
    "MAX_THINKING_TOKENS": 4096,
    "CLAUDE_CODE_SUBAGENT_MODEL": "claude-3-5-sonnet"
  }
  ```
- Initialize `.claude/PRPs/` and subfolders: `prds/`, `plans/`, `tasks/`, `reports/`.
- Copy relevant workspace documentation into the PRP folders:
  - Copy `docs/AegisAgent_PRD.md` to `.claude/PRPs/prds/AegisAgent_PRD.md`.
  - Copy current planning artifacts (plan, task, walkthrough) from the brain directory or workspace root to their respective `.claude/PRPs/` subdirectories.

### 3. Create Rules Files (.cursorrules & .clauderules)
- Reference the active profile and standard path-scoped directory mappings.

---

## Verification Plan

### Manual Verification
- Run `bash scripts/setup_agent_harness.sh --all` and verify the `.claude/` directory is created with settings.json, the PRPs subfolders, and all relevant files mapped.
- Check that `git status` shows files correctly.
