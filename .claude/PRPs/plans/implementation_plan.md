# Implementation Plan: Integrate TDD Workflow, Token Budget Advisor, and Security Scan Refinements

This plan outlines the integration of three specialized developer skill runbooks (modeled after the `affaan-m/ECC` framework) into the AegisAgent workspace:
1. **Token Budget Advisor** (`skills/token_budget_advisor.md`): Formulates complexity assessments, token cost estimations, and chunking guidelines.
2. **TDD Workflow** (`skills/tdd_workflow.md`): Implements Red-Green-Refactor cycles and coverage standards.
3. **Security Scan Refinement** (`skills/security_scan.md`): Enhances existing security audits with AgentShield/fail-closed controls.

---

## User Review Required

> [!IMPORTANT]
> **Enforced TDD Cycle & Coverage:**
> - Enforcing Red-Green-Refactor will mandate that all future implementations of Rust Axum handlers, SQLx database operations, and Python SDK decorators must begin with writing a failing unit test first.
> - Git commit checkpoints will be recommended after each state transition (Red, Green, Refactor).
> - Target test coverage is set at 80%+.

---

## Open Questions

- None at this moment.

---

## Proposed Changes

### Developer Skills

#### [NEW] [token_budget_advisor.md](file:///home/ems/AegisAgent/skills/token_budget_advisor.md)
Create a runbook detailing:
- Assessment of task complexity (Prose, Code, SQL, logs).
- Estimation rules for input/output tokens.
- Context chunking rules (e.g. splitting database migration files or logs analysis into smaller tasks).
- Preferred response depth choices (Essential, Moderate, Detailed, Exhaustive).

#### [NEW] [tdd_workflow.md](file:///home/ems/AegisAgent/skills/tdd_workflow.md)
Create a runbook detailing:
- The RED-GREEN-REFACTOR cycle rules.
- Test coverage requirements (80%+ target).
- Mandating failing test cases for Rust (`cargo test`) and Python (`unittest`).
- Commit messages / checkpoint rules for TDD phases.

#### [MODIFY] [security_scan.md](file:///home/ems/AegisAgent/skills/security_scan.md)
Enhance with additional audit checks:
- Verify fail-closed defaults for all resource evaluations.
- Signature checking verification.
- Audit for context propagation risks and token leaks in diagnostics logs.

---

### Agent Harness Configuration

#### [MODIFY] [setup_agent_harness.sh](file:///home/ems/AegisAgent/scripts/setup_agent_harness.sh)
- Add `token_budget_advisor.md` and `tdd_workflow.md` to `copy_common_skills` to deploy them to `.claude/rules/`.
- Associate them with the `developer` and `auditor` profiles.

---

## Verification Plan

### Manual Verification
- Execute `bash scripts/setup_agent_harness.sh --all` and verify that the files are properly generated/copied under `.claude/rules/`.
- Run `git status` to ensure everything is staged correctly.
