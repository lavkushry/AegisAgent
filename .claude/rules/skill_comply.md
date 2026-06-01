# AI Skill: Automated Compliance Measurement (`skills/skill_comply.md`)

This skill defines the self-audit and compliance verification checklist that AI developer agents must execute before completing a task.

---

## 1. Compliance Audit Procedure

To ensure the integrity, security, and quality of the AegisAgent codebase, the agent must run this compliance check.

---

## 2. Self-Compliance Checklist

### Security Compliance (CWE Checks)
- [ ] **SQL injection check (CWE-89):** Inspect all modified SQL queries. Ensure there are absolutely no string concatenations (`+`, `format!`, f-strings) of dynamic inputs.
- [ ] **Tenant Isolation (CWE-284):** Verify that every query targeting `tools`, `tool_actions`, `agents`, `decisions`, or `approvals` filters by `tenant_id`.
- [ ] **Fail-Closed default:** Confirm that any authorization or check logic defaults to denial/exception if inputs are null, empty, or unverified.
- [ ] **Local Interface Binding:** Ensure all TCP listener configurations in tests or dev code bind strictly to `127.0.0.1`.

### Code Quality & Standards
- [ ] **Rust gateway formatting:** Run `cargo fmt --manifest-path gateway/Cargo.toml -- --check` and verify it passes.
- [ ] **Python SDK formatting:** Run `black --check sdk-python/` and verify it passes.
- [ ] **Linter check:** Run `cargo clippy` and verify there are no compile-time warnings or clippy errors.

### Telemetry & Instrumentation
- [ ] **OTel spans:** Confirm that any new gateway HTTP handlers or core SQLite connection queries are instrumented with tracing spans.

### Documentation & Tracking
- [ ] **Task List:** Verify that `.claude/PRPs/tasks/task.md` has been updated and all finished items are checked `[x]`.
- [ ] **Walkthrough:** Confirm that `.claude/PRPs/reports/walkthrough.md` is updated with a description of changes and test verifications.
