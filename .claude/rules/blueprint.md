---
globs:
  - "docs/**/*"
  - "*.md"
---

# AI Skill: Architectural Planning & Blueprint Generation (`skills/blueprint.md`)

This skill defines the format and validation guidelines for creating step-by-step implementation blueprints when modifying the AegisAgent codebase.

---

## 1. Blueprint Generation Trigger

AI developer agents must generate an implementation plan (or blueprint) before writing code if the task involves:
- Adding database schema modifications or new migration files.
- Introducing new gateway HTTP endpoints or REST API contracts.
- Adjusting Cedar authorization policies or custom rules annotations.
- Modifying SDK tool interception mechanics.

---

## 2. Blueprint Document Format

The blueprint should be structured as follows:

```markdown
# Title: [Feature / Modification Name]

## 1. Architectural Scope & Impact
- Mapped folders and dependencies.
- Data layer schemas and constraints.

## 2. Step-by-Step Execution Phases
- **Phase 1: Database Migration:** Details migrations and SQLx offline preparation steps.
- **Phase 2: Gateway Implementation:** Details Rust handler edits, model validations, and route mapping.
- **Phase 3: Policy Integration:** Details AWS Cedar rule adjustments.
- **Phase 4: Client SDK/Decorator Updates:** Details Python SDK decorator wrapper modifications.

## 3. Verification & Testing Targets
- Rust unit/integration test commands.
- Python unit test and mockup runs.

## 4. Security Audit Checklist
- Parameterization confirmation.
- Tenant-isolation checks.
- Fail-closed defaults check.
```

---

## 3. Blueprint Quality Check

Ensure the generated blueprint conforms to the following project-wide rules:
1. **No String SQL Formatting:** All database operations must be parameterized.
2. **Dependency-First Execution:** Always build migration scripts and database models *before* editing HTTP handlers or SDK wrappers.
3. **Traceability:** Instrument any new handler or client decorator with OpenTelemetry trace spans.
