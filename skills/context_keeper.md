# AI Skill: Context Keeper & Session State Management (`skills/context_keeper.md`)

This skill describes how AI developer agents maintain codebase context and project progress across multi-turn sessions using the `.claude/PRPs/` folder structure.

---

## 1. Context Retention Strategy (ECC-Style)

When starting a new session or resuming a task, the agent has limited memory of prior actions. To prevent context drift and avoid repeating work, the agent must check and update the Project Requirements and Plans (PRP) registry.

---

## 2. Directory Layout and Role

The `.claude/PRPs/` folder acts as the local persistent memory bank:
- `.claude/PRPs/prds/`: Stores the baseline product requirements.
- `.claude/PRPs/plans/`: Stores the active design plan (`implementation_plan.md`).
- `.claude/PRPs/tasks/`: Stores the active TODO list (`task.md`).
- `.claude/PRPs/reports/`: Stores the latest completion summaries (`walkthrough.md`).

---

## 3. Session Synchronization Runbook

### On Session Start:
1. **Locate PRPs:** Check if `.claude/PRPs/` exists.
2. **Read Active Task List:** Open `.claude/PRPs/tasks/task.md` to see what tasks are completed `[x]`, in progress `[/]`, or pending `[ ]`.
3. **Read Implementation Plan:** Read `.claude/PRPs/plans/implementation_plan.md` to understand system design boundaries (e.g. multi-tenant tables, secure defaults).

### During active development:
1. **Update Tasks:** As code changes are written, update `.claude/PRPs/tasks/task.md` by marking matching items as `[x]`.
2. **Document Findings:** If you discover unexpected bugs or stack limitations, add a notes section in the implementation plan.

### On Session End:
1. **Compile Walkthrough:** Create or update `.claude/PRPs/reports/walkthrough.md`. Summarize what files were modified, what tests were executed, and include verification results.
2. **Clean Temporary Files:** Remove any scratch or log files outside standard ignored directories.
