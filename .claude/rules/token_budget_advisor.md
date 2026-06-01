# AI Skill: Token Budget Advisor (`skills/token_budget_advisor.md`)

This skill defines the methodology for proactively managing context window consumption, estimating prompt token costs, and dynamically determining the response depth for AegisAgent development tasks.

---

## 1. Complexity Assessment Matrix

Before starting any multi-step task (e.g., SQL migration, Rust Axum endpoint implementation, or Cedar policy auditing), the agent must assess complexity and estimate the token budget.

| Task Level | Files to Read/Modify | Context Size | Est. Tokens | Action Plan |
| :--- | :--- | :--- | :--- | :--- |
| **Simple** | 1-2 files | < 10KB | < 5k | Single-turn response, direct execution. |
| **Medium** | 3-5 files | 10KB - 50KB | 5k - 20k | Break into explicit sub-tasks. Review code imports. |
| **Complex** | 6-10 files | 50KB - 150KB | 20k - 60k | Apply implementation planning mode. Chunk changes files. |
| **Extreme** | > 10 files | > 150KB | > 60k | Split project into separate phases. Use subagents or persistent terminals. |

---

## 2. Token Budgeting & Estimation Rules

When interacting with codebases, use these heuristics to calculate context window usage:
* **Prose/Markdown:** ~1.3 tokens per word.
* **Source Code (Rust/Python):** ~4.5 tokens per line (including indentation and comments).
* **Terminal Output/Logs:** ~3.0 tokens per line (logs can be dense).
* **Database Schema/JSON:** ~2.5 tokens per line.

> [!WARNING]
> **Context Bloat Prevention:**
> Do not use `view_file` to read files larger than 100 lines completely unless it is a critical entry point. Prefer grep searches first, or read line slices (e.g., `StartLine` and `EndLine` parameters).

---

## 3. Response Depth Selection

The agent should offer the user or subagents four distinct execution depths depending on the task:

1. **Essential (< 500 output tokens):**
   - Direct fix, no explanations or code reviews.
   - Ideal for syntax errors, formatting, and single line changes.
2. **Moderate (500 - 1500 output tokens):**
   - Code change with brief inline documentation.
   - Standard mode for simple handler additions or basic Cedar policies.
3. **Detailed (1500 - 3000 output tokens):**
   - Full code implementation, unit tests, and brief design summaries.
   - Recommended for database migrations and API route bindings.
4. **Exhaustive (> 3000 output tokens):**
   - In-depth design plan, multiple implementation options, full unit and integration tests, threat models, and security audit reports.
   - Mandatory for core security gateway changes, new crypto features, or changes to context validation logic.

---

## 4. Context Chunking & Extraction Strategies

If the task is determined to be **Complex** or **Extreme**:
- **Chunking code changes:** Implement changes incrementally. For example, implement database schemas and migrations first, write the failing tests next, and finally implement the handlers.
- **Log analysis chunking:** When investigating test failures or debug outputs, do not dump the whole trace. Grep for `ERROR`, `FAIL`, or `panicked` first to extract specific contexts.
- **Token Recovery:** Run `setup_agent_harness.sh --clean` or reset the profile periodically if rules files get too large.
