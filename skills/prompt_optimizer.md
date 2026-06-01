# AI Skill: Prompt & Rule Optimizer (`skills/prompt_optimizer.md`)

This skill provides developer agents with optimization guidelines for composing clean prompt payloads, standardizing tool-call contexts, and authoring concise AWS Cedar rules.

---

## 1. Prompt Structuring Guidelines

To prevent context bloat and ensure high-accuracy responses from the gateway, all tool-call request payloads sent by the SDK must follow a structured, minimal format.

### Guidelines:
- **Explicit Schema Binding:** Never send raw, unstructured text. Always partition tool calls into explicit fields: `tool`, `action`, `resource`, and `parameters`.
- **JSON Minimization:** Strip out redundant or unnecessary parameters (e.g. large file contents, binary data) before querying `/v1/authorize`. Only pass parameters that are directly used by the authorization policies.
- **Redaction by Default:** Redact passwords, personal access tokens, and secret keys in the client-side decorator prior to payload transmission.

---

## 2. Optimizing Cedar Policies

Cedar policy engines run in-process for speed. To keep evaluation under 75ms, policy statements must be written efficiently.

### Guidelines:
- **Forbid Rules First:** Place high-priority `forbid` rules at the top of the policy store to abort evaluations quickly on known-unsafe patterns.
- **Avoid Wildcard Matching:** Use specific action and resource matching (e.g. `action == Action::"merge"`) instead of broad matches where possible.
- **Keep Condition Clauses Shallow:** Minimize deep nested logic inside `when` condition blocks. Break complex rules into modular, single-condition statements.

---

## 3. Cedar Annotation Optimization

When marking rules for manual human approval, ensure the annotations are clear and actionable for the approver (e.g. on the dashboard or Slack).

### Guidelines:
- **Standardized Annotations:** Always use the standard `@decision("require_approval")` annotation.
- **Provide Actionable Reasons:** Use descriptive comments or secondary annotations (like `@approver_group("leads")`) to guide the approval engine on where to route the request:
  ```cedar
  @decision("require_approval")
  @approver_group("platform-leads")
  permit (
      principal,
      action == Action::"tool_call",
      resource
  )
  when {
      resource.tool_key == "github" &&
      resource.action_key == "merge"
  };
  ```
