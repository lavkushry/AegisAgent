# AI Skill: Cedar Policy Authoring & Validation (`skills/cedar_policy_authoring.md`)

This skill outlines how to write, modify, and test policies using AWS Cedar within the AegisAgent gateway.

---

## 1. Cedar Policy Syntax and Structure

Cedar policies define authorization rules based on a `permit` or `forbid` structure. 

### Key Entities:
- **Principal:** The agent requesting action (e.g., `Agent::"agent_uuid"`).
- **Action:** The action being requested (e.g., `Action::"tool_call"`).
- **Resource:** The target tool/action (e.g., `ToolAction::"github_merge"`).
- **Context:** Dynamic environment details (e.g., `context.mutates_state`, `context.branch`, `context.args`).

---

## 2. Annotating Policies for Approvals

In AWS Cedar, policy evaluations natively return a binary `Allow` or `Deny` decision. AegisAgent introduces a third state, **`require_approval`**, by using Cedar Rule Annotations.

### How it Works:
1. When writing a permit policy that represents a sensitive action requiring human-in-the-loop validation, attach the `@decision("require_approval")` annotation to the rule.
2. In the Rust gateway, the policy engine evaluates the request. If the request is permitted, the engine checks the annotations of the rules that matched.
3. If any matching permit rule has `@decision("require_approval")`, the gateway changes the final authorization result from `Allow` to `RequireApproval` and triggers a pending approval state.

### Example Policy Bundle (`gateway/policies.cedar`):

```cedar
// 1. Read-only actions (no state mutation) are permitted instantly.
permit (
  principal,
  action == Action::"tool_call",
  resource
)
when {
  context.mutates_state == false
};

// 2. Committing directly to the 'main' branch of a repository requires human approval.
@decision("require_approval")
permit (
  principal,
  action == Action::"tool_call",
  resource
)
when {
  resource.tool_key == "github" &&
  resource.action_key == "commit" &&
  context.branch == "main"
};

// 3. Executing arbitrary commands requires human approval.
@decision("require_approval")
permit (
  principal,
  action == Action::"tool_call",
  resource
)
when {
  resource.tool_key == "terminal" &&
  resource.action_key == "execute"
};
```

---

## 3. Testing Policy Evaluation in Rust

Policies should be verified via unit tests inside the Rust gateway.

### Policy Test Outline:
Test cases are located in `gateway/src/policy.rs`. They load a mock policy store, initialize the Cedar evaluator, and test specific request contexts:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_readonly_allowed() {
        let engine = PolicyEngine::init("policies.cedar").await.unwrap();
        let request = AuthRequest {
            principal: "Agent::\"test_agent\"".to_string(),
            tool: "github".to_string(),
            action: "list_issues".to_string(),
            mutates_state: false,
            context: serde_json::json!({}),
        };
        let result = engine.authorize(request).await.unwrap();
        assert_eq!(result.decision, "allow");
    }

    #[tokio::test]
    async fn test_main_branch_requires_approval() {
        let engine = PolicyEngine::init("policies.cedar").await.unwrap();
        let request = AuthRequest {
            principal: "Agent::\"test_agent\"".to_string(),
            tool: "github".to_string(),
            action: "commit".to_string(),
            mutates_state: true,
            context: serde_json::json!({ "branch": "main" }),
        };
        let result = engine.authorize(request).await.unwrap();
        assert_eq!(result.decision, "require_approval");
    }
}
```

---

## 4. Runbook for Modifying Policies
1. **Edit `gateway/policies.cedar`:** Add or adjust rules according to authorization needs.
2. **Add matching unit test cases:** Write target assertions in `gateway/src/policy.rs` to verify correct evaluations (Allow / Deny / RequireApproval).
3. **Execute test suite:** Run tests to verify rules compile and evaluate correctly:
   ```bash
   cargo test --manifest-path gateway/Cargo.toml
   ```
