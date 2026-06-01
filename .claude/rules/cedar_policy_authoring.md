# AI Skill: Cedar Policy Authoring & Validation (`skills/cedar_policy_authoring.md`)

This skill outlines how to write, modify, and test policies using AWS Cedar within the AegisAgent gateway, incorporating context trust labeling and MCP tool manifest verification.

---

## 1. Cedar Policy Syntax and Structure

Cedar policies define authorization rules based on a `permit` or `forbid` structure. 

### Key Entities:
- **Principal:** The agent requesting action (e.g., `Agent::"agent_uuid"`).
- **Action:** The action being requested (e.g., `Action::"tool_call"`).
- **Resource:** The target tool/action (e.g., `ToolAction::"github_merge"`).
- **Context:** Dynamic environment details (e.g., `context.mutates_state`, `context.branch`, `context.trust_level`, `context.manifest_hash`).

---

## 2. Context Trust Level Modeling

To mitigate indirect prompt injection vulnerabilities (where untrusted inputs hijack tool execution), AegisAgent supports dynamic context trust labeling. Policies must enforce stricter validation on actions following untrusted context.

### Context Labels:
- `trusted_internal` (e.g., trigger from organization admin)
- `semi_trusted` (e.g., issue or comment from repository member)
- `untrusted_external` (e.g., issue or comment from public/external contributor)
- `suspicious` (e.g., input flagged by security heuristic)

### Example Policy enforcing trust-level gates:

```cedar
// Permit mutating actions ONLY when context is trusted or semi-trusted.
permit (
  principal,
  action == Action::"tool_call",
  resource
)
when {
  context.mutates_state == true &&
  (context.trust_level == "trusted_internal" || context.trust_level == "semi_trusted")
};

// Require approval for any write/mutate action following untrusted context.
@decision("require_approval")
permit (
  principal,
  action == Action::"tool_call",
  resource
)
when {
  context.mutates_state == true &&
  (context.trust_level == "untrusted_external" || context.trust_level == "suspicious")
};
```

---

## 3. MCP Tool Manifest Hashing and Drift Check

To prevent agents from calling unregistered, modified, or hijacked MCP tools, policies can validate the manifest hash of the MCP server during the authorization cycle.

### Example Policy:

```cedar
// Allow MCP tool execution only if the tool manifest matches the approved pinned hash.
permit (
  principal,
  action == Action::"tool_call",
  resource
)
when {
  resource.type == "mcp_tool" &&
  context.manifest_hash == "sha256:d89cf8b982103445..." // Pinned manifest hash
};

// Require approval or deny if there is manifest drift (hash mismatch)
@decision("require_approval")
permit (
  principal,
  action == Action::"tool_call",
  resource
)
when {
  resource.type == "mcp_tool" &&
  context.manifest_hash != "sha256:d89cf8b982103445..." // Manifest drift detected!
};
```

---

## 4. Annotating Policies for Approvals

In AWS Cedar, policy evaluations natively return a binary `Allow` or `Deny` decision. AegisAgent introduces a third state, **`require_approval`**, by using Cedar Rule Annotations. rules requiring human-in-the-loop validation carry the `@decision("require_approval")` annotation.

---

## 5. Testing Policy Evaluation in Rust

Policies should be verified via unit tests inside the Rust gateway (`gateway/src/policy.rs`).

### Example Integration Test:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_untrusted_context_escalation() {
        let engine = PolicyEngine::init("policies.cedar").await.unwrap();
        let request = AuthRequest {
            principal: "Agent::\"test_agent\"".to_string(),
            tool: "github".to_string(),
            action: "merge_pr".to_string(),
            mutates_state: true,
            context: serde_json::json!({
                "trust_level": "untrusted_external",
                "mutates_state": true
            }),
        };
        let result = engine.authorize(request).await.unwrap();
        assert_eq!(result.decision, "require_approval");
    }
}
```

---

## 6. Runbook for Modifying Policies
1. **Edit `gateway/policies.cedar`:** Add or adjust rules according to authorization needs.
2. **Add matching unit test cases:** Write target assertions in `gateway/src/policy.rs` to verify correct evaluations.
3. **Execute test suite:** Run tests to verify rules compile and evaluate correctly:
   ```bash
   cargo test --manifest-path gateway/Cargo.toml
   ```
