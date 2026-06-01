// Allow all read-only actions
permit (
    principal,
    action,
    resource
)
when {
    context.mutates_state == false
};

// Require approval for merge pull request actions on main branch
@decision("require_approval")
@approver_group("platform-leads")
@reason("Production GitHub merges require approval")
permit (
    principal,
    action == Action::"tool_call",
    resource == ToolAction::"github_merge_pull_request"
)
when {
    context.resource_base_branch == "main"
};

// Require approval for mutating actions after semi_trusted_customer context
@decision("require_approval")
@approver_group("security-reviewers")
@reason("High-risk action after customer context")
permit (
    principal,
    action == Action::"tool_call",
    resource
)
when {
    context.mutates_state == true &&
    context.trust_level == "semi_trusted_customer"
};

// Forbid mutating actions after untrusted context or malicious suspected context
forbid (
    principal,
    action == Action::"tool_call",
    resource
)
when {
    context.mutates_state == true &&
    (context.trust_level == "untrusted_external" || context.trust_level == "malicious_suspected" || context.trust_level == "unknown")
};
