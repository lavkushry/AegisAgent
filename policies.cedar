// AegisAgent default MVP policy pack
//
// Starter rule 1: deny-all baseline.
// Cedar is fail-closed by default: when no permit policy matches, the
// authorization decision is Deny. Keep this file free of broad catch-all
// permit rules unless they are explicitly constrained.

// Starter rule 2: allow read-only/non-mutating actions.
permit (
    principal,
    action,
    resource
)
when {
    context.mutates_state == false
};

// Starter rule 3: production GitHub merges to main require human approval.
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

// Starter rule 4: customer-originated context can pause mutating actions for review.
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

// Starter rule 5: untrusted or suspicious context cannot directly trigger mutations.
forbid (
    principal,
    action == Action::"tool_call",
    resource
)
when {
    context.mutates_state == true &&
    (
        context.trust_level == "untrusted_external" ||
        context.trust_level == "malicious_suspected" ||
        context.trust_level == "unknown"
    )
};
