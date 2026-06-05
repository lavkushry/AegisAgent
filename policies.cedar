// AegisAgent default policy pack — anti-confused-deputy trust-provenance gate.
//
// Cedar is fail-closed by default: when no `permit` matches, the decision is
// Deny; any matching `forbid` overrides every `permit`. We exploit both: the
// deny-block leads, and only narrowly-scoped permits open the gate.
//
// DETERMINISTIC TRUST-PROVENANCE GATE (the differentiator)
// --------------------------------------------------------
// Authorization for a MUTATING action is gated on the *source trust level* of
// the content that triggered it (context.trust_level), NOT on a text/risk
// score. This defeats the confused-deputy / indirect-prompt-injection class
// (e.g. the Invariant Labs GitHub-MCP attack, where a malicious *public* issue
// hijacks an agent into a privileged write). Classifiers may only TIGHTEN a
// label (e.g. -> malicious_suspected), never loosen it.
//
// Decision per source trust level for a mutating action (mutates_state == true):
//   trusted_internal_signed    -> permit          (rule "trusted-internal-mutation")
//   trusted_internal_unsigned  -> permit          (rule "trusted-internal-mutation")
//   semi_trusted_customer      -> require_approval (rule "customer-mutation-approval")
//   untrusted_external         -> DENY             (rule "untrusted-mutation-forbid", first)
//   malicious_suspected        -> DENY             (rule "untrusted-mutation-forbid", first)
//   unknown                    -> DENY             (rule "untrusted-mutation-forbid", first)
// Non-mutating (read-only) actions are always permitted regardless of source.

// === FORBID RULES FIRST (highest priority; abort on known-unsafe patterns) ===

// Rule "untrusted-mutation-forbid": untrusted, suspected-malicious, OR
// unclassified (unknown) context can NEVER directly trigger a mutating action.
// `unknown` is denied — not merely paused — because provenance is fail-closed:
// an unlabelled ingress channel must not be trusted to drive a state change.
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

// === PERMIT RULES ===

// Allow read-only/non-mutating actions (a forbid above still wins if one fires,
// but none target non-mutating calls).
permit (
    principal,
    action,
    resource
)
when {
    context.mutates_state == false
};

// Permit mutating actions ONLY when the triggering context is trusted-internal
// (signed or unsigned). This is the sole path by which a mutation auto-allows.
permit (
    principal,
    action == Action::"tool_call",
    resource
)
when {
    context.mutates_state == true &&
    (
        context.trust_level == "trusted_internal_signed" ||
        context.trust_level == "trusted_internal_unsigned"
    )
};

// Production GitHub merges to main require human approval (regardless of trust).
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

// Customer-originated context can pause mutating actions for human review.
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
