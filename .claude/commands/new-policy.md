---
description: Add or modify a Cedar authorization policy with TDD (RED → GREEN) — a failing test in policy.rs first, then edit policies.cedar.
allowed-tools: Bash, Read, Edit, Write
---

Change authorization the TDD way:

1. **RED:** add a failing test in `gateway/src/policy.rs` asserting the decision
   (`allow` / `deny` / `require_approval`) for the new case. Run
   `cargo test --manifest-path gateway/Cargo.toml` and confirm it fails for the right reason.
2. **GREEN:** edit `gateway/policies.cedar` (and keep root `policies.cedar` ≡ it). Place `forbid` rules
   first; use `@decision("require_approval")` + `@approver_group(...)` annotations for the approval state.
3. **Verify:** `cargo test` passes; `cargo fmt -- --check` and `cargo clippy -- -D warnings` clean.

**Invariants:** provenance is deterministic (classifiers only tighten); a mutating action +
`untrusted_external` / `malicious_suspected` / `unknown` → **deny**. See `.claude/rules/cedar_policy_authoring.md`.
