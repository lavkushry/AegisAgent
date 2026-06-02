<!-- Thanks for contributing to AegisAgent! -->

## Summary

<!-- What does this PR do and why? Link any related issue. -->

Closes #

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / cleanup
- [ ] Docs
- [ ] Security fix

## Checklist

- [ ] Tests added/updated; `cargo test --manifest-path gateway/Cargo.toml` and `python3 -m unittest discover -s sdk-python/tests` pass.
- [ ] `cargo fmt --manifest-path gateway/Cargo.toml -- --check` and `cargo clippy --manifest-path gateway/Cargo.toml -- -D warnings` pass.
- [ ] `python3 -m black --check sdk-python/ examples/` passes.
- [ ] No hardcoded secrets; secrets stay out of logs/receipts (hashes only).
- [ ] Tenant-owned queries bind/filter `tenant_id`; parameterized SQL only.

## Integrity invariants (do not weaken)

- [ ] If canonicalization/hashing changed, the scheme version was bumped **and** the SDK ↔ gateway byte-equality corpora were updated together.
- [ ] Fail-closed behavior preserved (unknown → deny; critical → deny; high-risk → approval; hash mismatch / expired / consumed approval → no execution).
- [ ] Trust-provenance changes only let classifiers *tighten* a label, never loosen it.

## Notes for reviewers

<!-- Anything that needs special attention. -->
