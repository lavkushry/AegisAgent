---
description: Run the full AegisAgent verification — gateway tests, Python SDK, and the Go + TS canonicalizers — proving cross-language byte-parity and a green build.
allowed-tools: Bash, Read
---

Run these and report a concise pass/fail summary per component. The **cross-language canon parity is the
load-bearing invariant** — all four must reproduce `tests/canonical_action_vectors.json` +
`tests/receipt_chain_vectors.json` byte-for-byte.

1. **Gateway (Rust):** `cargo test --manifest-path gateway/Cargo.toml`
   (add `cargo fmt -- --check` and `cargo clippy -- -D warnings` if asked).
2. **Python SDK:** `python3 -m unittest discover -s sdk-python/tests`
3. **Go canonicalizer:** `go -C sdk-go test ./...`
4. **TS canonicalizer:** `node --test sdk-typescript/test/canon.test.ts`

If any canon test diverges, **STOP** — that breaks the fail-closed approval guarantee. Report exactly
which vector mismatched (the `got` vs `want` strings) before doing anything else.
