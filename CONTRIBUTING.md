# Contributing to AegisAgent

Thanks for helping improve AegisAgent — the integrity layer for AI agent actions.
By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE), and you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## What we want

AegisAgent deliberately competes only on **integrity + provenance + verifiable
evidence**, not on the commodity gateway loop. The highest-value contributions
sharpen the two differentiators and the receipts:

1. **Approval integrity** — action-hash binding, expiry, single-use consumption.
2. **Deterministic trust-provenance gating** — the confused-deputy defense.
3. **Verifiable action receipts** — the hash-chained evidence trail.

See [`docs/AegisAgent_Gap_Reassessment_2026-06.md`](docs/AegisAgent_Gap_Reassessment_2026-06.md)
(the source of truth) and [`ROADMAP.md`](ROADMAP.md) before proposing large work.

## Development setup

```bash
# Python SDK
python3 -m pip install -e "sdk-python[dev]"
python3 -m unittest discover -s sdk-python/tests
python3 examples/integrity_demo.py            # no gateway needed

# Rust gateway (requires a Rust toolchain)
cargo test  --manifest-path gateway/Cargo.toml
cargo fmt   --manifest-path gateway/Cargo.toml -- --check
cargo clippy --manifest-path gateway/Cargo.toml -- -D warnings

# Optional full local stack
docker compose up --build
bash scripts/seed-demo.sh
python3 examples/github-attack-demo.py
```

## Before you open a PR

Everything CI checks, run locally first (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

- `cargo fmt … --check`, `cargo clippy … -D warnings`, `cargo test …`
- `python3 -m black --check sdk-python/ examples/`
- `python3 -m unittest discover -s sdk-python/tests`

The [pull request template](.github/PULL_REQUEST_TEMPLATE.md) has the full
checklist. Use [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).

## Critical invariants (do not weaken)

These guarantees are the product. A PR that weakens any of them will not be merged.

- **Canonicalization `aegis-jcs-1` MUST stay byte-identical across the SDK and
  the gateway** (keys sorted by Unicode code point, compact separators, raw
  UTF-8 / no `\uXXXX`, reject non-finite floats). It is locked by
  `tests/canonical_action_vectors.json` and `tests/receipt_chain_vectors.json`.
  **Never change hashing without bumping the scheme version and updating both
  corpora together** — a silent divergence breaks the fail-closed guarantee.
- **Fail closed:** unknown agent/tool/MCP server/MCP tool → deny; critical →
  deny; high-risk → require approval. The SDK refuses to execute on hash
  mismatch, expired approval, consumed/replayed approval, or an unreachable
  gateway for mutating/high-risk actions.
- **Approval integrity:** every approval binds to the original `action_hash`;
  edits re-hash and re-evaluate; approvals expire and are single-use.
- **Trust-provenance is deterministic:** classifiers may only *tighten* a label,
  never loosen it.

## Security and multi-tenant rules

- Every SQL query uses parameter binding (no `format!`/f-strings/concatenation).
- Tenant-owned data must bind/filter by `tenant_id`.
- Never hardcode secrets or tokens; keep secrets out of logs, traces, and
  receipts (store hashes, not payloads).
- No `.unwrap()`/`.expect()` in gateway production paths.
- Bind to `127.0.0.1` for dev/test.

Found a vulnerability? See [`SECURITY.md`](SECURITY.md) — report privately, do
not open a public issue.

## Policy contributions

- Keep Cedar policies fail-closed; avoid broad catch-all `permit` rules.
- Include tests for allow, deny, and `require_approval` paths.
- Keep `policies.cedar` and `gateway/policies.cedar` byte-identical.

## Good first issues

Issues labeled `good first issue` should include clear repro/implementation
steps, the tests to run, and the files likely to change.
