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
# One-shot: installs pre-commit (cargo fmt/clippy, black, gitleaks) and the Python SDK
make setup

# Python SDK
python3 -m pip install -e "sdk-python[dev]"
python3 -m unittest discover -s sdk-python/tests
python3 examples/integrity_demo.py            # no gateway needed

# Rust gateway (requires a Rust toolchain ≥ 1.88)
cargo test --workspace
cargo fmt -- --check
cargo clippy --workspace --all-targets -- -D warnings

# Optional full local stack
docker compose up --build
bash scripts/seed-demo.sh
python3 examples/github-attack-demo.py
```

## Branching and commits

- **Branch from `main`**, target PRs to `main`.
- **Branch naming**: use `feat/`, `fix/`, `docs/`, `perf/`, `test/`, `refactor/`, `chore/` prefixes.
  Examples: `feat/receipt-signing`, `fix/approval-expiry-race`, `docs/api-reference`.
- **Commit messages**: use [Conventional Commits](https://www.conventionalcommits.org/).
  CI will reject PR titles that don't follow the convention.

  ```
  feat(gateway): add Ed25519 receipt signing
  fix(sdk-python): handle empty parameters in canonicalization
  docs: update API versioning guide
  perf(gateway): parallelize authorize DB reads with tokio::join!
  test: add cross-tenant isolation stress test
  chore(deps): bump sqlx to 0.8.6
  ```

## Before you open a PR

Run `make check` (or everything CI checks individually, see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

- `cargo fmt -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`
- `python3 -m black --check sdk-python/ examples/`
- `python3 -m unittest discover -s sdk-python/tests`

The [pull request template](.github/PULL_REQUEST_TEMPLATE.md) has the full
checklist.

## The Four Design Laws

Every contribution to the gateway or SOC plane must obey these (full detail in
[`docs/AegisAgent_Agent_SOC_Design.md`](docs/AegisAgent_Agent_SOC_Design.md) §2)
— a PR that violates one will not be merged:

1. **Deterministic policy decides; scores never gate.** Cedar evaluates source
   trust level and `mutates_state`. `risk_score`, anomaly scores, and any
   prompt-injection score are advisory display metadata only — never the
   thing that allows or denies. A score is attacker-gameable; a deterministic
   provenance gate is not.
2. **The LLM investigates; it never decides, enforces, or reads instructions
   as instructions.** The only LLM in the system is the post-incident RCA
   narrator: sandboxed, no tool access, no path to an enforcement decision,
   and all evidence passed to it is treated as inert data, never as commands.
3. **The inline path is sacred; detection is asynchronous.** `POST
   /v1/authorize` has a <75ms budget. Collection, detection, correlation, and
   response must never sit in that path — the gateway emits an event
   (non-blocking) and the SOC consumes it out-of-band.
4. **Every moat primitive is preserved end-to-end.** Canonicalization stays
   byte-identical (`aegis-jcs-1`); approvals stay hash-bound and single-use;
   receipts stay hash-chained. New SOC features consume and surface these —
   they never weaken them.

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

## Architecture rules

All code changes must follow [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md):

- **Dependencies flow downward only** — `common` ← `api` ← `storage`/`policy` ← `soc` ← `src/`.
- **`src/` handlers are thin**: parse → service call → respond. No business logic.
- **Dual protocol**: every endpoint on both REST (Axum) and gRPC (tonic).
- **Protobuf is source of truth**: new API types → define in `lib/api/proto/*.proto` first.
- **All DB access** through the `StorageBackend` trait. Never use `SqlitePool` directly.
- All functions return `Result<T, AegisError>`.

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
- Keep `policies.cedar` and `src/policies.cedar` byte-identical.

## Good first issues

Issues labeled `good first issue` should include clear repro/implementation
steps, the tests to run, and the files likely to change.

## Release process

Releases are automated via [release-please](https://github.com/googleapis/release-please).
Merging conventional-commit PRs into `main` automatically updates the open
Release PR. When the maintainer merges that Release PR, a new version is tagged,
the CHANGELOG is updated, and Docker images are published. See
[`.github/workflows/release-please.yml`](.github/workflows/release-please.yml).
