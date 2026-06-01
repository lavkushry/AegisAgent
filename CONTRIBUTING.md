# Contributing to AegisAgent

Thanks for helping improve AegisAgent.

## Local Development

```bash
cargo test --manifest-path gateway/Cargo.toml
python3 -m unittest discover -s sdk-python/tests
```

Optional local demo:

```bash
docker compose up --build
bash scripts/seed-demo.sh
python3 examples/github-attack-demo.py
```

## Rust Gateway Checks

```bash
cargo fmt --manifest-path gateway/Cargo.toml -- --check
cargo clippy --manifest-path gateway/Cargo.toml -- -D warnings
cargo test --manifest-path gateway/Cargo.toml
```

## Python SDK Checks

```bash
python3 -m pip install -e sdk-python
python3 -m unittest discover -s sdk-python/tests
```

## Policy Contributions

- Keep Cedar policies fail-closed.
- Avoid broad catch-all permit rules.
- Include tests for allow, deny, and require_approval paths.
- Update `policies.cedar` and `gateway/policies.cedar` together when starter rules change.

## Security and Multi-Tenant Rules

- Every SQL query must use parameter binding.
- Tenant-owned data must bind/filter by `tenant_id`.
- Do not hardcode secrets or tokens.
- Do not weaken approval action-hash checks.

## Good First Issues

Good first issues should be labeled `good first issue` and include:

- Clear reproduction or implementation steps.
- Expected tests to run.
- Files likely to change.
