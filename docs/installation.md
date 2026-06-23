# Installation

AegisAgent is self-hostable and runs as a single Rust gateway plus a language SDK. This page gets you
from zero to a verified protected action.

## Requirements

- **Rust** (stable) for the gateway
- **Python 3.8+** for the reference SDK and demos
- *(optional)* **Docker + Docker Compose** for the local stack

## Option A — zero-setup demo (no gateway needed)

The fastest way to see approval integrity working end-to-end:

```bash
python3 -m pip install -e sdk-python/
python3 examples/integrity_demo.py
```

This runs the frozen-action approval + fail-closed-on-swap flow entirely in-process.

## Option B — run the gateway

```bash
# build & test
cargo check  --manifest-path gateway/Cargo.toml
cargo test   --manifest-path gateway/Cargo.toml

# run (binds 127.0.0.1:8080)
CEDAR_POLICY_PATH=policies.cedar cargo run --manifest-path gateway/Cargo.toml

# health check
curl -s http://127.0.0.1:8080/health
```

Install the SDK and point it at the gateway:

```bash
python3 -m pip install -e sdk-python/
python3 -m unittest discover -s sdk-python/tests   # 25/25
```

## Option C — local stack (Docker)

```bash
docker compose up --build
bash scripts/seed-demo.sh
python3 examples/github-attack-demo.py
```

This brings up the gateway with seeded agents/tools and runs the malicious-GitHub-issue attack demo
(untrusted-provenance deny → approval → fail-closed-on-swap → verifiable receipt).

## Verify a receipt

Every protected action emits a hash-chained receipt. Verify a receipts file independently:

```bash
aegis-verify-receipts <receipts.json>
# or:  python3 -m aegisagent.verify_receipts <receipts.json>
```

## Bind interface

For development and testing the gateway binds the loopback interface (`127.0.0.1`). For production,
front it with TLS and expose it on a controlled endpoint your agents can reach (see
[Integration & connectivity](AegisAgent_Integration_Connectivity.md) §4 for network and auth).

## Next steps

- **[Connect your first agent](AegisAgent_Integration_Connectivity.md)** — inline SDK, proxy, or agentless.
- Write policies — the deterministic gates live in `policies.cedar`.
- Read the [Operational design](AegisAgent_Operational_Design.md) for SLOs and fail-closed behavior.
- Ready for production? See the **[Deployment guide](deployment-guide.md)** for Docker Compose, Kubernetes (Helm), bare metal, the full environment variable reference, and capacity planning.
