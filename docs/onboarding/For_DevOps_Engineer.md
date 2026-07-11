# Onboarding: DevOps / Platform Engineer

**Goal:** run AegisAgent locally, in Docker, and on Kubernetes — with the fail-closed production posture intact.

> **Status:** Known-agent single-writer deployment is production-hardened. Multi-replica PostgreSQL and complete cage/sensor/egress/broker force paths remain Partial.

## Overview

Your job is to make the authorization boundary available without weakening it. You own safe listener exposure, identity and secrets, durable evidence storage, probes, metrics, backup/restore, rollout, rollback, and capacity limits.

## 1. Read first

[../deployment-guide.md](../deployment-guide.md) → [../production-hardening.md](../production-hardening.md) (config reference + checklist) → [../AegisAgent_Operational_Design.md](../AegisAgent_Operational_Design.md) (SLOs, ops model).

## 2. The three environments

| Env | How | Notes |
|---|---|---|
| Local dev | `docker compose up --build -d` + `bash scripts/seed-demo.sh` (or `docker-compose.dev.yml` for a pre-seeded stack) | binds `127.0.0.1:8080` (REST) / `6334` (gRPC) |
| Single-node prod | container from `release-publish.yml` images (cosign-signed, SLSA provenance, SBOM — verify before running) | SQLite + WAL; back up per [../runbooks/backup-and-restore.md](../runbooks/backup-and-restore.md) |
| Kubernetes | `helm install aegis helm/aegis-gateway/` | probes wired to `/livez` `/readyz` `/startupz`; policy ConfigMap checksummed + hot-reloaded (`AEGIS_POLICY_HOT_RELOAD=true`); **keep `replicaCount: 1` until Postgres (#1194)** — SQLite is single-writer |

## 3. Production posture checklist (fail-closed by construction)

- `AEGIS_JWT_SECRET` set (supports `new,old` rotation) and `AEGIS_JWT_REQUIRED=true`
- Public bind only with the hardened startup checks (public-bind fail-closed mode) — see [../production-hardening.md](../production-hardening.md)
- Encryption at rest: build with `--features sqlcipher` **and** set `AEGIS_DB_ENCRYPTION_KEY` (key without the feature = startup error, by design)
- mTLS for agents (optional): `AEGIS_MTLS_CA_CERT` (+ `AEGIS_MTLS_CRL_PATH`)
- Webhook/callback secrets: `AEGIS_GITHUB_WEBHOOK_SECRET`, `AEGIS_SLACK_SIGNING_SECRET`, `AEGIS_POLICY_SIGNING_KEY` (bundles 501 without it)
- Replay store for multi-instance: `AEGIS_REPLAY_STORE=db`
- Receipt signing key provisioned out-of-band; rotate per [../runbooks/secret-rotation.md](../runbooks/secret-rotation.md)

## 4. Observability

- Prometheus: `GET /metrics` (incl. `approval_hash_mismatch_total`, `provenance_denials_total`, `authorize_latency_seconds`)
- OTLP traces + metrics: set `AEGIS_OTLP_ENDPOINT` (unset = fully inert); tokio runtime metrics included; `traceparent` propagation stitches SDK↔gateway traces
- Grafana: import `grafana/dashboards/`
- Health: `/livez` (process), `/readyz` (DB + audit writer + background tasks), `/startupz` (migrations/policy done), `/debug/runtime` (tokio)

## 5. Tuning knobs (env)

DB: `AEGIS_DB_STATEMENT_CACHE_CAPACITY`, `AEGIS_DB_MMAP_SIZE`, `AEGIS_DB_JOURNAL_SIZE_LIMIT`, `AEGIS_DB_WAL_AUTOCHECKPOINT` · approvals: `AEGIS_APPROVAL_TTL_SECS` · policy: `AEGIS_POLICY_HOT_RELOAD`, `CEDAR_POLICY_PATH`. Full reference: [../production-hardening.md](../production-hardening.md); baselines: [../performance-baseline.md](../performance-baseline.md), [../performance-tuning-guide.md](../performance-tuning-guide.md).

## 6. CI/CD you inherit

`ci.yml` (fmt/clippy/test/coverage/parity) · `docs.yml` (docs site to gh-pages, regenerates OpenAPI) · `container-scan.yml`/`sast.yml`/`secret-scan.yml` · `release-please.yml` + `release-publish.yml` (tags → signed images). Helm changes: `helm lint helm/aegis-gateway/`.

## 7. When things break

[../AegisAgent_Debugging_Guide.md](../AegisAgent_Debugging_Guide.md) · [../runbooks/index.md](../runbooks/index.md) — deny-storm, exfiltration, token rotation, backup/restore, receipt-chain verification, secret rotation.

## 8. First Verified Task

```bash
make doctor
make demo
curl -fsS http://127.0.0.1:8080/readyz
```

Confirm the demo blocks the swapped action and replay, verifies the receipt chain, and leaves readiness healthy. Then stop the local stack with `docker compose down`.

## 9. Security and Failure Handling

- Never expose the gateway publicly with demo mode or without enforced authentication and TLS.
- Keep SQLite at one writer; do not infer HA from a successful multi-pod rollout.
- Treat policy, database, backups, JWT secrets, and receipt-signing material as security assets.
- Do not work around an outage by making protected SDK calls fail open.
- After restore or rollback, verify the receipt chain before restoring traffic.

## 10. Operations and Troubleshooting

Start with `/startupz`, `/readyz`, and `/livez`, then inspect database pool wait, background-task status, event drops, receipt integrity, and recent configuration/image/policy changes. Use the [Deployment Guide](../deployment-guide.md) for rollout/rollback and the [runbook index](../runbooks/index.md) for incident procedures.

## 11. References

[Deployment Guide](../deployment-guide.md) · [Production Hardening](../production-hardening.md) · [Performance Tuning](../performance-tuning-guide.md) · [Implementation Status](../Implementation_Status.md)
