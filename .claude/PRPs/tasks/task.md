# MVP Launch Readiness Tasks

## P0: Must-Have for MVP Launch

- [x] Create root `policies.cedar`
  - [x] File exists at repository root.
  - [x] Synchronized with `gateway/policies.cedar`.
  - [x] Includes fail-closed baseline, read-only allow, main-merge approval, semi-trusted approval, and untrusted mutation denial.
- [x] Add `docker-compose.yml`
  - [x] Compose builds gateway from `gateway/Dockerfile`.
  - [x] SQLite data persists under `data/`.
  - [x] Healthcheck targets `/health`.
  - [x] Environment variables documented in README/CLAUDE.
- [x] Python SDK `@protect_tool` decorator
  - [x] Calls `/v1/authorize`.
  - [x] Raises `PermissionError` on deny and unexpected decisions.
  - [x] Supports approval polling, edited parameters, and action-hash verification.
- [x] Demo script: `examples/github-attack-demo.py`
  - [x] Simulates malicious issue content.
  - [x] Attempts main-branch merge under untrusted context.
  - [x] Prints blocked outcome and audit URL.
- [x] Seed script: `scripts/seed-demo.sh`
  - [x] Registers demo agent.
  - [x] Registers mock GitHub actions.
  - [x] Registers demo MCP server/tool manifest.
  - [x] Idempotent against gateway upserts.
- [x] README quickstart
  - [x] Five-step local flow.
  - [x] Expected output snippets.
  - [x] Audit endpoint instructions.

## P1: Strongly Recommended for Credibility

- [x] `SECURITY.md`
- [x] `CONTRIBUTING.md`
- [x] GitHub Actions CI workflow
- [x] `ROADMAP.md`
- [x] Static dashboard mock at `docs/dashboard-mock.html`
- [ ] Record/link 90-second demo video

## P2: Post-MVP

- [ ] Slack signed callback verification and approver role lookup.
- [ ] TypeScript SDK.
- [ ] MCP manifest signing and drift detection.
- [ ] Runtime MCP proxy execution path.
- [ ] OpenTelemetry exporter examples and traceparent propagation.
- [ ] Audit redaction controls.
