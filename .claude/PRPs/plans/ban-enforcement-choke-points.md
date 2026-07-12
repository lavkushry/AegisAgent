# Title: Ban/Quarantine Enforcement at All Choke Points

Closes the Wave C gap "Ban/quarantine enforcement at all choke points (egress,
broker, cage start, sensor), not only store + partial preflight". The
`agent_bans` migration (0029) already promises enforcement "before sandbox
start, authorize, tool call, MCP call, egress, credential issuance" — today
only `/v1/egress/check` consults the store.

## 1. Architectural Scope & Impact

- `lib/storage` — one new read method on `StorageBackend` (no schema change,
  no migration): `list_active_agent_runs_for_agent(tenant_id, agent_id)`.
- `src/src/routes/authorize.rs` — deterministic deny (durable decision +
  audit event via `write_decision_and_audit`) when the resolved agent or the
  requested tool is under an active ban, or the agent has an active
  `quarantine_records` row.
- `src/src/routes/broker.rs` — 403 before approval consumption when the
  broker tool is banned or quarantined.
- `src/src/routes/runtime.rs` — 403 on `create_agent_run` and `claim_run`
  when the run's agent is banned/quarantined (claim also blocks a
  quarantined run) — bans created after registration still block start.
- `src/src/routes/control.rs` — `POST /v1/bans` with `target_type=agent`
  additionally issues signed `kill_run` control commands for the agent's
  active runs (sensor/runner propagation, best-effort + logged).

Invariants preserved: Cedar remains the only allow-producer — bans/quarantine
only tighten (deny); DB errors fail closed (500 blocks execution); every
query binds `tenant_id`; parameterized SQL only.

## 2. Step-by-Step Execution Phases

- **Phase 1: Storage** — trait + `db/agent_runs.rs` query for non-terminal
  runs (`started|claimed|running|paused`) by agent; unit tests.
- **Phase 2: Gateway enforcement** — authorize, broker, runtime handlers
  (tests first, then minimal checks).
- **Phase 3: Ban propagation** — `create_ban` issues signed kill commands
  per active run when a signing key is configured; without a key the ban row
  still lands (choke points enforce it) and the response reports zero
  propagated commands.
- **Phase 4: SDKs** — no change: denial surfaces as the existing
  `deny`/403 contract the fail-closed SDKs already handle.

## 3. Verification & Testing Targets

- `cargo test --workspace -- --test-threads=1` (route + storage tests)
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`
- `node scripts/validate-docs.mjs`

## 4. Security Audit Checklist

- [x] Parameterized SQL only (reuse `is_banned` / `is_quarantined` lookups).
- [x] Every new query filters `tenant_id`.
- [x] Fail-closed: storage errors deny (500), never allow.
- [x] Ban/quarantine can only produce deny — never allow, never loosen trust.
- [x] Signed control commands only (no signing key ⇒ no unsigned command).
