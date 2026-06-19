# ADR-0002: SQLite as the default storage backend (Postgres at scale)

**Status:** Accepted
**Date:** 2026-01 (retroactive — recorded 2026-06)
**Issue:** [#1197](https://github.com/lavkushry/AegisAgent/issues/1197)

## Context

The gateway persists agents, tools, decisions, approvals, receipts, audit
events, SOC alerts/incidents — all tenant-scoped — and needs a storage layer
from day one. The product's stated self-hosted deployment target is
`docker compose up` → first protected action in under 20 minutes, with **no
production tool-call traffic leaving the customer's network**
(`AegisAgent_Operational_Design.md` §"Self-hosted single binary").

## Decision

Default to SQLite (via SQLx, WAL journal mode, busy-timeout) as the
**self-hosted, first-class** backend, with the same SQLx query layer designed
to retarget Postgres for the SaaS/Enterprise deployment tiers as load or
multi-node requirements demand. See
[`database_migration.md`](https://github.com/lavkushry/AegisAgent/blob/main/.claude/rules/database_migration.md) and
[`sqlite_usage.md`](https://github.com/lavkushry/AegisAgent/blob/main/.claude/rules/sqlite_usage.md) for the operational
specifics (WAL, busy-timeout, tenant-id indexing).

## Consequences

- Zero external dependency for the deployment tier most likely to be
  evaluated first (a single binary + one file is the entire stateful
  footprint) — directly serves the 20-minute quickstart goal.
- SQLite's single-writer-file model means write throughput is bounded by one
  process; mitigated today by WAL mode + a 5s busy-timeout + (where the
  write isn't latency-critical, e.g. `audit_events`) async batched writes
  via a Tokio channel, but this is a real ceiling, not a workaround that
  scales indefinitely.
- Because all queries go through SQLx with parameterized binds (never string
  interpolation) and the schema is designed tenant-scoped from the start,
  the eventual Postgres retarget is a connection-string and dialect change,
  not a rewrite — but it has not yet been built or load-tested as of this
  writing (`docs/AegisAgent_Gap_Reassessment_2026-06.md` lists "PostgreSQL
  backend" under "Next").
- Compile-time query checking (`sqlx::query!`) ties CI to either a live
  SQLite DB or a committed `sqlx-data.json` offline cache that must be kept
  in sync with schema migrations.

## Alternatives considered

- **Postgres from day one** — better write concurrency and a clearer scale
  story, but requires a running Postgres instance even for local evaluation,
  directly working against the self-hosted "no external infra" pitch and the
  20-minute quickstart target.
- **An embedded KV store (e.g. sled, redb)** — would avoid SQL entirely, but
  forfeits SQLx's compile-time query checking and the large amount of
  existing relational tooling (migrations, ORMs, ad-hoc operator queries)
  that SQL gives operators for free.

## Revisit when

A self-hosted deployment's write volume (audit events, decisions, SOC
events) starts hitting SQLite's single-writer ceiling in practice, or a
customer's multi-node / HA requirement forces the Postgres backend to be
built out rather than remain a documented future tier.
