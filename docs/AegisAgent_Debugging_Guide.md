# Debugging Guide

**One sentence:** how to figure out *why* AegisAgent did what it did — decision by decision, layer by layer.

**Golden rule:** in this system, "it blocked me" is usually the product working. Debug the *reason chain*, not around the block.

## 1. First five commands

```bash
curl -s localhost:8080/readyz | jq        # db, audit_writer, background_tasks
curl -s localhost:8080/startupz | jq      # migrations/policy finished?
curl -s localhost:8080/metrics | grep -E 'aegis|approval|provenance'
curl -s localhost:8080/debug/runtime | jq # tokio workers/utilization
RUST_LOG=debug CEDAR_POLICY_PATH=policies.cedar cargo run -p gateway --bin gateway
```

## 2. "Why was this denied?"

Work the chain in order — the answer names itself:

1. **Decision record:** `GET /v1/decisions?limit=…` / `GET /v1/decisions/:id` — the `reason` field is authoritative.
2. **Was it registry?** unknown agent/tool/MCP server/tool = deny by default. Check registration; remember identifier normalization (case/percent/Unicode variants all map to one key — #1335).
3. **Was it provenance?** `source_trust` on the decision; `provenance_denials_total` on `/metrics`. Untrusted-external + mutating = forbid, by policy.
4. **Was it policy?** test the exact request against Cedar: `POST /v1/policies/compile` for syntax; policy unit tests in `lib/policy`; hot-reload state via `POST /v1/policies/reload` response.
5. **Was it agent status?** `GET /v1/agents/:id` — frozen/quarantined/revoked agents fail closed at auth (401), which can *look like* a policy deny from the agent's side.
6. **Was it rate/quota/replay?** 429s: per-tenant limiter, per-IP approval limiter, per-approval-id attempt tracker, replay-nonce dedup, timestamp staleness (>5 min → reject).

## 3. "Why won't my approval consume?"

`GET /v1/approvals/:id` → status tells you: `expired` (TTL), `consumed` (single-use — did something consume it first?), `rejected`, or hash mismatch (the action you're executing isn't the one approved — check for parameter drift; `approval_hash_mismatch_total` increments). 429 → attempt tracker; slow down and check for ID brute-forcing.

## 4. "Where did my event/alert go?"

- Emitted at all? `GET /v1/audit/events` (decision-linked), `GET /v1/ws/events` (live).
- Pipeline healthy? `/readyz` → `background_tasks` false means a drain/writer task died (#1152); `audit_writer` false means the last batch flush failed (#1299/#1315).
- Rule firing? `detection_rules` rows + `POST /v1/soc/rules/reload`; dry-run via `POST /v1/playbooks/:id/test`.
- Webhook delivery? subscription `delivery_status` — `dead` after 10 consecutive failures; `POST /v1/webhook_subscriptions/:id/reactivate`.

## 5. "Receipts won't verify"

`POST /v1/receipts/verify-range` to bisect the break; compare against an anchored `chain-head`. Usual causes: manual DB edits, restore from older snapshot (chain forks), or hand-rolled canonicalization in a client. See [flows/Receipt_Flow.md](flows/Receipt_Flow.md) and [runbooks/receipt-chain-verification.md](runbooks/receipt-chain-verification.md).

## 6. SDK-side

Python raises typed errors: `AegisAuthorizationDenied` (decision), `AegisConnectionError` (gateway unreachable → fail-closed for mutating). Turn on SDK logging (`aegisagent/logging.py`). Reproduce without your agent: `python3 examples/mock_server.py`. Byte-parity doubts: run the vectors under `tests/` through the SDK's canon.

## 7. Performance

`authorize_latency_seconds` histogram (OTLP) · benches: `cargo bench -p gateway` · flamegraphs: `scripts/flamegraph.sh authorize_benchmark` · SQLite knobs: [performance-tuning-guide.md](performance-tuning-guide.md). Slow authorize is usually WAL write contention — check the deferred-write/batching paths landed (#1511/#1512/#1315) and don't share one SQLite file across processes.

## 8. Tracing

Set `AEGIS_OTLP_ENDPOINT` — spans: `authorize`, `cedar_evaluate`, `db_query`, `receipt_hash`, `approval_create`; SDK `traceparent` stitches end-to-end. Unset = inert.

## 9. Escalation map

| Layer | Owner file(s) |
|---|---|
| Routing/extractors | `src/src/main.rs`, `src/src/routes/mod.rs` |
| Decisions | `src/src/routes/authorize*.rs`, `lib/policy/` |
| Storage | `lib/storage/src/db/*`, migrations |
| SOC | `lib/soc/src/*` |
| SDKs | `sdk-*/` |
| UI | `ui/src/` ([components/Console_UI.md](components/Console_UI.md)) |

## 10. Related docs

[Local_Development.md](Local_Development.md) · [fail-closed-behavior.md](fail-closed-behavior.md) · [runbooks/index.md](runbooks/index.md) · [production-hardening.md](production-hardening.md)
