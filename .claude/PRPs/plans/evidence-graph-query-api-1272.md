# Title: Evidence Graph Query API (#1272)

## 1. Architectural Scope & Impact

- `gateway/src/graph.rs` (#1271, already merged): `EvidenceGraph`,
  `GraphNode`/`GraphEdge`, `NodeType`/`EdgeType` — schema only, unchanged.
- `gateway/src/db.rs`: three new tenant-scoped, parameterized read helpers —
  no schema/migration changes (all tables already exist):
  - `list_decisions_by_run_id(pool, tenant_id, run_id) -> Vec<DecisionRecord>`
  - `get_action_receipt_by_decision_id(pool, tenant_id, decision_id) -> Option<ActionReceiptRecord>`
  - `get_audit_event_decision_id(pool, tenant_id, event_id) -> Option<String>`
- `gateway/src/routes.rs`: new `/v1/graph/*` handlers built as JOIN-free
  sequential queries (SQLite — no recursive CTE needed at this scale) that
  assemble an `EvidenceGraph` via a shared `add_decision_subgraph` helper.
- `gateway/src/main.rs`: route registration only.
- `gateway/policies.cedar`: **no change** — read-only query endpoints, no new
  authorization semantics.

## 2. Endpoints

- `GET /v1/graph/run/:run_id` — full subgraph for one agent run.
- `GET /v1/graph/incident/:incident_id` — subgraph for one SOC incident.
- `GET /v1/graph/agent/:agent_id?depth=N` — agent-centric graph,
  `depth` clamped to `[1, 5]`, default `3`.

All three: tenant-scoped via the existing `TenantId` extractor, 404 (not 500)
when the root entity doesn't exist or belongs to another tenant, response
body `EvidenceGraph { nodes, edges }` (#1271 vis.js-compatible shape).

## 3. Graph Assembly Model

Shared helper `add_decision_subgraph(graph, seen, pool, tenant_id, decision, agent_node_id, depth)`
builds the provenance chain for one `DecisionRecord`:

- `ToolCall` node (`tool_call:{decision.id}`, label `"{skill}.{action}"`).
- `Decision` node (`decision:{decision.id}`, label = `decision.decision`).
- edge `tool_call -[decided]-> decision`.
- if `decision.run_id` is set: `Run` node (`run:{run_id}`), edges
  `run -[executed]-> tool_call` and `run -[triggered_by]-> agent`;
  else: edge `tool_call -[triggered_by]-> agent`.
- depth >= 2: `get_approval_by_decision_id` → `Approval` node + edge
  `decision -[approved]-> approval`; `get_action_receipt_by_decision_id` →
  `Receipt` node + edge `decision -[produced]-> receipt`.
- depth >= 3: each entry in `decision.matched_policy_ids` (comma-separated,
  existing format) → `Policy` node (`policy:{name}`) + edge
  `decision -[linked_to]-> policy`.

`seen: &mut HashSet<String>` dedups node ids (a decision's approval/receipt
may already exist in the graph from a prior decision — not expected, but
cheap to guard).

### Run graph (`/v1/graph/run/:run_id`)

1. `list_decisions_by_run_id` — 404 if empty.
2. Add `Agent` node from the first decision's `agent_id`.
3. `add_decision_subgraph(..., depth=3)` for every decision in the run.

### Incident graph (`/v1/graph/incident/:incident_id`)

1. `get_soc_incident` — 404 if missing/wrong tenant.
2. Add `Incident` node + `Agent` node (`incident.agent_id`) + edge
   `incident -[linked_to]-> agent`.
3. Parse `source_event_ids` (JSON array of strings). For each id,
   `get_audit_event_decision_id`; if it resolves to a decision not yet seen,
   `get_decision_by_id` + `add_decision_subgraph(..., depth=2)` + edge
   `incident -[linked_to]-> decision`.

### Agent graph (`/v1/graph/agent/:agent_id?depth=N`)

1. `get_agent_by_id` — 404 if missing/wrong tenant. `depth = clamp(query.depth.unwrap_or(3), 1, 5)`.
2. Add `Agent` node.
3. `list_decisions(pool, tenant_id, limit=50, offset=0, Some(agent_id), None)`
   → `add_decision_subgraph(..., depth)` for each (bounds the query —
   "Depth limit to prevent unbounded queries").
4. depth >= 3: `list_soc_incidents(..., agent_id=Some(agent_id))` (limit 50)
   → `Incident` nodes + edge `incident -[linked_to]-> agent`.

Depths 4-5 are accepted (clamped, not rejected) but currently behave the same
as depth 3 — no further expansion is defined yet. Documented in code, not a
behavioral gap that needs a 400.

## 4. Verification & Testing Targets

```bash
cargo test   --manifest-path gateway/Cargo.toml   # full suite + new graph route tests
cargo fmt    --manifest-path gateway/Cargo.toml -- --check
cargo clippy --manifest-path gateway/Cargo.toml --all-targets -- -D warnings
```

New `#[tokio::test]` integration tests in `routes.rs`:

- run graph returns nodes/edges for a seeded decision + approval + receipt;
  404 for unknown/cross-tenant run_id.
- incident graph returns incident + agent + linked decision; 404 for
  unknown/cross-tenant incident_id.
- agent graph returns agent + decisions at depth 1; approvals/receipts appear
  only at depth >= 2; incidents appear only at depth >= 3; 404 for
  unknown/cross-tenant agent_id; depth clamps to `[1,5]` (e.g. `depth=99` ->
  treated as 5, no error).

## 5. Security Audit Checklist

- [ ] Every new `db.rs` query binds `tenant_id` (CWE-284) and is parameterized
      (CWE-89) — no string interpolation, including the `source_event_ids`
      loop (one parameterized query per id, no dynamic `IN (...)` list).
- [ ] All three handlers return 404 (never 500/leak) for missing or
      cross-tenant root entities.
- [ ] `depth` query param is clamped server-side, never trusted raw, so a
      crafted `depth=999999` cannot cause unbounded recursion (there is no
      recursion, but document the bound regardless).
- [ ] Read-only endpoints — no `/v1/authorize` decision path touched (Law 1
      unaffected).
