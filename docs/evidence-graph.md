# AegisAgent — Evidence Graph

**Issue:** [#1323](https://github.com/lavkushry/AegisAgent/issues/1323)
**Code:** `gateway/src/graph.rs` (#1271, schema) · `gateway/src/routes.rs` (#1272, query API)

The evidence graph is AegisAgent's compliance-facing view that ties one tenant's agents, runs, tool calls, decisions, approvals, receipts, incidents, MCP servers, and policies together into a single auditable graph. It is **constructed at query time** from existing tables — there is no separate graph database or background job maintaining it, so it is always consistent with `decisions`/`approvals`/`action_receipts`/`soc_incidents` as of the moment you query it.

---

## 1. Node and edge types

`gateway/src/graph.rs` defines the canonical, closed set of node and edge kinds. Both serialize directly to the field names [vis.js Network](https://visjs.github.io/vis-network/docs/network/) expects — `id`/`group`/`label` for nodes, `from`/`to`/`label` for edges — specifically so an `EvidenceGraph` response can be handed straight to a `vis.Network` `DataSet` with no client-side remapping (see §4).

### Node types (`NodeType`, serializes as a node's `group`)

| Type | Represents | `label` is... |
|---|---|---|
| `agent` | One registered agent | The agent's name |
| `run` | One agent run (`trace.run_id`) | The run id |
| `tool_call` | One `/v1/authorize` call | `{tool}.{action}` |
| `decision` | The Cedar decision for a `tool_call` | `allow`/`deny`/`require_approval`/`redact`/`quarantine` |
| `approval` | A pending/decided approval | The approval's status |
| `receipt` | A signed action receipt | The receipt hash |
| `incident` | A SOC incident | The incident summary |
| `mcp_server` | An MCP server | (reserved — not yet populated by any `/v1/graph/*` endpoint; see §5) |
| `policy` | A Cedar policy that matched a decision | The matched policy's name |

### Edge types (`EdgeType`, serializes as an edge's `label`)

| Type | Meaning |
|---|---|
| `triggered_by` | A `run` was triggered by an `agent` (or a standalone `tool_call` with no `run_id` was triggered directly by the `agent`) |
| `executed` | A `run` executed a `tool_call` |
| `decided` | A `tool_call` was decided, producing a `decision` |
| `approved` | A `decision` produced an `approval` |
| `produced` | A `decision` produced a `receipt` |
| `linked_to` | A `decision` matched a `policy`, or an `incident` is linked to an `agent`/`decision` |

### Wire shape

```json
{
  "nodes": [
    { "id": "agent:agent_42", "group": "agent", "label": "Coding Agent", "timestamp": "2026-06-17T12:00:00Z", "metadata": null },
    { "id": "tool_call:d1", "group": "tool_call", "label": "github.merge_pull_request", "timestamp": "2026-06-17T12:00:01Z", "metadata": null },
    { "id": "decision:d1", "group": "decision", "label": "require_approval", "timestamp": "2026-06-17T12:00:01Z", "metadata": { "risk_score": 72, "reason": "..." } }
  ],
  "edges": [
    { "from": "tool_call:d1", "to": "decision:d1", "label": "decided", "timestamp": "2026-06-17T12:00:01Z" }
  ]
}
```

Node ids are namespaced `{type}:{underlying_id}` (e.g. `agent:agent_42`, `decision:d1`, `policy:untrusted-mutation-forbid`) so they're stable and collision-free across node types without a lookup table. `metadata` is free-form (currently populated only on `decision` nodes, with `risk_score`/`reason`) and follows the same redaction invariant as everything else in AegisAgent — no secrets, tokens, or raw action payloads ever appear in it.

---

## 2. Query API

All three endpoints are tenant-scoped (via the standard agent-token-derived tenant context) and **read-only** — building a graph never writes to `soc_alerts`/`soc_incidents`/anything else (the same "advisory, never mutates state" posture as `composite_risk_score` and detection-rule backtesting).

| Endpoint | Scope | Notes |
|---|---|---|
| `GET /v1/graph/run/:run_id` | One agent run | Fixed depth 3 (everything: approvals, receipts, matched policies). 404 if the run has no decisions for this tenant. |
| `GET /v1/graph/incident/:incident_id` | One SOC incident | Fixed depth 2 (no policy nodes). Walks the incident's `source_event_ids` → audit event → decision linkage (#1301) to find every decision behind the incident. 404 if the incident doesn't exist for this tenant. |
| `GET /v1/graph/agent/:agent_id?depth=N` | One agent | `depth` optional, clamped to `[1, 5]`, default `3`. Depths 4–5 are accepted but currently behave identically to depth 3 — reserved for future expansion (e.g. multi-hop trust-chain or cross-agent linkage) rather than a bug. Capped at the agent's most recent **50** decisions (`GRAPH_AGENT_DECISION_LIMIT`) regardless of `depth`, to bound the query. 404 if the agent doesn't exist for this tenant. |

### Depth semantics (shared by all three)

- **depth 1**: `tool_call` + `decision` nodes, plus `run`/`agent` linkage (`triggered_by`/`executed`/`decided` edges).
- **depth ≥ 2**: adds `approval` nodes (only for decisions with `require_approval`) and `receipt` nodes (only for decisions that produced one).
- **depth ≥ 3**: adds `policy` nodes for every entry in the decision's `matched_policy_ids`.

Cross-tenant isolation is enforced the same way as every other query endpoint: a request scoped to tenant A can never resolve a run/incident/agent id belonging to tenant B — it 404s exactly as if the id didn't exist at all, never leaking "it exists, but you can't see it."

### Worked example

```bash
curl -s -H "Authorization: Bearer $AGENT_TOKEN" \
  "http://127.0.0.1:8080/v1/graph/run/run_42"
```

For a run with one `require_approval` decision (risk score 72, matched two policies, later approved, with a receipt issued):

```json
{
  "nodes": [
    { "id": "agent:agent_42", "group": "agent", "label": "Coding Agent", "timestamp": "2026-06-17T11:59:00Z", "metadata": null },
    { "id": "run:run_42", "group": "run", "label": "run_42", "timestamp": "2026-06-17T12:00:01Z", "metadata": null },
    { "id": "tool_call:d1", "group": "tool_call", "label": "github.merge_pull_request", "timestamp": "2026-06-17T12:00:01Z", "metadata": null },
    { "id": "decision:d1", "group": "decision", "label": "require_approval", "timestamp": "2026-06-17T12:00:01Z", "metadata": { "risk_score": 72, "reason": "high-risk mutating action" } },
    { "id": "approval:a1", "group": "approval", "label": "APPROVED", "timestamp": "2026-06-17T12:00:01Z", "metadata": null },
    { "id": "receipt:r1", "group": "receipt", "label": "3f9a...e21c", "timestamp": "2026-06-17T12:00:05Z", "metadata": null },
    { "id": "policy:require-approval-high-risk", "group": "policy", "label": "require-approval-high-risk", "timestamp": "2026-06-17T12:00:01Z", "metadata": null },
    { "id": "policy:approver-group-leads", "group": "policy", "label": "approver-group-leads", "timestamp": "2026-06-17T12:00:01Z", "metadata": null }
  ],
  "edges": [
    { "from": "run:run_42", "to": "agent:agent_42", "label": "triggered_by", "timestamp": "2026-06-17T12:00:01Z" },
    { "from": "run:run_42", "to": "tool_call:d1", "label": "executed", "timestamp": "2026-06-17T12:00:01Z" },
    { "from": "tool_call:d1", "to": "decision:d1", "label": "decided", "timestamp": "2026-06-17T12:00:01Z" },
    { "from": "decision:d1", "to": "approval:a1", "label": "approved", "timestamp": "2026-06-17T12:00:01Z" },
    { "from": "decision:d1", "to": "receipt:r1", "label": "produced", "timestamp": "2026-06-17T12:00:01Z" },
    { "from": "decision:d1", "to": "policy:require-approval-high-risk", "label": "linked_to", "timestamp": "2026-06-17T12:00:01Z" },
    { "from": "decision:d1", "to": "policy:approver-group-leads", "label": "linked_to", "timestamp": "2026-06-17T12:00:01Z" }
  ]
}
```

---

## 3. Investigation workflow: tracing an attack chain

A typical confused-deputy or deny-storm investigation starts from a SOC alert/incident, not a run id, so the natural entry point is `GET /v1/incidents` → `GET /v1/graph/incident/:incident_id`:

1. **Find the incident.** `GET /v1/incidents?severity=high` (or the live `GET /v1/ws/events` feed) surfaces the triggering pattern — e.g. `rule_deny_storm`: 5+ denies for the same agent within 60 seconds.
2. **Pull its evidence graph.** `GET /v1/graph/incident/:incident_id` returns every decision behind the incident, each with its `risk_score`/`reason` in `metadata`, plus the matched Cedar policy that denied each one (depth 2 — no policy nodes from the incident endpoint itself; see below to get those).
3. **Expand to the full run.** Each `decision` node's id is `decision:{decision_id}`; cross-reference `GET /v1/decisions/:id` for the full record (which includes `run_id`), then `GET /v1/graph/run/:run_id` to see the *entire* run depth-3 — every tool call the agent made in that run, not just the ones that triggered this incident, which often reveals the step *before* the denied action (e.g. the agent reading an `untrusted_external` GitHub issue) that the incident graph alone wouldn't show.
4. **Check the agent's broader pattern.** `GET /v1/graph/agent/:agent_id?depth=3` shows the agent's last 50 decisions across *all* runs — useful for confirming whether this was a one-off or part of a sustained pattern (which `risk_escalation.rs`'s auto-tier-escalation, #1296, would also have already started responding to independently).
5. **Verify the receipt chain**, if the action executed before being caught: `receipt` nodes link to `POST /v1/receipts/verify-chain` for cryptographic confirmation the recorded decision matches what the SDK actually hashed and (if applicable) what executed.

This mirrors exactly how `add_decision_subgraph` (the shared internal helper behind all three endpoints) assembles the graph — there's no separate "investigation mode," just composing the same three read-only queries in the order an investigation naturally needs them.

---

## 4. Visualization

There is no built-in graph dashboard in the SOC Console UI today (see [`AegisAgent_SOC_UI_Design.md`](AegisAgent_SOC_UI_Design.md) for what *is* shipped — `/v1/soc/summary` plus the live WebSocket feed, no graph view yet). The `EvidenceGraph` response shape is deliberately vis.js-compatible so you can render one with minimal glue code:

```html
<!DOCTYPE html>
<html>
<head>
  <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
</head>
<body>
  <div id="graph" style="height: 600px;"></div>
  <script>
    const AGENT_TOKEN = "<your agent's bearer token>"; // never hardcode this in a real deployment

    fetch("http://127.0.0.1:8080/v1/graph/run/run_42", {
      headers: { "Authorization": "Bearer " + AGENT_TOKEN }
    })
      .then(r => r.json())
      .then(({ nodes, edges }) => {
        new vis.Network(
          document.getElementById("graph"),
          { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) },
          { groups: {
              agent: { color: "#4C6EF5" }, decision: { color: "#F76707" },
              approval: { color: "#37B24D" }, incident: { color: "#E03131" },
              receipt: { color: "#7048E8" }, policy: { color: "#868E96" }
          } }
        );
      });
  </script>
</body>
</html>
```

Point this at any of the three endpoints (swapping the URL) to get an interactive, draggable graph — vis.js colors/groups nodes by the `group` field directly, no transformation needed. This is a minimal standalone example, not a shipped AegisAgent artifact; treat it as a starting point for your own internal tooling rather than an official UI.

---

## 5. Scope and limitations

- **`mcp_server` nodes are defined but not yet populated.** `NodeType::McpServer` exists in the schema (so MCP-related graph data has a defined shape to land in later), but none of the three current `/v1/graph/*` endpoints construct one — there's no query path today that adds an MCP server into a run/incident/agent graph. If you need to correlate MCP manifest drift with denied decisions today, use the audit trail described in [`mcp-defense-architecture.md`](mcp-defense-architecture.md) §3 instead.
- **No cross-agent graph traversal.** `GET /v1/graph/agent/:agent_id` does not currently surface `parent_run_id`/`root_trust_level` multi-hop chain data (#1293) as graph edges, even though that data is persisted on `decisions`. Today you'd reconstruct a multi-agent chain by following `run_id`/`parent_run_id` manually across separate `GET /v1/decisions` calls.
- **Bounded, not streaming.** All three endpoints build the full response in memory in one request — depth and the 50-decision agent cap exist specifically to keep that bounded; there's no pagination or incremental-loading variant for very large graphs.
