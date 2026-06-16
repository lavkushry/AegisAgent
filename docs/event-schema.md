# AegisAgent — Canonical Agent Security Event (AseEvent) Schema

> **Source of truth:** `gateway/src/events.rs` — `AseEvent` struct.
> **Issue:** [#1388](https://github.com/lavkushry/AegisAgent/issues/1388)

An **Agent Security Event** (`AseEvent`) is the normalized unit that every
SOC-plane consumer (detection, correlation, response, indexing, WebSocket feed)
receives. Events are emitted non-blockingly onto a bounded Tokio `mpsc` channel
so the inline `/v1/authorize` decision is never delayed by downstream processing
(design law 3).

---

## Schema

```json
{
  "event_id":        "<uuid-v4>",
  "occurred_at":     "<RFC 3339 UTC>",
  "tenant_id":       "<string>",
  "kind":            "<event kind — see table below>",
  "agent_id":        "<uuid-v4 | 'unknown'>",
  "decision":        "allow | deny | require_approval",
  "tool":            "<skill_key | source system>",
  "action":          "<action_key | verb>",
  "resource":        "<string | null>",
  "risk_score":      0,
  "reason":          "<human-readable explanation>",
  "run_id":          "<string | null>",
  "trace_id":        "<string | null>",
  "matched_policies": ["<policy_id>", ...]
}
```

### Field reference

| Field | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `event_id` | string (UUID v4) | **yes** | Unique identifier for this event. Independent from the `decision_id` on the `/v1/decisions` row. |
| `occurred_at` | string (RFC 3339 UTC) | **yes** | Wall-clock time the event was produced, in the gateway process. |
| `tenant_id` | string | **yes** | Owning tenant. Every SOC consumer filters and scopes by this field. Never cross-tenant data flows through a single `AseEvent`. |
| `kind` | string | **yes** | Event class. See [Event kinds](#event-kinds) below. |
| `agent_id` | string (UUID v4) | **yes** | UUID of the registered agent that triggered the event. For ingested external events where an agent UUID is unavailable, the value is `"unknown"`. |
| `decision` | string | **yes** | The authorization outcome: `allow`, `deny`, or `require_approval`. Ingested external events always carry `"allow"` (they are observations, not authorizations). |
| `tool` | string | **yes** | The `skill_key` (e.g. `"github"`, `"filesystem"`) for authorize events; the source system (e.g. `"github"`, `"openai"`) for ingested events. |
| `action` | string | **yes** | The `action_key` (e.g. `"merge_pull_request"`) for authorize events; the verb from the external payload for ingested events. |
| `resource` | string or null | no | Specific resource operated on (e.g. `"org/repo"`, `"/etc/passwd"`). Null when not provided by the caller. |
| `risk_score` | integer | **yes** | Advisory risk score `0..=100`. Informational only — never gates the decision (design law 1). Ingested events carry `0`. |
| `reason` | string | **yes** | Human-readable explanation of the decision, sourced from the Cedar policy match or the inline deny logic. |
| `run_id` | string or null | no | Caller-supplied agent run identifier, propagated from `AuthorizeRequest.trace.run_id`. Null when absent. |
| `trace_id` | string or null | no | Caller-supplied distributed trace identifier, propagated from `AuthorizeRequest.trace.trace_id`. Null when absent. |
| `matched_policies` | array of strings | **yes** | Cedar policy IDs that matched this request (e.g. `["policy1"]`). Empty array for ingested events. |

---

## Event kinds

The `kind` field discriminates the event class. Consumers (detection rules,
correlators) branch on this value.

| Kind | Emitter | When emitted |
| ---- | ------- | ------------ |
| `authorize_decision` | `routes.rs` — `authorize_action` | Every `POST /v1/authorize` that completes an inline decision (allow, deny, require_approval). This is by far the most frequent event. |
| `replay_attempt` | `routes.rs` — `emit_replay_event` | When `POST /v1/authorize` detects a replay-nonce reuse (`replay_nonce_reused`) or a `POST /v1/approvals/:id/consume` re-consumes an already-consumed single-use approval. |
| `mcp_manifest_drift` | `routes.rs` — `discover_mcp_tools` | When an MCP server's live manifest hash diverges from the pinned hash. Carries `risk_score` that reflects drift severity. |
| `external_event:github_webhook` | `ingest.rs` | Normalized from a `POST /v1/ingest` payload with `source: "github_webhook"`. Always `decision = "allow"`, `risk_score = 0`. |
| `external_event:openai_trace` | `ingest.rs` | Normalized from a `POST /v1/ingest` payload with `source: "openai_trace"`. Always `decision = "allow"`, `risk_score = 0`. |

---

## Example events

### `authorize_decision` — allow

```json
{
  "event_id": "e7c2a1d4-1234-4000-8000-abcdef012345",
  "occurred_at": "2026-06-16T10:00:00Z",
  "tenant_id": "tenant_acme",
  "kind": "authorize_decision",
  "agent_id": "a9f1b2c3-dead-beef-cafe-000000000001",
  "decision": "allow",
  "tool": "filesystem",
  "action": "read_file",
  "resource": "/home/user/report.pdf",
  "risk_score": 10,
  "reason": "Policy evaluation complete.",
  "run_id": "run-abc123",
  "trace_id": "trace-xyz789",
  "matched_policies": ["policy1"]
}
```

### `authorize_decision` — deny (confused-deputy / untrusted provenance)

```json
{
  "event_id": "f3a8c2b1-0000-4000-8000-000000000002",
  "occurred_at": "2026-06-16T10:01:00Z",
  "tenant_id": "tenant_acme",
  "kind": "authorize_decision",
  "agent_id": "a9f1b2c3-dead-beef-cafe-000000000001",
  "decision": "deny",
  "tool": "github",
  "action": "merge_pull_request",
  "resource": "org/repo",
  "risk_score": 90,
  "reason": "Mutating action denied: untrusted_external source cannot trigger state mutation (confused-deputy defense).",
  "run_id": null,
  "trace_id": null,
  "matched_policies": ["policy3"]
}
```

### `authorize_decision` — require_approval

```json
{
  "event_id": "1a2b3c4d-0000-4000-8000-000000000003",
  "occurred_at": "2026-06-16T10:02:00Z",
  "tenant_id": "tenant_acme",
  "kind": "authorize_decision",
  "agent_id": "a9f1b2c3-dead-beef-cafe-000000000001",
  "decision": "require_approval",
  "tool": "github",
  "action": "merge_pull_request",
  "resource": "org/repo#42",
  "risk_score": 75,
  "reason": "Human approval required for high-risk mutating action.",
  "run_id": "run-def456",
  "trace_id": null,
  "matched_policies": ["policy2"]
}
```

### `replay_attempt`

```json
{
  "event_id": "dead1234-0000-4000-8000-000000000004",
  "occurred_at": "2026-06-16T10:03:00Z",
  "tenant_id": "tenant_acme",
  "kind": "replay_attempt",
  "agent_id": "a9f1b2c3-dead-beef-cafe-000000000001",
  "decision": "deny",
  "tool": "replay_nonce_reused",
  "action": "replay_nonce_reused",
  "resource": null,
  "risk_score": 100,
  "reason": "Replay-nonce reused: nonce 'abc123' was already consumed within the replay window.",
  "run_id": null,
  "trace_id": null,
  "matched_policies": []
}
```

### `mcp_manifest_drift`

```json
{
  "event_id": "cafe0000-0000-4000-8000-000000000005",
  "occurred_at": "2026-06-16T10:04:00Z",
  "tenant_id": "tenant_acme",
  "kind": "mcp_manifest_drift",
  "agent_id": "unknown",
  "decision": "deny",
  "tool": "github-mcp",
  "action": "drift_detected",
  "resource": "github-mcp",
  "risk_score": 80,
  "reason": "MCP manifest hash mismatch: expected sha256:abc… got sha256:def…",
  "run_id": null,
  "trace_id": null,
  "matched_policies": []
}
```

### `external_event:github_webhook`

```json
{
  "event_id": "fedc9876-0000-4000-8000-000000000006",
  "occurred_at": "2026-06-16T10:05:00Z",
  "tenant_id": "tenant_acme",
  "kind": "external_event:github_webhook",
  "agent_id": "alice",
  "decision": "allow",
  "tool": "github",
  "action": "opened",
  "resource": "org/repo",
  "risk_score": 0,
  "reason": "ingested via /v1/ingest",
  "run_id": null,
  "trace_id": null,
  "matched_policies": []
}
```

---

## Detection rules (Phase 1)

Detection rules evaluate each `AseEvent` and produce **alerts**. Rules are
YAML-driven (`gateway/src/rule_dsl.rs`). The embedded defaults ship in
`DEFAULT_RULES_YAML`; tenants may add custom rules via
`POST /v1/soc/rules`.

### Default rules

| Rule key | Alert name | Severity | Trigger condition |
| -------- | ---------- | -------- | ----------------- |
| `confused_deputy_block` | `confused_deputy_block` | HIGH | `decision=deny` + `mutates_state=true` + `source_trust` ∈ {`untrusted_external`, `malicious_suspected`} |
| `approval_required_surface` | `approval_required_surface` | INFO | `decision=require_approval` (any action) |
| `critical_deny_risk_score` | `critical_deny` | HIGH | `risk_score ≥ 100` |
| `critical_deny_policy` | `critical_deny` | HIGH | `matched_policies` contains `mcp_unknown_tool` or `critical` |
| `replay_attempt` | `replay_attempt` | HIGH | `kind=replay_attempt` |
| `mcp_manifest_drift_high` | `mcp_manifest_drift` | HIGH | `kind=mcp_manifest_drift` + `risk_score ≥ 75` |
| `mcp_manifest_drift_medium` | `mcp_manifest_drift` | MEDIUM | `kind=mcp_manifest_drift` + `40 ≤ risk_score ≤ 74` |
| `mcp_manifest_drift_low` | `mcp_manifest_drift` | LOW | `kind=mcp_manifest_drift` + `risk_score ≤ 39` |

### Behavioral baseline rules (SOC-007)

Emitted by `gateway/src/baseline.rs` after per-agent frequency tracking.

| Alert rule | Severity | Trigger condition |
| ---------- | -------- | ----------------- |
| `behavioral_anomaly_new_tool` | INFO | Agent calls a `(tool, action)` pair it has never used before. |
| `behavioral_anomaly_rate` | HIGH | Agent's action rate in the current time window exceeds 3× its historical mean. |

---

## Correlation rules (Phase 3)

The stateful correlator (`gateway/src/correlate.rs`) groups events into
**incidents** when multi-event patterns are detected.

| Incident kind | Severity | Pattern |
| ------------- | -------- | ------- |
| `deny_storm` | HIGH | ≥ 5 `deny` decisions from the same `(tenant, agent)` within a 60-second sliding window. |
| `runaway` | HIGH | ≥ 10 actions from the same `(tenant, agent)` within 30 seconds, regardless of decision. |
| `repeated_approval` | MEDIUM | ≥ 3 `require_approval` decisions for the same `(tenant, agent, tool, action)` within 10 minutes. |
| `trust_escalation` | HIGH | A `deny` event follows a `require_approval` event for the same `(tenant, agent)` within 30 seconds — suggests the agent re-tried a denied action via an escalation path. |

---

## Versioning

The `AseEvent` schema is **v0** (implicit). When a breaking field change is
needed:

1. Bump the schema version in a new field, e.g. `"schema_version": "v1"`.
2. All existing consumers and the DB indexer must handle both versions during
   the migration window.
3. Update `DEFAULT_RULES_YAML` conditions to reference the new field where
   needed.
4. Update this document and the cross-language corpus vector files
   (`tests/canonical_action_vectors.json`, `tests/receipt_chain_vectors.json`)
   if the event feeds into the hash chain.

Non-breaking additions (new optional fields, new `kind` values, new rule
keys) do not require a version bump; consumers that do not recognize a new
field ignore it.

---

## Producing a valid AseEvent (SDK / integration)

For integrations that feed external events via `POST /v1/ingest`, the
gateway normalizes the raw payload — you never construct an `AseEvent`
directly. For SDK contributors extending the gateway, the minimum required
fields are:

```rust
AseEvent {
    event_id:        Uuid::new_v4().to_string(),
    occurred_at:     Utc::now().to_rfc3339(),
    tenant_id:       tenant_id.to_string(),  // required — every consumer scopes by this
    kind:            "authorize_decision".to_string(),
    agent_id:        agent.id.clone(),
    decision:        "allow".to_string(),
    tool:            tool_call.tool.clone(),
    action:          tool_call.action.clone(),
    resource:        tool_call.resource.clone(),
    risk_score:      0,
    reason:          "Policy evaluation complete.".to_string(),
    run_id:          None,
    trace_id:        None,
    matched_policies: vec![],
}
```

Emit via `state.events.emit(event)` — the call is non-blocking and never
propagates an error to the caller.
