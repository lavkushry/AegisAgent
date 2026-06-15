# Runtime authorization API: `/v1/authorize` deep-dive

`POST /v1/authorize` is the core of AegisAgent: every tool call an SDK
intercepts is sent here before it executes. This page documents the request
and response schema, how a decision is reached, how the action hash and
trust-provenance gating work, what happens on error, and what latency to
expect.

For the operational counterpart — what happens when a dependency is
unavailable — see [Fail-closed behavior guide](fail-closed-behavior.md).

## Request

```
POST /v1/authorize
Authorization: Bearer <agent_token>
X-Aegis-Tenant-ID: <tenant_uuid>
Content-Type: application/json
```

```json
{
  "request_id": "optional-idempotency-key",
  "agent": { "id": "agent-uuid-or-key", "environment": "production" },
  "user": { "id": "user-123", "role": "operator" },
  "tool_call": {
    "tool": "github",
    "action": "merge_pr",
    "resource": "repo:acme/widgets#pr-42",
    "mutates_state": true,
    "parameters": { "branch": "main", "pr_number": 42 }
  },
  "context": {
    "source_trust": "semi_trusted_customer",
    "contains_sensitive_data": false
  },
  "trace": { "run_id": "run_abc123", "trace_id": "0123456789abcdef0123456789abcdef" },
  "callback": { "url": "https://example.com/slack/callback", "secret": "whsec_..." },
  "nonce": "optional-replay-protection-nonce",
  "timestamp": "2026-06-15T12:00:00Z"
}
```

### Field reference

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | string | no | **Idempotency key.** A repeat `(agent, request_id)` returns the *original* decision/approval verbatim instead of re-evaluating policy or writing duplicate audit rows. |
| `agent.id` | string | yes | Agent identifier as known to the SDK; the gateway resolves the *actual* agent via the `Authorization` Bearer token, not this field. |
| `agent.environment` | string | yes | Free-form environment label (e.g. `production`, `staging`). |
| `user` | object | no | The human/principal on whose behalf the agent is acting, if known. |
| `tool_call.tool` | string | yes | Tool key (e.g. `github`, `slack`, or an MCP server key). |
| `tool_call.action` | string | yes | Action key within the tool (e.g. `merge_pr`). |
| `tool_call.resource` | string \| null | no | Target resource identifier. `null`/absent is part of the canonical action and the hash. |
| `tool_call.mutates_state` | bool | yes | Whether this action changes state. Drives risk defaults, trust-provenance gating, and the audit-writer fail-closed check. |
| `tool_call.parameters` | object | yes | Arbitrary JSON parameters for the call. **Strip secrets/large payloads client-side before sending** — only what policies need. |
| `context.source_trust` | string | yes | One of the 6 trust-provenance levels (see below). |
| `context.contains_sensitive_data` | bool | no | Hint for policy evaluation; defaults `false`. |
| `trace.run_id` / `trace.trace_id` | string | no | Propagated for cross-system correlation (OpenTelemetry trace ID). |
| `callback` | object | no | Registers a webhook for a `require_approval` decision. `secret` is hashed (`sha256`) before storage as `callback_secret_hash`; the plaintext is never persisted. |
| `nonce` / `timestamp` | string | no | Opt-in replay protection (#1306): a repeated `(tenant, agent, nonce)`, or a `timestamp` more than 5 minutes old/in the future, is rejected with `409`. This is distinct from `request_id` — `nonce` *rejects* a repeat; `request_id` *replays* the original result. |

## Response

```json
{
  "decision_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "decision": "require_approval",
  "risk_score": 75,
  "risk_level": "high",
  "reason": "Mutating action on 'github' requires human approval per policy.",
  "matched_policies": ["require_approval_mutating_github"],
  "approval": {
    "approval_id": "893c5d64-1234-4321-9988-aabbccddeeff",
    "status": "pending",
    "approver_group": "platform-leads",
    "expires_at": "2026-06-15T12:15:00Z",
    "action_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d"
  }
}
```

| Field | Notes |
|---|---|
| `decision_id` | UUID for this evaluation; appears in `/v1/decisions/:id` and `/v1/audit/events`. |
| `decision` | `"allow"`, `"deny"`, or `"require_approval"` — see [Decision types](#decision-types). |
| `risk_score` / `risk_level` | Derived from the registered tool/action's configured risk (`low`→10, `medium`→40, `high`→75, `critical`→95), or MCP tool risk for MCP calls. |
| `reason` | Human-readable explanation, safe to display to an operator. |
| `matched_policies` | Cedar policy IDs (or synthetic markers like `agent_frozen`, `mcp_unknown_tool`, `critical_risk_requires_approval`) that produced the decision — useful for debugging policy precedence. |
| `approval` | Present only when `decision == "require_approval"`. `action_hash` is the value the SDK **must** match before executing (see below). |

## Decision types

`/v1/authorize` returns exactly one of three values in `decision`:

- **`allow`** — execute immediately. No approval is created.
- **`deny`** — never execute. The SDK raises `AegisAuthorizationDenied`
  (`PermissionError` in the decorator). `matched_policies` explains why —
  common markers include `registered_action_default_deny` (unregistered
  action), `mcp_unknown_tool` / `mcp_server_quarantined`, `agent_frozen` /
  `agent_revoked`, and Cedar `forbid` policy IDs for untrusted/malicious
  provenance.
- **`require_approval`** — block until a human approves (or the approval
  expires). The response includes an `approval` object; the SDK polls
  `GET /v1/approvals/:id` until `status` is `approved`, `rejected`, or
  `EXPIRED`.

**"Quarantine" and "redact" are not `decision` values.** Quarantine is
enforced as a *state* on an agent (`frozen`/`revoked` via
`POST /v1/agents/:id/freeze|revoke`) or an MCP server
(`POST /v1/mcp/servers/:server_key/quarantine`) — once quarantined, every
subsequent `/v1/authorize` call for that principal/server returns `deny`
with a `matched_policies` marker (`agent_frozen`, `agent_revoked`,
`mcp_server_quarantined`) rather than a distinct decision string. Redaction
of sensitive fields happens at the logging/receipt layer (`context.
contains_sensitive_data`), not as an authorize decision.

## Policy evaluation flow

```
SDK                                Gateway (/v1/authorize)
───                                ───────────────────────
compute expected_action_hash
  (aegis-jcs-1 over tool_call)
        │
        ▼
POST /v1/authorize ───────────────▶ 1. Resolve agent via Bearer token
                                       (tenant-scoped) → 401 if invalid
                                    2. Replay/nonce + idempotency
                                       (request_id) checks
                                    3. Rate limit / quota checks
                                    4. agent.status frozen/revoked?
                                       → deny, matched_policies=[agent_<status>]
                                    5. Look up registered action
                                       (risk_level, risk_score,
                                       approval_required, default_decision)
                                    6. MCP path only: server quarantined?
                                       tool unknown/unapproved?
                                       → deny, mcp_* markers
                                    7. Cedar policy_engine.authorize(
                                         principal=Agent::<id>,
                                         action=Action::"tool_call",
                                         resource=ToolAction::<tool>_<action>,
                                         context={trust_level, mutates_state,
                                                   contains_sensitive_data,
                                                   resource_base_branch})
                                       → allow | deny | (allow + @decision(
                                         "require_approval") annotation)
                                    8. Post-processing overrides:
                                       - risk_level == "critical" and
                                         decision == "allow"
                                         → require_approval
                                       - agent.force_approval (post-incident)
                                         → require_approval
                                    9. Audit-writer preflight: SOC event
                                       channel full + high-risk/mutating?
                                       → deny, audit_writer_unavailable
                                   10. write_decision_and_audit():
                                       persist DecisionRecord, emit ASE event
                                       (async SOC pipeline)
                                   11. require_approval only: create Approval
                                       row bound to action_hash, expires_at,
                                       optional callback
        ◀────────────────── AuthorizeResponse {decision, risk_*, reason,
                              matched_policies, approval?}
        │
  decision == allow
        │──▶ execute tool
  decision == deny
        │──▶ raise AegisAuthorizationDenied — never executes
  decision == require_approval
        │──▶ poll GET /v1/approvals/:id until approved
        │──▶ recompute action_hash for the about-to-run action
        │──▶ compare to approval.action_hash
        │       mismatch → FAIL CLOSED (PermissionError), never executes
        │       match → POST /v1/approvals/:id/consume (single-use) → execute
```

## Trust-provenance integration

`context.source_trust` is one of six deterministic levels (most → least
trusted):

1. `trusted_internal_signed`
2. `trusted_internal_unsigned`
3. `semi_trusted_customer`
4. `untrusted_external`
5. `malicious_suspected`
6. `unknown`

The gateway passes this through verbatim as `context.trust_level` to Cedar.
Classifiers upstream of the SDK may only **tighten** this label (move it
down the list), never loosen it. The base policy pack
(`gateway/policies.cedar`) encodes:

- `mutates_state == true` **and** `trust_level` is `trusted_internal_*` →
  evaluated normally (no special gating).
- `mutates_state == true` **and** `trust_level` is `semi_trusted_customer`
  or `unknown` → `require_approval`, regardless of what the action itself
  would otherwise resolve to.
- `mutates_state == true` **and** `trust_level` is `untrusted_external` or
  `malicious_suspected` → `forbid` (hard deny).

This is the **confused-deputy defense**: a prompt-injected instruction
arriving via an untrusted channel cannot cause a mutating tool call to
execute, no matter how the request is worded — only the *source* of the
triggering content matters. See `gateway/policies.cedar` for the exact
rules.

## Action hash computation (`aegis-jcs-1`)

Both the SDK (before calling `/v1/authorize` and again before executing
after approval) and the gateway (when binding an approval) compute:

```
action_hash = sha256_hex(canonicalize({
  "tool": tool_call.tool,
  "action": tool_call.action,
  "resource": tool_call.resource,   // or null if absent
  "mutates_state": tool_call.mutates_state,
  "parameters": tool_call.parameters,
}))
```

`canonicalize` is the **`aegis-jcs-1`** scheme:

- object keys sorted by Unicode code point
- compact separators (`","`/`":"`, no spaces)
- raw UTF-8 — non-ASCII is **not** escaped to `\uXXXX`
- non-finite floats (`NaN`/`Infinity`) are rejected

This must be **byte-identical** across the Python, Go, and TypeScript SDKs
and the Rust gateway — locked by `tests/canonical_action_vectors.json` and
a cross-language CI gate. Any divergence would silently break the
approval-integrity guarantee, so never modify canonicalization without
bumping the scheme version and updating all four implementations together.

This hash is the basis of the **approve-then-swap defense (T-A1/T-A2)**: if
the action about to execute hashes to anything other than the
`action_hash` bound to its approval, the SDK fails closed and the tool never
runs.

## Error cases and fail-closed behavior

Every error case for `/v1/authorize` — unreachable gateway, database error,
unregistered agent/tool, frozen agent, expired/mismatched approval, full
audit pipeline, untrusted provenance, etc. — is enumerated with its exact
behavior in the [Fail-closed behavior guide](fail-closed-behavior.md). The
short version: **mutating or high-risk actions deny on any ambiguity**;
only non-mutating, low-risk reads may ever proceed without a fully verified
chain.

## Code examples

### Python

```python
from aegisagent import protect_tool, AegisAuthorizationDenied

@protect_tool(tool_key="github", action_key="merge_pr")
def merge_pr(branch: str, pr_number: int) -> str:
    ...  # actual GitHub API call

try:
    merge_pr(branch="main", pr_number=42)
except AegisAuthorizationDenied as e:
    print(f"Denied: {e}")
```

`@protect_tool` computes `expected_action_hash`, calls
`client.authorize(...)`, and on `require_approval` blocks polling
`GET /v1/approvals/:id` before re-checking the hash and calling
`POST /v1/approvals/:id/consume` prior to executing `merge_pr`.

### Go

```go
client := aegis.NewClient(aegis.ClientOptions{
    BaseURL:    "http://127.0.0.1:8080",
    AgentToken: agentToken,
    TenantID:   tenantID,
})

err := aegis.Protect(client, aegis.AuthorizeRequest{
    Tool:          "github",
    Action:        "merge_pr",
    MutatesState:  true,
    Parameters:    map[string]any{"branch": "main", "pr_number": 42},
    SourceTrust:   "trusted_internal_unsigned",
}, func() error {
    return mergePR("main", 42) // executes only on allow / approved
})
```

### TypeScript

```ts
import { AegisClient, protect } from "@aegisagent/sdk";

const client = new AegisClient({
  baseUrl: "http://127.0.0.1:8080",
  agentToken,
  tenantId,
});

await protect(
  client,
  {
    tool: "github",
    action: "merge_pr",
    mutatesState: true,
    parameters: { branch: "main", prNumber: 42 },
  },
  async () => mergePR("main", 42) // executes only on allow / approved
);
```

## Latency expectations

The in-process `/v1/authorize` hot path meets:

- **p50 < 10ms**
- **p95 < 50ms**
- **p99 < 100ms**

Cedar policy evaluation itself targets **<75ms** even for tenants with
custom policy sets. See
[`performance-baseline.md`](performance-baseline.md) for the full
methodology (criterion benchmark against a real SQLite-backed `AppState`,
100 agents / 1000 prior decisions seeded) and HTTP-level overhead notes.
