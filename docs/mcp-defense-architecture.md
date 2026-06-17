# AegisAgent — MCP Defense Architecture

**Issue:** [#1338](https://github.com/lavkushry/AegisAgent/issues/1338)
**Read first (general trust boundaries):** [`security-model.md`](security-model.md), specifically boundary **B5** (Gateway → External Tool / MCP Server).

This document describes how AegisAgent treats the Model Context Protocol (MCP) as an untrusted-supply-chain surface: every MCP server is registered, every tool it advertises is pinned to a hashed manifest, drift is detected and auto-contained, and unknown or unapproved tools fail closed. There is no separate "MCP proxy" process — MCP defense is built directly into the gateway's `/v1/authorize` hot path and the `mcp_servers`/`mcp_tools` tables (`gateway/src/db.rs`, `gateway/src/routes.rs`).

---

## 1. Threat model: why MCP needs its own gate

MCP servers are typically third-party or community-maintained processes an agent's runtime connects to for extra tools (filesystem, GitHub, databases, SaaS APIs). Unlike a tool AegisAgent's operator hand-registers and risk-tiers themselves, an MCP server's tool *manifest* — the list of tools, their names, descriptions, and risk metadata — is supplied by that external process and can change between deployments, versions, or compromises.

This creates a supply-chain attack surface distinct from the confused-deputy / indirect-prompt-injection class the trust-provenance gate defends against (see [`security-model.md`](security-model.md) §1, boundary B5):

- **Manifest drift**: an MCP server silently adds a new tool, widens an existing tool's capability, or removes a tool — any of which can happen without an operator re-running discovery review to notice.
- **Unknown tool invocation**: an agent (or a confused/compromised agent) calls an MCP tool that was never discovered/registered at all.
- **Unapproved tool invocation**: a tool was discovered but an operator hasn't yet reviewed and approved it.
- **Compromised server**: the MCP server itself starts returning a different, malicious manifest on a later discovery call.

AegisAgent's answer: **pin the manifest hash on first discovery, fail closed on every gap, and require an explicit operator action to re-trust a server after drift.**

---

## 2. Lifecycle: register → discover → pin → gate

```text
1. POST /v1/mcp/servers                 Operator registers the MCP server (trust_level, endpoint, transport)
2. POST /v1/mcp/servers/:key/tools      Discovery: server's tool manifest is submitted
                                           → upserted into mcp_tools (one row per tool)
                                           → manifest hash computed + snapshotted
                                           → first discovery: hash pinned, no drift possible yet
                                           → later discovery: hash compared against the pin
3. POST .../tools/:tool_key/approve     Operator reviews and approves each discovered tool
                                           (tools default to NOT approved — fail closed)
4. POST /v1/authorize (tool="mcp:<key>") Every call gated inline: server status, tool status, manifest pin
```

Steps 1–3 are administrative (`gateway/src/routes.rs`: `register_mcp_server`, `discover_mcp_tools`, `approve_mcp_tool`/`disable_mcp_tool`). Step 4 is the enforcement hot path every `/v1/authorize` call for an MCP tool passes through, described in §4.

### 2.1 Manifest hashing and pinning

`discover_mcp_tools` computes `compute_mcp_manifest_hash(&payload.tools)` — a deterministic hash over the submitted tool list — on every discovery call:

- **First discovery** for a server: `db::get_mcp_server_manifest_hash` returns an empty pin, so the new hash is simply pinned via `db::set_mcp_server_manifest_hash`. No drift event fires (there is nothing to drift *from* yet).
- **Subsequent discovery**: the new hash is compared against the pin. A mismatch fires drift handling (§3). Whether or not drift fired, the new hash always becomes the pin afterward — each distinct manifest change alerts exactly once, not on every poll.
- Every discovery call additionally writes a full manifest **snapshot** (`db::insert_mcp_manifest_snapshot`) — not just the hash — so a drift event can be diffed against the prior version's actual tool list, not just told "something changed."

### 2.2 Tools default to unapproved

`discover_mcp_tools` registers each discovered tool with `default_decision = "require_approval"` (if the manifest marks it `approval_required`) or `"policy"` otherwise, but **the tool's `status` itself starts unapproved** — `approve_mcp_tool`/`disable_mcp_tool` are the only way to move it to `"approved"`. A discovered-but-unreviewed tool is denied at the gate (§4.2), not silently allowed because it parsed successfully.

---

## 3. Drift detection and auto-containment

When a discovery call's computed manifest hash differs from the pinned value, `discover_mcp_tools` (`gateway/src/routes.rs`):

1. **Classifies the drift** via `classify_manifest_drift(old_tools, new_tools)` (#1336), diffing the two most recent manifest snapshots:
   - `tool_added` / `tool_removed` → **high** severity (a tool appearing or disappearing is the strongest hijack signal)
   - `tool_modified` (description/risk/mutates_state changed on an existing tool) → **medium** severity
   - anything else that still hashes differently → **low** severity
2. **Emits an SOC event** (`kind: "mcp_manifest_drift"`, `decision: "flag"` — not `"deny"`, since drift is a server-integrity signal kept out of the deny-storm correlation engine, design law 1) carrying the server key, old/new hash, classification, and diff — never the raw tool payload.
3. **Auto-quarantines the server** (`db::set_mcp_server_status(... "quarantined")`) and writes a dedicated `mcp_server_auto_quarantined` audit event distinct from a manually-triggered `mcp_server_quarantined` event, so an operator reviewing the audit trail can tell *why* a server went into quarantine.
4. **Re-pins** the new hash regardless of the drift outcome, so the next discovery call diffs against this version, not the stale one.

This is **fail-closed by construction**: quarantining happens at discovery time, and the gate in §4.1 denies every tool call from a quarantined server on the very next `/v1/authorize` call — there is no window where a drifted manifest is silently trusted pending review. An operator must explicitly call `POST /v1/mcp/servers/:server_key/restore` after investigating out-of-band.

The default YAML detection rules (`rule_dsl::default_rules()`, see [`event-schema.md`](event-schema.md)) include three severity-banded rules keyed on this event — `mcp_manifest_drift_high` (`min_risk_score: 75`), `_medium` (`40-74`), `_low` (`<40`) — so the live SOC pipeline surfaces drift at the right urgency without an operator having to read raw event payloads.

---

## 4. Enforcement: the `/v1/authorize` gate for MCP calls

Every `/v1/authorize` call whose `tool_call.tool` resolves to an MCP server key (`mcp_server_key_from_tool`, matching the `mcp:<server_key>` convention) passes through three fail-closed checks, in order, **before** Cedar policy evaluation ever runs:

### 4.1 Server-status gate

```text
db::get_mcp_server_by_key(...).status == "quarantined"
    → deny, matched_policies = ["mcp_server_quarantined"], risk_score = 100 (critical)
```

A quarantined server — whether quarantined manually or auto-quarantined on drift (§3) — denies **every** tool call it advertises, regardless of any individual tool's approved status. Without this server-level gate, a quarantine event would be recorded but not actually enforced on the hot path.

### 4.2 Tool-status gate

```text
db::get_mcp_tool_by_key(...).status != "approved"
    → deny, matched_policies = ["mcp_tool_status"]
```

A tool that was discovered but not yet approved (or has been explicitly disabled) is denied — fail closed on "haven't reviewed it yet," not fail open.

### 4.3 Unknown-tool gate

```text
db::get_mcp_tool_by_key(...) == None
    → deny, matched_policies = ["mcp_unknown_tool"], risk_score = 100 (critical)
```

A tool call naming an action that was never discovered for this server at all — including an attempt to disguise the `mcp:` prefix to dodge the `mcp_server_key_from_tool` match — is denied at maximum risk score, distinct from the merely-unapproved case in §4.2.

Only after all three checks pass does the call proceed to Cedar policy evaluation and the rest of the normal `/v1/authorize` pipeline (trust-provenance gate, risk scoring, approval routing). The `critical_deny_policy` default detection rule additionally watches for `matched_policy_contains: [mcp_unknown_tool, critical]` so an unknown-MCP-tool attempt also surfaces on the live SOC feed, not just as a single denied decision.

---

## 5. API surface

| Endpoint | Purpose |
|---|---|
| `POST /v1/mcp/servers` (register) | Register an MCP server: `server_key`, `name`, `transport`, `trust_level`, `endpoint` |
| `GET /v1/mcp/servers` | List servers with `status` and pinned `manifest_hash` |
| `GET\|PUT /v1/mcp/servers/:server_key` | Read/update server metadata |
| `POST /v1/mcp/servers/:server_key/quarantine` | Manually quarantine (denies all of that server's tool calls immediately) |
| `POST /v1/mcp/servers/:server_key/restore` | Reactivate after operator review (manual or post-drift) |
| `POST /v1/mcp/servers/:server_key/tools` (discover) | Submit the tool manifest; triggers hashing, pinning, and drift detection |
| `GET /v1/mcp/servers/:server_key/tools` | Read the current discovered tool manifest |
| `POST .../tools/:tool_key/approve` | Move a discovered tool to `"approved"` |
| `POST .../tools/:tool_key/disable` | Move a tool to `"disabled"` (denied at the gate, same as never-approved) |

All routes are tenant-scoped (`TenantId` extractor, parameterized SQLx) — see [`security-model.md`](security-model.md) boundary B7.

---

## 6. Audit trail

Every state transition in this lifecycle writes a distinct, queryable `audit_events` row (`GET /v1/audit/events`):

| `event_type` | Written by | When |
|---|---|---|
| `mcp_tool_discovered` | `discover_mcp_tools` | Once per tool, every discovery call |
| `mcp_server_quarantined` / `mcp_server_active` | `update_mcp_server_quarantine` | Manual quarantine/restore via the API |
| `mcp_server_auto_quarantined` | `discover_mcp_tools` (drift handling) | Automatic, on manifest drift, carrying classification + diff |

Combined with the `mcp_manifest_drift` SOC event stream (§3) and the evidence graph's `mcp_server` node type (`graph.rs`, #1271), an operator can reconstruct the full chain — *which* manifest changed, *what* changed, *when* it was auto-quarantined, and *which* denied `/v1/authorize` calls happened while it was quarantined — without re-deriving it from raw event payloads.

---

## 7. What this does not cover

- **MCP response inspection** (validating tool *output*, not just gating the call) is a separate, not-yet-built concern (#1333) — AegisAgent is pre-execution-only today; it gates whether a call happens, not what a tool returns.
- **A standalone MCP proxy process** does not exist. All MCP defense lives in the gateway's existing `/v1/authorize` path and `mcp_servers`/`mcp_tools` tables — there is nothing to deploy or operate separately.
- **Transport-level security** (TLS to the MCP server, credential management for the `endpoint`) is the operator's responsibility; AegisAgent's gate operates on the manifest and call metadata, not the wire transport.
