# Flow: Known Agent Action

**Status: ✅ Implemented end-to-end.** The canonical happy(ish) path — every SDK-protected tool call takes this route.

```mermaid
sequenceDiagram
    autonumber
    participant Code as Developer code
    participant SDK
    participant GW as Gateway /v1/authorize
    participant PE as Policy engine
    participant H as Approver
    participant T as Tool
    participant SOC
    Code->>SDK: merge_pr(repo, 57)  [wrapped]
    SDK->>SDK: canonicalize (aegis-jcs-1) → action_hash
    SDK->>GW: POST /v1/authorize {tool_call, action_hash, context}
    GW->>GW: tenant auth, rate/quota, agent status, identifier normalization
    GW->>PE: Cedar(principal, action, resource, context{trust, mutates_state, risk})
    alt allow
        PE-->>GW: allow
        GW-->>SDK: decision=allow
        SDK->>T: execute
    else require_approval
        PE-->>GW: require_approval
        GW-->>SDK: approval_id (action frozen + hash-bound)
        H->>GW: approve exact frozen action
        SDK->>GW: POST /v1/approvals/:id/consume (single-use)
        SDK->>SDK: re-check hash == approved hash
        SDK->>T: execute
    else deny
        PE-->>GW: deny
        GW-->>SDK: decision=deny → exception, tool never runs
    end
    GW->>GW: decision + audit row; receipt appended to chain
    GW-->>SOC: async event → detect/correlate/respond
```

## Step-by-step with code

| # | Step | Code |
|---|---|---|
| 1 | Developer wraps the function | `@protect_tool` — `sdk-python/aegisagent/decorator.py`, `sdk-go/aegis/protect.go`, `sdk-typescript/src/protect.ts` |
| 2 | Canonicalize + hash | `sdk-python/aegisagent/canon.py` ↔ gateway `src/canon/` (byte parity: `tests/canonical_action_vectors.json`) |
| 3 | Authorize request | `POST /v1/authorize` → `src/src/routes/authorize.rs` |
| 4 | Preflight | `TenantId` extractor, `RateLimiter`/`QuotaManager`, agent status check, `normalize_tool_identifier` (`routes/mod.rs`) — plus optional admission webhook (#1143), replay-nonce dedup (#1306), timestamp staleness check |
| 5 | Registry lookup | skill/action metadata (`SkillActionCache` → `db::get_skill_action`); unknown tool → **deny** |
| 6 | Policy | `lib/policy/src/cedar.rs` + `trust_chain.rs` + `risk.rs` — allow / deny / `@decision("require_approval")` |
| 7 | Approval branch | [../components/Approval_Engine.md](../components/Approval_Engine.md) |
| 8 | Execute | only in developer code, only after a valid decision — the SDK raises on deny/mismatch/expiry/unreachable |
| 9 | Persist | decision + audit (`write_decision_and_audit`, batched audit #1315), receipt append (`routes/authorize_receipts.rs`) |
| 10 | SOC | `EventSink` (`lib/soc/src/events.rs`) → `lib/soc` pipeline → alerts/incidents/containment |

## Latency shape

Inline plane targets < 75 ms: hot-path caches (skill metadata, risk weights, canonical-hash cache), heartbeat debouncing (#1511), deferred best-effort writes (#1512). The SOC plane is fully out-of-band.

## Failure modes (all fail closed)

Gateway unreachable (mutating/high-risk) → SDK refuses · unknown agent/tool → deny · stale timestamp/replayed nonce → reject · hash mismatch at consume → refuse · receipt write failure for protected decision → refuse.

## Try it

`python3 examples/integrity_demo.py` (zero-setup) · `python3 examples/mock_server.py` (approval loop) · [../quickstart.md](../quickstart.md)

## Related docs

[../Last_Mile_System_Walkthrough.md](../Last_Mile_System_Walkthrough.md) · [../runtime-authorization-api.md](../runtime-authorization-api.md) · [../fail-closed-behavior.md](../fail-closed-behavior.md) · [Prompt_To_Action_Lineage.md](Prompt_To_Action_Lineage.md)
