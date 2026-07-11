# Onboarding: SDK / Integration Developer

**Goal:** protected tool calls in ~10 minutes; understand the fail-closed contract so you never accidentally weaken it.

> **Status:** Python and TypeScript integrity paths are production-ready; Go is beta with documented capture-parity gaps. Check [SDK Parity Status](../sdk-parity-status.md).

## Overview

The SDK is the cooperating enforcement point immediately before a tool call. Your responsibility is to preserve canonical action identity, deterministic decision handling, exact-action approval consume, secret redaction, and safe failure behavior across network errors and version changes.

## 1. Ten-minute integration (Python)

```bash
pip install aegisagent
export AEGIS_GATEWAY_URL=http://127.0.0.1:8080
export AEGIS_AGENT_TOKEN=...   # from POST /v1/agents/register
```

```python
from aegisagent import protect_tool, AegisAuthorizationDenied

@protect_tool(tool_key="github", action_key="merge_pr")
def merge_pr(repo: str, pr_number: int) -> str:
    ...

try:
    merge_pr("acme/app", 57)
except AegisAuthorizationDenied as e:
    print("blocked:", e)          # tool never ran
```

`allow` → runs immediately. `require_approval` → the decorator polls, then **consumes** the approval (single-use) and re-checks the hash before executing. `deny` → raises; nothing runs. Go: `sdk-go/aegis/protect.go`; TypeScript: `sdk-typescript/src/protect.ts` (parity gaps: [../sdk-parity-status.md](../sdk-parity-status.md)).

## 2. The contract you must not break

1. **Canonicalization is sacred.** `aegis-jcs-1` must stay byte-identical across Python/Go/TS/gateway. Any change must update all four + `tests/canonical_action_vectors.json` + `tests/receipt_chain_vectors.json`, or CI parity checks fail.
2. **Fail closed.** On hash mismatch, expired/consumed approval, or unreachable gateway (mutating/high-risk), the SDK refuses to execute. Never add a "proceed anyway" flag.
3. **Poll + consume, never just poll.** Executing on `status=approved` without `POST /approvals/:id/consume` bypasses single-use protection.
4. **Redact before transmit.** Strip secrets/PATs from parameters client-side; pass only what policies need.

## 3. Files to inspect

`sdk-python/aegisagent/`: `canon.py` (canonicalizer), `client.py` (HTTP + errors), `decorator.py` (the wrapper), `receipts.py`/`verify_receipts.py` (evidence), `cli.py` (the `aegis` CLI), `webhooks.py`, `evidence.py`. Mirrors: `sdk-go/{canon,aegis}/`, `sdk-typescript/src/`.

## 4. Testing your integration

Unit tests mock the network — never require a live gateway (`unittest.mock.patch` on `requests.post/get`; see `sdk-python/tests/` and `.claude/rules/sdk_testing.md` for canonical mock shapes: instant allow, instant deny, poll-then-approve). Integration: run the gateway (`docker compose up`) + `python3 examples/mock_server.py`.

```bash
python3 -m unittest discover -s sdk-python/tests   # 187 tests
cd sdk-go && go test ./...
cd sdk-typescript && npm ci && npx tsc --noEmit && npm test
```

## 5. Common mistakes

- Hand-serializing JSON for hashing (`json.dumps` defaults ≠ `aegis-jcs-1`) — always use the SDK's `canon`.
- Catching `AegisError` broadly and continuing — denial is a security decision, not an exception to swallow.
- Registering tools lazily in production — unknown tool = deny by design.
- Sending floats that may be `NaN`/`Infinity` — canonicalization rejects non-finite floats.

## 6. Read next

[../components/SDK.md](../components/SDK.md) (full guide) · [../flows/Known_Agent_Flow.md](../flows/Known_Agent_Flow.md) · [../fail-closed-behavior.md](../fail-closed-behavior.md) · [../runtime-authorization-api.md](../runtime-authorization-api.md)

## 7. Security and Failure Handling

- Treat unknown decision values, malformed responses, non-success status, and protected gateway failure as deny.
- Never log tokens, callback secrets, unredacted parameters, or canonical bytes containing secrets.
- Use bounded approval polling with deadline and backoff; always consume before execution.
- Preserve `root_trust_level` across agent hops and never loosen a source label.
- Version canonicalization and receipt verification changes through shared corpora before release.

## 8. Operations and Troubleshooting

When parity fails, compare exact UTF-8 bytes—not parsed JSON objects—against the shared vectors. When an approved call does not execute, inspect expiry, bound hash, consume status, tenant/agent identity, and clock skew. Do not add bypass flags; fix the integration or re-authorize the current action.

## 9. References

[SDK Component](../components/SDK.md) · [Canonicalization ADR](../adr/0003-aegis-jcs-1-canonicalization.md) · [Receipt Specification](../action-receipt-spec.md) · [Implementation Status](../Implementation_Status.md)
