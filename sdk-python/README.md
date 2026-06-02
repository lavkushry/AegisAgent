# AegisAgent Python SDK

Client and `@protect_tool` decorator for [AegisAgent](https://github.com/lavkushry/AegisAgent) — the integrity layer for AI agent actions.

The SDK is the **enforcement point inside your agent's trust boundary**. It:

- intercepts a protected tool call and authorizes it against the gateway,
- **fails closed** on deny, on `action_hash` mismatch (approve-then-swap), on an expired approval, and when the gateway is unreachable for a mutating/high-risk action,
- consumes single-use approvals atomically before executing (replay defense),
- ships a canonicalization scheme (`aegis-jcs-1`) that is byte-identical to the Rust gateway, so the hash a human approved is the hash that runs.

## Install

```bash
pip install -e .            # from this directory
pip install -e ".[dev]"     # with black for formatting checks
```

## Usage

```python
from aegisagent import protect_tool

@protect_tool(tool_key="github", action_key="merge_pull_request")
def merge_pr(repo: str, number: int) -> str:
    ...
```

If the gateway denies the action, `AegisAuthorizationDenied` is raised and the
wrapped function never runs. If a human approval is required, the call blocks
until the approval is decided, then verifies the approved action hash matches
the action about to execute before proceeding.

## Verify receipts

```bash
aegis-verify-receipts receipts.json
```

Recomputes the per-tenant hash chain and reports whether the evidence is intact.

See the [main README](https://github.com/lavkushry/AegisAgent) and
[`docs/action-receipt-spec.md`](https://github.com/lavkushry/AegisAgent/blob/main/docs/action-receipt-spec.md)
for the full picture.

## License

MIT — see [LICENSE](https://github.com/lavkushry/AegisAgent/blob/main/LICENSE).
