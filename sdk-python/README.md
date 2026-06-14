# AegisAgent Python SDK

Client and `@protect_tool` decorator for [AegisAgent](https://github.com/lavkushry/AegisAgent) — the integrity layer for AI agent actions.

The SDK is the **enforcement point inside your agent's trust boundary**. It:

- intercepts a protected tool call and authorizes it against the gateway,
- **fails closed** on deny, on `action_hash` mismatch (approve-then-swap), on an expired approval, and when the gateway is unreachable for a mutating/high-risk action,
- consumes single-use approvals atomically before executing (replay defense),
- ships a canonicalization scheme (`aegis-jcs-1`) that is byte-identical to the Rust gateway and the Go/TypeScript SDKs, so the hash a human approved is the hash that runs.

## Install

```bash
pip install -e .            # from this directory
pip install -e ".[dev]"     # with black for formatting checks
pip install -e ".[async]"   # with httpx for the async client
```

## Usage

### Sync

```python
from aegisagent import protect_tool

@protect_tool(tool_key="github", action_key="merge_pull_request")
def merge_pr(repo: str, number: int) -> str:
    ...
```

### Async

```python
from aegisagent import async_protect_tool

@async_protect_tool(tool_key="github", action_key="merge_pull_request")
async def merge_pr(repo: str, number: int) -> str:
    ...
```

If the gateway denies the action, `AegisAuthorizationDenied` is raised and the
wrapped function never runs. If a human approval is required, the call blocks
until the approval is decided, then verifies the approved action hash matches
the action about to execute before proceeding.

## CLI tools

```bash
# Verify a receipt chain
aegis-verify-receipts receipts.json

# Check gateway health and agent summary
aegis-status --gateway http://127.0.0.1:8080

# Freeze an agent
aegis-freeze-agent --gateway http://127.0.0.1:8080 --agent <id>

# Export audit events
aegis-export-audit --gateway http://127.0.0.1:8080 --output audit.json
```

## Features

- **`AegisClient`** — sync client for all gateway endpoints (authorize, approvals, receipts, agents, SOC).
- **`AegisAsyncClient`** — async client powered by `httpx` (`pip install aegisagent[async]`).
- **`@protect_tool` / `@async_protect_tool`** — fail-closed decorators with approval polling + hash verification.
- **Receipts** — `seal_receipt()`, `seal_chain()`, `verify_receipt()`, `verify_chain()`, `ReceiptAccumulator`.
- **Evidence packs** — `create_evidence_pack()` for bundling receipts as compliance evidence.
- **Webhook handling** — `WebhookHandler` for approval callbacks, `verify_slack_signature()`.
- **Structured logging** — `StructuredJSONFormatter` for JSON log output.
- **SOC client methods** — `get_soc_summary()`, `list_alerts()`, `list_incidents()`, `close_incident()`, `narrate_incident()`.

## Tests

```bash
python3 -m unittest discover -s tests   # 174 tests
```

See the [main README](https://github.com/lavkushry/AegisAgent) and
[`docs/action-receipt-spec.md`](https://github.com/lavkushry/AegisAgent/blob/main/docs/action-receipt-spec.md)
for the full picture.

## License

MIT — see [LICENSE](https://github.com/lavkushry/AegisAgent/blob/main/LICENSE).
