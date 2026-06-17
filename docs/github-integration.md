# AegisAgent — GitHub Integration Guide

**Issue:** [#1406](https://github.com/lavkushry/AegisAgent/issues/1406)
**Related:** [`mcp-defense-architecture.md`](mcp-defense-architecture.md) (a parallel untrusted-supply-chain gate, for MCP servers instead of GitHub).

AegisAgent's GitHub integration has three independent pieces, each gated by its own environment variable, each optional, and each fail-closed when misconfigured:

1. **PR protection** — every `/v1/authorize` decision on a `github`-tool call updates the PR's check run (`AEGIS_GITHUB_APP_TOKEN`) and, on `deny`, posts an explanatory comment (also `AEGIS_GITHUB_APP_TOKEN`).
2. **Webhook ingestion** — `POST /v1/webhooks/github` accepts native GitHub events (`pull_request`, `issues`, `issue_comment`) into the SOC pipeline (`AEGIS_GITHUB_WEBHOOK_SECRET`).
3. **The trust-provenance gate itself** — what actually blocks a malicious merge — needs no GitHub-specific configuration at all; it's the same Cedar policy every tool call goes through (see [`security-model.md`](security-model.md)).

There is no GitHub App manifest, private key, or JWT-exchange flow built into AegisAgent. Both `AEGIS_GITHUB_*` variables are pre-obtained bearer credentials you generate through GitHub (a GitHub App installation access token, or a fine-grained PAT with equivalent scopes) and hand to the gateway as plain strings.

---

## 1. Configuration reference

| Env var | Used by | Effect when set | Effect when unset |
|---|---|---|---|
| `AEGIS_GITHUB_APP_TOKEN` | `gh_comment.rs` (#1382), `gh_checks.rs` (#1383) | Bearer token for the GitHub REST API. Enables PR deny-comments and the "Aegis Security Gate" check run. | Both features are disabled — `/v1/authorize` still evaluates and records every decision normally, it just never calls out to GitHub. |
| `AEGIS_GITHUB_WEBHOOK_SECRET` | `routes.rs::receive_github_webhook` (#1381) | HMAC-SHA256 secret used to verify `X-Hub-Signature-256` on every webhook delivery. | `POST /v1/webhooks/github` returns `401 webhook_not_configured` for every request — **fail-closed**, not fail-open: an unconfigured endpoint refuses everything rather than silently accepting unverified payloads. |

Both are read once at startup (`gateway/src/main.rs`) and logged (token presence only, never the value) so you can confirm configuration from the gateway's startup log without inspecting the environment directly.

```bash
export AEGIS_GITHUB_APP_TOKEN="ghs_..."          # installation access token or fine-grained PAT
export AEGIS_GITHUB_WEBHOOK_SECRET="$(openssl rand -hex 32)"
cargo run --manifest-path gateway/Cargo.toml
```

---

## 2. Obtaining `AEGIS_GITHUB_APP_TOKEN`

AegisAgent does not perform the GitHub App JWT → installation-token exchange itself. You provide an already-valid bearer token by one of:

- **GitHub App installation access token** (recommended for production): your own short-lived-token refresher (a small cron job, or your CI's GitHub App action) calls `POST /app/installations/{installation_id}/access_tokens` using your App's private key, and re-exports `AEGIS_GITHUB_APP_TOKEN` with the result, since these tokens expire after one hour. Required permissions:
  - **Pull requests: Read & write** — to post deny-explanation comments (#1382).
  - **Checks: Read & write** — to create/update the "Aegis Security Gate" check run (#1383).
  - **Issues: Read** — only if you also want the webhook ingestion path (§3) to see `issues.opened` events; the token itself is unrelated to webhook verification, but the App installation needs the subscription either way.
- **Fine-grained personal access token** (fastest for a demo/local run): create one scoped to the target repo(s) with the same Pull requests/Checks permissions above. Simpler to set up, but tied to a personal account rather than the App identity — not recommended past initial evaluation.

A token with insufficient scope doesn't break authorization: `gh_comment.rs`/`gh_checks.rs` are strictly best-effort and fire-and-forget (Law 3 — never block or alter the `/v1/authorize` decision). A failed GitHub API call is logged and silently dropped; the PR simply won't get a comment or check-run update for that decision.

---

## 3. Setting up webhook ingestion

`POST /v1/webhooks/github` is the *agentless* ingestion path (#1381, distinct from the generic `POST /v1/ingest` used for non-GitHub sources) — it lets GitHub itself push events into AegisAgent's SOC pipeline without an agent or SDK in the loop at all, e.g. so a public-issue-driven attack attempt shows up on the SOC feed even before any agent acts on it.

1. In your GitHub App settings (or repo **Settings → Webhooks** for a classic webhook), set:
   - **Payload URL**: `https://<your-gateway-host>/v1/webhooks/github`
   - **Content type**: `application/json`
   - **Secret**: the same value as `AEGIS_GITHUB_WEBHOOK_SECRET`
   - **Events**: Pull requests, Issues, Issue comments (everything else is silently ignored — see §3.1)
2. Every delivery must also carry an `X-Aegis-Tenant-ID` header identifying which AegisAgent tenant owns this repo. A classic GitHub webhook can't add custom headers, so for multi-tenant deployments use a GitHub App (whose webhook config you control) or a small relay that injects the header before forwarding to AegisAgent.
3. Send a test delivery from GitHub's webhook settings page and confirm a `202 {"status": "accepted", "event_id": "..."}` response (or `202 {"status": "ignored", ...}` for an event type you didn't subscribe an action for — both are healthy responses, not errors).

### 3.1 Supported events

`ingest::normalize_github_native_event` only recognizes these `(X-GitHub-Event, action)` pairs — everything else (including `pull_request` actions other than `opened`/`closed`, like `synchronize` or `labeled`) is acknowledged with `202 ignored` and never reaches the SOC stream, to avoid polluting it with events not yet modeled:

| `X-GitHub-Event` | `action` | Normalized as |
|---|---|---|
| `pull_request` | `opened` | `pull_request.opened` |
| `pull_request` | `closed` (merged) | `pull_request.merged` |
| `pull_request` | `closed` (not merged) | `pull_request.closed` |
| `issues` | `opened` | `issues.opened` |
| `issue_comment` | `created` | `issue_comment.created` |

### 3.2 Signature verification is mandatory, fail-closed

Every delivery must carry a valid `X-Hub-Signature-256: sha256=<hmac-hex>` computed over the *raw* request body with `AEGIS_GITHUB_WEBHOOK_SECRET`. There is no way to disable this short of unsetting the secret entirely (which instead makes the endpoint refuse everything — §1). This mirrors the same fail-closed posture as the rest of the gateway: an unverifiable GitHub payload is never trusted just because it arrived on the right URL.

---

## 4. PR protection in practice

Once `AEGIS_GITHUB_APP_TOKEN` is set, **every** `/v1/authorize` decision where `tool_call.tool == "github"` and `resource` parses as `org/repo#42` (via `gh_comment::extract_pr_ref`) automatically:

- Creates (on first decision) or updates (thereafter) an **"Aegis Security Gate"** check run on the PR's head commit. The check tallies every decision made against that PR — `allow`/`redact` count as allowed, `require_approval` as pending, everything else (`deny`/`quarantine`/unknown) as denied — and sets the check's conclusion to `failure` if anything was denied, else `action_required` if anything is pending, else `success`. Denied/risky decisions also appear as check-run annotations (capped at 20) so they're visible directly on the PR diff view, not just in a separate dashboard.
- On a `deny` specifically, posts an explanatory PR comment (templated by `gh_comment::format_deny_comment`) naming the matched policies, risk score, and decision ID — rate-limited to 5 comments per `(repo, pr_number)` per gateway process lifetime to survive a noisy deny-storm without spamming the PR.

This is the same `/v1/authorize` call your agent's SDK already makes for every tool call — there's no separate "PR protection mode" to turn on beyond having the token configured. A `github` tool call whose `resource` *doesn't* parse as a PR reference (e.g. a raw repo-level action) skips both features silently; they're additive to the underlying decision, never a precondition for it.

---

## 5. End-to-end demo: malicious issue → denied merge → PR comment

`examples/github-attack-demo.py` exercises the core attack this whole integration defends against — an indirect prompt injection via a public GitHub issue tricking a coding agent into merging to `main`:

```bash
# Terminal 1
CEDAR_POLICY_PATH=policies.cedar cargo run --manifest-path gateway/Cargo.toml

# Terminal 2
python3 examples/github-attack-demo.py
```

The script:

1. Registers a demo coding agent and a mock `github` tool against the local gateway.
2. Simulates the agent having just read a malicious public GitHub issue (`set_context_trust_level("untrusted_external")` — the same context-trust label a real classifier would assign to public, unauthenticated content).
3. Has the agent attempt `merge_pull_request` against `main` under that untrusted context.
4. AegisAgent's trust-provenance gate denies the mutation outright (the `untrusted-mutation-forbid` Cedar rule — see [`security-model.md`](security-model.md) §1) and the script prints the `GET /v1/audit/events` URL to inspect the recorded decision.

This demo runs entirely through the SDK against a local gateway — no real GitHub App or webhook is involved, since the point is to demonstrate the *decision* (the trust-provenance gate), which is identical whether the triggering content arrived via a real GitHub webhook or a simulated one. To see the **PR-comment and check-run side** of the same denial against a real PR, configure `AEGIS_GITHUB_APP_TOKEN` (§2) and re-run the attack against an agent whose `tool_call.resource` is a real `org/repo#42` reference — the deny comment and failing check run will appear on that actual PR.

---

## 6. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `401 webhook_not_configured` from `/v1/webhooks/github` | `AEGIS_GITHUB_WEBHOOK_SECRET` is not set — set it and restart the gateway. |
| `401 invalid_signature` from `/v1/webhooks/github` | The webhook's configured secret doesn't match `AEGIS_GITHUB_WEBHOOK_SECRET`, or a proxy in front of the gateway is rewriting the request body before AegisAgent verifies it (signature is computed over raw bytes). |
| Deliveries return `202 ignored` | The `(X-GitHub-Event, action)` pair isn't one of the five supported combinations in §3.1 — not an error, just not modeled yet. |
| No PR comment or check run appears after a denied `/v1/authorize` call | `AEGIS_GITHUB_APP_TOKEN` is unset, or the decision's `resource` didn't parse as `org/repo#42`, or the token lacks Pull requests/Checks write permission (failures here are logged server-side, not surfaced to the caller — check the gateway's logs). |
