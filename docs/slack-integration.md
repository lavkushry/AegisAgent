# AegisAgent — Slack Integration Guide

**Issue:** [#1405](https://github.com/lavkushry/AegisAgent/issues/1405)
**Related:** [`github-integration.md`](github-integration.md), [`mcp-defense-architecture.md`](mcp-defense-architecture.md) (the other source-specific integration guides).

AegisAgent has two independent, separately-configured Slack integration points. They are not wired to each other today, and understanding that boundary up front will save you a debugging session:

1. **Outbound SOC notifications** (`notify.rs`) — posts a plain, informational Slack-compatible message for every `deny`/`require_approval` decision and every HIGH-severity alert/incident. Gated by `AEGIS_WEBHOOK_URL`. No buttons, no interactivity — just visibility.
2. **Inbound interactive approval callback** (`POST /v1/callbacks/slack`, #1276) — verifies an HMAC-signed Slack Block Kit button click and approves/rejects the corresponding AegisAgent approval. Gated by `AEGIS_SLACK_SIGNING_SECRET`.

Nothing in AegisAgent today constructs the Block Kit **buttons** that #1276 expects to receive a click from. The outbound notification (§1) is flat text/attachments with no `action_id`/`value` fields. To get an actual "approve from a Slack button" workflow, you build a small relay (a Slack app of your own, or a few lines in your existing Slack bot) that posts the button message and points its Interactivity Request URL at `/v1/callbacks/slack`. §4 below gives you the exact message shape that relay needs to produce.

---

## 1. Configuration reference

| Env var | Used by | Effect when set | Effect when unset |
|---|---|---|---|
| `AEGIS_WEBHOOK_URL` | `notify.rs::from_env` | Activates the outbound `WebhookSink` — every `deny`/`require_approval` decision and HIGH alert/incident gets POSTed here as a Slack-compatible JSON body (a Slack **Incoming Webhook** URL works directly). | `NullSink` — notifications are silently dropped. Safe default for dev/test; not a failure. |
| `AEGIS_WEBHOOK_SECRET` | `notify.rs::WebhookSink::notify` | HMAC-SHA256-signs the outbound JSON body; the signature is sent as a header alongside the POST so a receiving relay can verify the message actually came from your gateway. | Outbound POSTs are unsigned — fine for a same-network Slack Incoming Webhook, but verify your relay's trust boundary if it's reachable from elsewhere. |
| `AEGIS_WEBHOOK_FAILURE_THRESHOLD` | `notify.rs::WebhookSink::notify` | Number of consecutive outbound failures before the circuit breaker opens (default `5`). | Default of `5` applies. |
| `AEGIS_WEBHOOK_COOLDOWN_SECS` | `notify.rs::WebhookSink::notify` | Seconds the circuit breaker stays open before a half-open probe (default `30`). | Default of `30` applies. |
| `AEGIS_SLACK_SIGNING_SECRET` | `routes.rs::slack_callback` | Enables `POST /v1/callbacks/slack` and is the key used to verify `X-Slack-Signature`. | `/v1/callbacks/slack` returns `404` for every request — the feature is effectively disabled, fail-closed (no secret means no signature can ever be verified). |

All five are read once at gateway startup (`gateway/src/main.rs`); the Slack secret's presence (never its value) is logged so you can confirm configuration without inspecting the environment directly.

```bash
export AEGIS_WEBHOOK_URL="https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXXXXXXXXXX"
export AEGIS_WEBHOOK_SECRET="$(openssl rand -hex 32)"   # optional, signs outbound POSTs
export AEGIS_SLACK_SIGNING_SECRET="$(openssl rand -hex 32)"  # from your Slack app's Basic Information page
cargo run --manifest-path gateway/Cargo.toml
```

---

## 2. App creation

You need a single Slack app to cover both directions:

1. Go to <https://api.slack.com/apps> → **Create New App** → "From scratch".
2. **Incoming Webhooks** (for §3, outbound): under **Features → Incoming Webhooks**, toggle it on, then **Add New Webhook to Workspace** and pick the channel your SOC alerts should land in. Copy the generated URL into `AEGIS_WEBHOOK_URL`.
3. **Interactivity & Shortcuts** (for §4, inbound): under **Features → Interactivity & Shortcuts**, toggle it on and set the **Request URL** to `https://<your-gateway-host>/v1/callbacks/slack`. Slack will only enable the toggle once that URL responds correctly to its verification handshake, so configure `AEGIS_SLACK_SIGNING_SECRET` and have the gateway reachable first.
4. Copy the **Signing Secret** from **Basic Information → App Credentials** into `AEGIS_SLACK_SIGNING_SECRET`. This is *not* the Incoming Webhook URL and *not* a bot token — interactive payload verification uses this one secret regardless of how the message was originally posted.

No bot token, OAuth scopes, or `chat:write` permission is required for either AegisAgent feature itself — Incoming Webhooks post without a bot identity, and the interactive callback only ever reads the payload Slack sends, it never calls back into the Slack API. You will need a bot token (`chat:write`) only if your own relay (§4) posts the interactive button message via `chat.postMessage` instead of a second Incoming Webhook.

---

## 3. Outbound notifications

Once `AEGIS_WEBHOOK_URL` is set, the background SOC drain loop (`events::drain`) posts a message for exactly three triggers — chosen to avoid alert fatigue:

| Trigger | Notes |
|---|---|
| Every `deny` decision | Always SOC-visible. |
| Every `require_approval` decision | A human is now in the loop. |
| Every HIGH-severity alert or incident | Confused-deputy, deny-storm, runaway-agent patterns from `detect.rs`/`correlate.rs`. |

Plain `allow` decisions are never notified. Each message is built by `notify::slack_body` as a Slack attachment:

```json
{
  "text": ":rotating_light: *[AegisAgent SOC]* `authorize_decision` | severity=high | tenant=`acme` | agent=`agent_42`\n>decision=deny tool=github action=merge_pr reason=Mutating action denied: untrusted_external provenance",
  "attachments": [{
    "color": "danger",
    "fields": [
      {"title": "Kind", "value": "authorize_decision", "short": true},
      {"title": "Severity", "value": "high", "short": true},
      {"title": "Tenant", "value": "acme", "short": true},
      {"title": "Agent", "value": "agent_42", "short": true},
      {"title": "Timestamp", "value": "2026-06-17T12:00:00Z", "short": false},
      {"title": "Summary", "value": "decision=deny tool=github action=merge_pr reason=...", "short": false}
    ],
    "footer": "AegisAgent SOC",
    "ts": "2026-06-17T12:00:00Z"
  }]
}
```

This payload contains **no secrets, tokens, or raw action parameters** by design (the redaction invariant) — only identifiers, decision, severity, and a human-readable summary. It also contains **no `approval_id`** — by the time a `require_approval` notification reaches Slack, the message tells you a human is needed, but you still look the approval up via `GET /v1/approvals` (or your SOC dashboard) to act on it through the REST API. See §4 for closing that gap with one-click Slack buttons.

A failed or slow delivery never blocks the gateway: `WebhookSink::notify` spawns a detached task with a 5-second timeout and a circuit breaker (`AEGIS_WEBHOOK_FAILURE_THRESHOLD`/`AEGIS_WEBHOOK_COOLDOWN_SECS`) that stops attempting deliveries during a sustained Slack outage rather than piling up tasks.

---

## 4. Building the interactive approval flow

`POST /v1/callbacks/slack` (#1276) is built to receive exactly what Slack sends when a user clicks a **Block Kit button** inside an interactive message — but AegisAgent doesn't post that message for you. The relay you build (a small bot, a Lambda/Cloud Function, or a few lines added to an existing internal Slack app) needs to:

1. Learn about a new `require_approval` decision — either by subscribing to the outbound notification (§3) and looking up the matching pending approval via `GET /v1/approvals?agent_id=...`, or by polling `GET /v1/approvals` directly.
2. Post a Block Kit message with **Approve**/**Reject** buttons whose `value` is exactly `"{tenant_id}:{approval_id}"` and whose `action_id` is `"approve"` or `"reject"`:

   ```json
   {
     "channel": "#soc-approvals",
     "text": "Approval needed: agent_42 wants to merge_pr on github",
     "blocks": [
       {
         "type": "section",
         "text": { "type": "mrkdwn", "text": "*Approval needed*\nAgent `agent_42` wants to run `merge_pr` on `github`." }
       },
       {
         "type": "actions",
         "elements": [
           {
             "type": "button",
             "text": { "type": "plain_text", "text": "Approve" },
             "style": "primary",
             "action_id": "approve",
             "value": "acme:7f3c1e9a-1234-4d56-9abc-1234567890ab"
           },
           {
             "type": "button",
             "text": { "type": "plain_text", "text": "Reject" },
             "style": "danger",
             "action_id": "reject",
             "value": "acme:7f3c1e9a-1234-4d56-9abc-1234567890ab"
           }
         ]
       }
     ]
   }
   ```

3. Post it via `chat.postMessage` (needs a bot token + `chat:write` scope) or a second Incoming Webhook.

When a user clicks a button, Slack itself POSTs the click to your app's **Interactivity Request URL** — which you pointed at `/v1/callbacks/slack` in §2 — as `application/x-www-form-urlencoded` with a single `payload` field containing the URL-encoded interactive-payload JSON. `slack_callback` then, fail-closed at every step:

1. Returns `404` immediately if `AEGIS_SLACK_SIGNING_SECRET` is unset.
2. Reads `X-Slack-Request-Timestamp` and rejects (`401`) anything older than 5 minutes — defends against replay of a captured request.
3. Reads `X-Slack-Signature` and rejects (`401`) anything that doesn't match `v0=HMAC-SHA256("v0:{timestamp}:{raw body}", AEGIS_SLACK_SIGNING_SECRET)`, computed with a constant-time comparison — defends against forged approvals.
4. Parses the `payload` field, reads `actions[0].value` as `"{tenant_id}:{approval_id}"` and `actions[0].action_id` as `"approve"`/`"reject"`, and the approver identity from `user.username` (falling back to `user.id`).
5. Calls the exact same internal logic as `POST /v1/approvals/:id/approve` or `.../reject` — including the existing per-IP rate limit and the single-pending-decision guard (a `409` if the approval was already decided, e.g. by two people clicking at once or someone also using the REST API).

The recorded `reason` for an approval decided this way is always `"Decided via Slack interactive callback"`, so it's distinguishable in `GET /v1/audit/events` from a decision made through the REST API directly or through `examples/`/SDK tooling.

Note that this endpoint is **not tenant-scoped via the usual `TenantId` header extractor** — Slack has no way to send your agent authentication headers — so the tenant is recovered from the button's encoded `value` instead, and authenticity comes entirely from the HMAC signature in step 3. Make sure your relay only ever embeds a `tenant_id` it has independently verified the requesting Slack workspace/channel is entitled to act on; the gateway trusts whatever tenant ID arrives in a correctly-signed callback.

---

## 5. The SDK's `verify_slack_signature` / `WebhookHandler` — a different feature

`sdk-python/aegisagent/webhooks.py` ships `verify_slack_signature()` (a Python port of the same `v0=HMAC-SHA256` scheme as §4) and a `WebhookHandler` class with `on_approved`/`on_rejected`/`on_edited`/`on_expired` hooks. **This is unrelated to Slack specifically** — it's a generic helper for the *agent's own* SDK process to receive the `callback: {"url": ..., "secret": ...}` webhook optionally registered on a `POST /v1/authorize` call (see the repo's `CLAUDE.md` API contract), reusing Slack's signing scheme purely for convenience since it's a well-documented, easy-to-implement HMAC format. It does not talk to Slack, and a Slack interactive-button click never reaches it. Don't wire it into the flow described in §4 — that flow is gateway-side (`slack_callback` in `routes.rs`), not SDK-side.

---

## 6. What an approval message looks like (mockup)

Producing real screenshots requires a live Slack workspace and app install, which isn't available in this environment. Here's what the Block Kit message from §4 renders as:

```text
┌─────────────────────────────────────────────────┐
│ AegisAgent SOC                              12:00 │
│                                                   │
│ Approval needed                                  │
│ Agent agent_42 wants to run merge_pr on github.  │
│                                                   │
│  [ Approve ]   [ Reject ]                        │
│   (green)        (red)                           │
└─────────────────────────────────────────────────┘
```

And the plain outbound notification from §3 (no buttons) as:

```text
┌─────────────────────────────────────────────────┐
│ 🚨 [AegisAgent SOC] authorize_decision           │
│ severity=high | tenant=acme | agent=agent_42     │
│ decision=deny tool=github action=merge_pr        │
│ reason=Mutating action denied: untrusted_external│
│        provenance                                │
│                                                   │
│ Kind: authorize_decision   Severity: high        │
│ Tenant: acme                Agent: agent_42      │
│ Timestamp: 2026-06-17T12:00:00Z                  │
└─────────────────────────────────────────────────┘
```

---

## 7. Troubleshooting

| Symptom | Likely cause |
|---|---|
| Slack never enables the Interactivity toggle / shows a Request URL error | `AEGIS_SLACK_SIGNING_SECRET` is unset (endpoint 404s) or the gateway isn't reachable at the configured Request URL from Slack's network. |
| `401 stale_timestamp` from `/v1/callbacks/slack` | The click arrived more than 5 minutes after the `X-Slack-Request-Timestamp` Slack attached, or a proxy delayed delivery. Not adjustable — this matches Slack's own signing guidance. |
| `401 invalid_signature` | `AEGIS_SLACK_SIGNING_SECRET` doesn't match the Signing Secret on the Slack app's Basic Information page, or a proxy in front of the gateway rewrote the raw body before AegisAgent verified it (the signature is computed over raw bytes). |
| `400 invalid approval id in callback value` / `missing or malformed callback value` | The button's `value` wasn't built as `"{tenant_id}:{approval_id}"`, or the relay posting the message has a bug. Re-check the JSON shape in §4 step 2. |
| `409 Approval already decided` | Someone else (or another click) already approved/rejected it first — this is the existing single-decision guard working as intended, not a bug. |
| No outbound message appears in Slack at all | `AEGIS_WEBHOOK_URL` is unset (falls back to `NullSink`, silent by design), the circuit breaker is open after repeated delivery failures (check gateway logs for "circuit breaker is OPEN"), or the decision was a plain `allow` (never notified). |
| Outbound messages stop during a Slack outage and don't resume immediately after | Working as intended — the circuit breaker waits `AEGIS_WEBHOOK_COOLDOWN_SECS` (default 30s) before a half-open probe rather than retrying every message immediately. |
