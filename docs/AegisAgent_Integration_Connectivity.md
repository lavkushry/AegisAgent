# AegisAgent — Integration & Connectivity Guide

> **Status:** Product documentation (2026-06-05). How agents — running on laptops, servers, cloud, CI, or anywhere — **connect** to AegisAgent, how their actions are **collected**, and how **rules are applied**.
> **Related:** [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md) (monitoring) · [`AegisAgent_Agent_Workforce_Governance.md`](AegisAgent_Agent_Workforce_Governance.md) (fleet) · [`action-receipt-spec.md`](action-receipt-spec.md) (evidence).

This guide answers the three questions every deployment starts with: **How do we connect? How do we collect? How do we apply rules?**

---

## 1. The model: one gateway, agents phone home

There is **one central Gateway** — self-hosted inside your network, or run as SaaS. Agents **anywhere** reach it over **outbound HTTPS**, authenticated with a **per-agent token** issued at enrollment. (Same shape as a Wazuh agent → manager.)

```
EMPLOYEE LAPTOPS      SERVERS / CLOUD       CI / CD          3rd-PARTY SaaS
 coding-agent          prod agents          pipeline         (no SDK possible)
   │ SDK                 │ SDK / proxy         │ SDK             │ webhooks / traces
   └──── HTTPS 443 ──────┴─────────┬───────────┘                 │ (agentless)
                                   ▼                             ▼
                     AegisAgent Gateway  (central)
                     Cedar rules · approvals · receipts · event emit
                                   │
                                   ▼
                     Store (SQLite / Postgres) + Agent SOC (async)
```

The gateway is the one place rules live and decisions are made. Everything else is about getting an agent's action *to* the gateway before it executes.

---

## 2. The three connection modes

| Mode | How you **connect** | How you **collect** | How rules **apply** | Enforcement |
|---|---|---|---|---|
| **Inline SDK** (primary) | The agent imports the AegisAgent SDK, configured with `gateway_url` + `agent_token`. `@protect_tool` wraps each tool function and calls `POST /v1/authorize` before it runs | The authorize call **is** the collection point (+ an async event to the SOC) | **Cedar in the gateway, inline, <75 ms**, before the action runs | ✅ **blocks** (fail-closed) |
| **Proxy / token-broker** | The agent's tool/MCP calls are pointed at the AegisAgent **proxy** instead of the tool directly; the agent holds **no raw tool credentials** | The proxy sees every call | At the proxy, before forwarding to the tool | ✅ **blocks** — and the agent *cannot skip it* |
| **Agentless ingestion** | Existing telemetry (GitHub webhooks, OpenAI / LangSmith traces, OpenTelemetry) is forwarded to the AegisAgent **collector** | From logs/traces, after the fact | SOC **detection / correlation** only | ⚠️ **detect & alert only — no block** |

You can mix modes per agent: inline SDK for agents you build, proxy for agents you want hard-enforced, agentless for black-box SaaS agents you can only observe.

---

## 3. The enforcement truth (read this once)

**To apply a rule in real time, the action must pass *through* AegisAgent before it happens.** There are exactly two ways to guarantee that:

1. **You control how the agent is deployed** → ship it with the SDK already wired in (a team template / wrapper). Effective when you own the agent's build.
2. **You control the credentials** → **token broker / proxy-only credentials**: remove the raw GitHub / AWS / DB / Stripe tokens from the agent and let it reach those tools *only* through AegisAgent. Now going through the gateway is not optional — it is the **only path to the tools**. This is how you enforce on agents you did not write, including ones on employee machines.

If you can do **neither** (a closed SaaS agent), you fall back to **agentless** — you get monitoring, detection, and alerts, but you did **not** prevent the action. That trade-off is fundamental; state it to stakeholders up front.

> **Rule of thumb:** *SDK is the easy path. Proxy-only credentials are the enforcement backstop. Agentless is the observe-only fallback.*

---

## 4. Connecting an agent: enrollment → token → first call

### Step 1 — Enroll the agent (admin, once)
```
POST /v1/agents/register
  { agent_key, name, owner_team, owner_email, environment, risk_tier, framework, ... }
→ { agent_id, agent_token }      # the token is a secret — store it like any credential
```
This is the "hire" step in [workforce governance](AegisAgent_Agent_Workforce_Governance.md) §2 (Joiner). The token is short-lived and rotatable.

### Step 2 — Configure the agent (wherever it runs)
```python
from aegisagent import AegisClient, protect_tool

aegis = AegisClient(
    gateway_url="https://aegis.acme-corp.internal",   # the central gateway
    agent_token="aegis_agt_…",                         # from enrollment (a secret)
)

@protect_tool(client=aegis, tool="github", action="merge_pull_request", risk="high")
def merge_pr(repo: str, pr_number: int, branch: str):
    return github.merge_pull_request(repo, pr_number, branch)
# → before this runs, the SDK canonicalizes the action, calls the gateway,
#   applies Cedar rules, and FAILS CLOSED on deny / hash-mismatch / unreachable.
```

### Step 3 — Network & auth
- **Egress:** the agent makes **outbound HTTPS** to the gateway (dev binds `127.0.0.1:8080`; production behind TLS on `443`/`9443`). No inbound ports on the agent.
- **Auth:** the per-agent **token** identifies the agent + tenant; **mTLS** and request signing are available for enterprise.
- **Reachability:** the gateway endpoint must be reachable from where the agent runs (public, VPN, or private network). Agents on employee laptops need egress to that endpoint — exactly like any phone-home SDK.

---

## 5. What gets collected

Every protected action produces:
- a **decision** row (`decisions`: agent, tool, action, params-hash, `source_trust`, decision, risk, matched policies, trace),
- a **verifiable receipt** (`action_receipts`: hash-chained, tamper-evident — see [receipt spec](action-receipt-spec.md)),
- an **audit event**, and
- (Agent SOC) an asynchronous **Agent Security Event** onto the SOC stream for detection/correlation.

Secrets are never stored — only **hashes** of inputs/outputs (redaction invariant). So collection is safe to centralize and to screenshot.

---

## 6. How rules are applied

- **Inline (the gate):** **Cedar** evaluates every `/v1/authorize` call deterministically — `allow` / `deny` / `require_approval` — *before* the action runs. Rules live in `policies.cedar` (provenance gates, approval gates, per-action risk). Decisions are **deterministic**, never a text score.
- **Async (the SOC):** detection + correlation rules run **off** the event stream (deny-storms, read→exfil sequences, MCP drift) — these **detect and respond** (alert, freeze, quarantine), they are not the inline gate. See [SOC design](AegisAgent_Agent_SOC_Design.md) §9.

So "applying rules" happens twice, by design: **synchronously to decide an action**, and **asynchronously to detect patterns across actions**.

---

## 7. Deploying across the company

| Where the agent runs | Recommended mode | Notes |
|---|---|---|
| **Employee laptops** (dev/coding agents) | Inline SDK (via a team template) **or** proxy-only creds | If you can't mandate the SDK, broker the tool creds so the agent must route through AegisAgent |
| **Servers / cloud** (prod agents) | Inline SDK or proxy | Strong enforcement; mTLS in enterprise |
| **CI / CD** (pipeline agents) | Inline SDK | Token from the CI secret store |
| **Third-party SaaS agents** | Agentless | Webhooks/traces → collector; monitoring + detection only |

The [workforce governance](AegisAgent_Agent_Workforce_Governance.md) model tracks all of them in one fleet, each tied to a human owner.

---

## 8. Decision guide

```
Do you control the agent's build?
  ├─ yes → embed the SDK (Inline)                         ✅ real-time enforcement
  └─ no  → Can you broker its tool credentials?
            ├─ yes → proxy-only creds (Proxy)              ✅ real-time enforcement (can't be skipped)
            └─ no  → ingest its telemetry (Agentless)       ⚠️ detect & alert only (no block)
```

---

## 9. SDK availability (today)

- **Python** (`sdk-python`) — complete: client + `@protect_tool` + receipts verifier. Use this now.
- **Go** (`sdk-go`) / **TypeScript** (`sdk-typescript`) — the `aegis-jcs-1` canonicalizer is built and verified byte-identical to Python; the HTTP client + decorator are next. (Canon is the hard part; the rest is HTTP + the fail-closed contract.)

---

## 10. Quick checklist to go live

- [ ] Deploy the gateway (self-hosted single binary or SaaS); confirm `GET /health`.
- [ ] Enroll each agent → store its token as a secret.
- [ ] Choose a mode per agent (SDK / proxy / agentless) using §8.
- [ ] For agents you can't mandate: **broker the tool credentials** so they must route through AegisAgent.
- [ ] Write/confirm Cedar policies for your high-risk actions (merge, deploy, IAM, refund, data export).
- [ ] Verify a denied action fails closed and emits a receipt; verify the receipt with `aegis-verify-receipts`.
