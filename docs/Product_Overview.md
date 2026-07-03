# Product Overview

**One sentence:** AegisAgent is the security control plane that decides what autonomous AI agents may do, proves what they did, and contains them when they misbehave.

## Why it exists

AI agents now hold credentials, call APIs, merge code, move money, and talk to customers. Three things go wrong at scale:

1. **Prompt injection turns your agent into someone else's agent.** A malicious GitHub issue or support ticket can steer an agent into using *your* credentials against you (the confused-deputy problem).
2. **"Human in the loop" is usually theater.** Most approval flows approve a *description* of an action. The agent can then execute something subtly different (approve-then-swap, TOCTOU), or replay an old approval.
3. **Nobody can prove what an agent actually did.** Text logs are mutable and unstructured; auditors and incident responders need tamper-evident evidence.

Generic "AI firewalls" answer these with probabilistic text classifiers. AegisAgent's position: **classifiers can only ever tighten a decision — never make one.** Authorization must be deterministic.

## What AegisAgent is (and is not)

AegisAgent **is**: Control Plane + Runtime Sensor + Agent Cage + Egress Proxy + Tool Broker + MCP Gateway + Receipt SOC for autonomous AI agents. It is open-source, self-hostable, and framework-neutral (LangGraph, OpenAI Agents, Autogen, custom, MCP).

AegisAgent **is not**: an agent, an LLM, a prompt scanner, or a model provider. It never generates actions; it authorizes, records, and contains them.

> **Honest scope note:** the control plane, SDK enforcement, MCP defense, approvals, receipts, and the SOC are implemented today. The runtime data plane for *unknown* agents (node sensor, cage runner, egress proxy, tool broker) is a designed and partially-stored roadmap — see [Implementation_Status.md](Implementation_Status.md). Do not sell what column "Planned" contains.

## The two defensible differentiators

### 1. Approval integrity
When a human approves an action, the approval is bound to a **SHA-256 hash of the frozen, canonicalized action** (`aegis-jcs-1`). The SDK **fails closed** if the action that would execute differs by a single byte from what was approved, if the approval expired, or if it was already consumed (single-use, atomic). Editing an approval re-hashes and re-evaluates. This defeats approve-then-swap, replay, and render-vs-bytes attacks. Deep dive: [components/Approval_Engine.md](components/Approval_Engine.md).

### 2. Deterministic trust-provenance gating
Every piece of content that can trigger an agent carries one of **six source trust levels** (`trusted_internal_signed` → `malicious_suspected`/`unknown`). Cedar policies gate mutating actions on that label — e.g. *"content from a public GitHub issue may never trigger a state-mutating tool call, regardless of what the text says."* Labels propagate across agent hops and can only be tightened, never loosened. Deep dive: [Architecture_Overview.md](Architecture_Overview.md) §Trust provenance.

Plus the evidence layer: **verifiable, hash-chained action receipts** (optionally Ed25519-signed) that a third party can verify without trusting the gateway — compliance evidence for SOC 2 and EU AI Act Article 14. Deep dive: [components/Receipt_Engine.md](components/Receipt_Engine.md).

## The core rule: choke points, not magic

Aegis does **not** claim to catch everything an agent could ever do. The architecture is honest:

> **Aegis controls what passes through Aegis choke points. Anything outside the choke points is treated as hostile — isolated, blocked, killed, or banned.**

The eleven choke points (prompt/model, tool, API, MCP, egress, filesystem, process, secrets, approval, runtime control, receipt/evidence) and their implementation status are mapped in [Architecture_Overview.md](Architecture_Overview.md).

- **Known agents** opt into choke points via the SDK — and the SDK makes bypass unattractive: no valid decision, no execution.
- **Unknown agents** get no opt-out: the (designed) agent cage removes the ambient environment — no host filesystem, no raw credentials, no direct internet — so the choke points are the *only* paths that work.

## Who uses it

| Persona | What they get |
|---|---|
| Platform / AI engineers | `@protect_tool` decorator (Python/Go/TS) — 10 minutes to fail-closed protection |
| Security architects | Deterministic policy (Cedar), 6-level trust provenance, threat model with named boundaries |
| SOC analysts | Agent-native SIEM: alerts, incidents, timelines, narratives, freeze/quarantine/revoke |
| Compliance / CTOs | Evidence packs and receipts that prove control effectiveness |

## See it in 5 minutes

```bash
docker compose up --build -d       # gateway on 127.0.0.1:8080, console at /dashboard
bash scripts/seed-demo.sh
python3 examples/integrity_demo.py         # zero-setup wedge demo
python3 examples/approve_then_swap_demo.py # watch the swap get refused
```

Full path: [quickstart.md](quickstart.md) → [Last_Mile_System_Walkthrough.md](Last_Mile_System_Walkthrough.md).

## Related docs

[START_HERE.md](START_HERE.md) · [Architecture_Overview.md](Architecture_Overview.md) · [Implementation_Status.md](Implementation_Status.md) · [AegisAgent_Threat_Model.md](AegisAgent_Threat_Model.md) · internal strategy: [AegisAgent_Gap_Reassessment_2026-06.md](AegisAgent_Gap_Reassessment_2026-06.md)
