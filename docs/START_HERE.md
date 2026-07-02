# Start Here

**AegisAgent lets you run AI agents without losing control.**

Before an AI agent does something risky, Aegis checks it, controls it, records it, and proves what happened. Aegis is not an agent — it is the control layer *for* agents.

**Who it's for:** teams putting AI agents near real credentials, real APIs, and real data — and the security people who have to answer for it.

---

## Pick your path

### 🟢 "I am new"

1. [The_One_Minute_Tour.md](The_One_Minute_Tour.md) — the whole idea in 60 seconds
2. [What_Is_AegisAgent.md](What_Is_AegisAgent.md) — what it is and is not
3. [How_It_Works.md](How_It_Works.md) — the mechanism, step by step
4. Then, when curious: [Last_Mile_System_Walkthrough.md](Last_Mile_System_Walkthrough.md) — the full story with code

### 🔵 "I am a developer"

1. [onboarding/For_SDK_Developer.md](onboarding/For_SDK_Developer.md) — protected tool calls in ~10 minutes
2. [Local_Development.md](Local_Development.md) — run the whole stack locally
3. [flows/Known_Agent_Flow.md](flows/Known_Agent_Flow.md) — what actually happens on every call
4. Reference: [components/SDK.md](components/SDK.md) · [api-reference.md](api-reference.md)

### 🔴 "I am security / SOC"

1. [onboarding/For_Security_Architect.md](onboarding/For_Security_Architect.md) — trust boundaries in ~15 minutes
2. [onboarding/For_SOC_Analyst.md](onboarding/For_SOC_Analyst.md) — investigate an incident in ~10 minutes
3. [AegisAgent_Threat_Model.md](AegisAgent_Threat_Model.md) — the adversary's view
4. [Implementation_Status.md](Implementation_Status.md) — the honest implemented-vs-planned ledger

Other roles — frontend, DevOps, new maintainer: [onboarding/](onboarding/For_New_Engineer.md) has a guide each. The complete map of every document is [Documentation_Index.md](Documentation_Index.md).

---

## The three documents everyone should read

1. [Product_Overview.md](Product_Overview.md) — what it is, why it exists (10 min)
2. [Last_Mile_System_Walkthrough.md](Last_Mile_System_Walkthrough.md) — the entire system as one story (15 min)
3. [Architecture_Overview.md](Architecture_Overview.md) — control points, trust boundaries, fail-closed rules (15 min)

## Explore visually

- [AegisAgent_Diagram_Index.md](AegisAgent_Diagram_Index.md) — every diagram, small and mobile-readable
- [explorer/index.html](explorer/index.html) — optional interactive system map (2D fallback built in), driven by [architecture-map.json](architecture-map.json)

## One honest rule

Aegis controls what passes through Aegis control points (SDK, gateway, policy, approvals, receipts, SOC, MCP gateway — and, on the roadmap, tool broker, egress proxy, agent cage, node sensor). An agent that bypasses every control point is treated as unsafe: in runtime-controlled modes it is isolated, blocked, killed, quarantined, or banned. Nothing in these docs claims otherwise — check [Implementation_Status.md](Implementation_Status.md) before believing any capability.

## Naming note

Some common titles map to canonical files to avoid duplicates: API reference → [api-reference.md](api-reference.md) (generated) · deployment → [deployment-guide.md](deployment-guide.md) + [production-hardening.md](production-hardening.md) · runbook → [runbooks/index.md](runbooks/index.md) · contributor guide → [CONTRIBUTING.md](https://github.com/lavkushry/AegisAgent/blob/main/CONTRIBUTING.md) · FAQ → [faq.md](faq.md) · glossary → [Glossary.md](Glossary.md).
