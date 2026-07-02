# Why AegisAgent?

## Simple version

You wouldn't give a new employee production credentials with no review, no log, and no way to fire them. AI agents get exactly that every day. AegisAgent gives you the review, the log, and the off switch.

## The three problems

### 1. Agents can be tricked

A malicious GitHub issue or support ticket can steer an agent into misusing *your* credentials (prompt injection / confused deputy). Text filters miss this — attackers write new text.

**Aegis answer:** decisions gate on *where content came from* (six deterministic trust levels), not on what the text says. Content from an untrusted source can never authorize a risky action, no matter how convincing it reads.

### 2. "Human approval" is usually theater

Most approval flows approve a *description*. The agent can then run something slightly different, or reuse an old approval.

**Aegis answer:** approvals bind to a SHA-256 fingerprint of the exact action. One byte different → refused. Approvals are single-use and expire. Try to break it: `python3 examples/approve_then_swap_demo.py`.

### 3. Nobody can prove what an agent did

Text logs can be edited, reordered, deleted. Auditors and incident responders need proof.

**Aegis answer:** every decision produces a hash-chained **receipt**. Tampering breaks the chain visibly. Optional signatures let a third party verify without trusting the server.

## Why not just an "AI firewall"?

AI firewalls score text with another model — probabilistic, evadable, unexplainable. AegisAgent's rule: **classifiers may only tighten a decision, never make one.** Authorization stays deterministic, so you can explain every decision to an auditor.

## Why this matters to each reader

| You are | Aegis gives you |
|---|---|
| Engineering leader | agents in production without betting the company on a prompt |
| Developer | one decorator; fail-closed protection in minutes |
| Security architect | deterministic policy, named trust boundaries, real threat model |
| SOC analyst | agent-native alerts, incidents, timelines, and an off switch |
| Compliance / investor | cryptographic evidence (SOC 2, EU AI Act Art. 14 alignment) |

## Current status

Everything above except runtime containment of unknown agents is Implemented — the honest ledger is [Implementation_Status.md](Implementation_Status.md).

## Related docs

[What_Is_AegisAgent.md](What_Is_AegisAgent.md) · [The_One_Minute_Tour.md](The_One_Minute_Tour.md) · [AegisAgent_Threat_Model.md](AegisAgent_Threat_Model.md) · [Product_Overview.md](Product_Overview.md)
