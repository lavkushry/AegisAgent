# The One-Minute Tour

*Sixty seconds. No jargon.*

## Overview

Remember three ideas: Aegis checks actions rather than trusting generated text; a human approval is bound to one exact action; and every protected decision leaves independently verifiable evidence.

> **Status:** These known-agent integrity capabilities are implemented. Cage, sensor, forced egress, broker enforcement, and multi-replica HA remain Partial.

## The problem

Companies are handing AI agents real power: credentials, APIs, code, money, customer data.

## The risk

Agents do what text tells them. Attackers write text. One poisoned ticket, issue, or email can turn *your* agent into *their* agent — and afterwards, nobody can prove what actually happened.

## The solution

**AegisAgent lets you run AI agents without losing control.**

Before an agent does something risky, Aegis:

1. **Checks it** — deterministic policy, based on where the request came from.
2. **Controls it** — risky actions wait for a human; the approval locks to the *exact* action.
3. **Records it** — every decision becomes a tamper-evident receipt.
4. **Proves it** — the receipt chain shows exactly what happened, to anyone.

And if an agent misbehaves, the built-in SOC can freeze, quarantine, or ban it.

## The simple picture

```mermaid
flowchart LR
    A[AI agent] --> C[Aegis checks]
    C -->|safe| RUN[Action runs]
    C -->|risky| H[Human approves exact action] --> RUN
    C -->|dangerous| STOP[Blocked]
    RUN --> P[Provable receipt]
    P --> W[SOC watches and can stop the agent]
```

## Next

- What it is, in full: [What_Is_AegisAgent.md](What_Is_AegisAgent.md)
- Why it works this way: [Why_AegisAgent.md](Why_AegisAgent.md)
- The mechanism, step by step: [How_It_Works.md](How_It_Works.md)
- I'm a developer — integrate now: [onboarding/For_SDK_Developer.md](onboarding/For_SDK_Developer.md)
- The full story with code references: [Last_Mile_System_Walkthrough.md](Last_Mile_System_Walkthrough.md)

## Try It

```bash
make demo
```

The expected outcome is a blocked malicious action, a rejected action swap/replay, and a verified receipt chain—not merely a running dashboard.
