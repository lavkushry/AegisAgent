---
title: AegisAgent FAQ
description: Common questions about AegisAgent, current capabilities, and roadmap.
---

# FAQ

## Is AegisAgent an AI agent?

No.

AegisAgent is security infrastructure that controls AI agents.

It sits between agents and risky actions such as tool calls, API calls, MCP calls, approvals, and future runtime/network activity.

---

## Is AegisAgent just a prompt firewall?

No.

Prompt filtering tries to decide whether text is safe.

AegisAgent focuses on what the agent is about to do.

```text
Prompt firewall question:
"Does this text look malicious?"

AegisAgent question:
"Should this agent be allowed to perform this exact action on this exact resource right now?"
```

AegisAgent may capture prompt/model metadata where there is a proper choke point, but the product is action-control infrastructure, not a prompt-only scanner.

---

## What does AegisAgent protect today?

The current MVP protects known agents through the SDK and gateway.

Available today in the repository:

- Rust Axum gateway
- Python SDK with `@protect_tool`
- Cedar policy evaluation
- deterministic source-trust policy
- approval workflow
- canonical action hashing
- fail-closed approval verification
- hash-chained receipts
- audit events
- MCP Gateway Lite governance primitives
- Docker Compose local demo
- GitHub prompt-injection attack demo

See [Current vs roadmap](current-vs-roadmap.md) for a public status table.

---

## What is on the roadmap?

The target architecture expands AegisAgent into a broader AI Agent Security Control Plane:

- node sensor
- agent cage runner
- egress proxy
- tool broker
- signed runtime control commands
- ban and quarantine system
- prompt/model/tool/runtime timeline
- receipt-backed SOC evidence graph
- full console UI
- production Postgres and Kubernetes deployment model

These are roadmap items unless specifically marked as available today.

---

## Can AegisAgent stop an agent that bypasses it completely?

Not by magic.

AegisAgent can only control what passes through an AegisAgent choke point.

Current choke points include the SDK and gateway.

Target choke points include:

- SDK
- gateway
- MCP gateway
- tool broker
- egress proxy
- runtime sensor
- agent cage
- approval engine
- receipt engine

If an agent bypasses every choke point, it should be treated as unknown or hostile and controlled through runtime isolation, network controls, bans, and quarantine.

---

## What is approval integrity?

Approval integrity means the approval is bound to the exact action.

AegisAgent computes an `action_hash` from deterministic canonical JSON.

If an agent changes the action after approval, the hash changes and the SDK fails closed.

This protects against approve-then-swap attacks.

---

## What is an action hash?

An action hash is a SHA-256 fingerprint of the exact tool/action/resource/parameters being requested.

It turns a human approval from:

```text
"Looks okay"
```

into:

```text
"Approved exactly this action hash, once, before expiry"
```

---

## What are receipts?

Receipts are tamper-evident records for protected decisions and actions.

They help prove:

- what was requested
- what was allowed or denied
- what required approval
- what exact action was approved
- who approved it
- whether the evidence chain was modified

AegisAgent receipts are designed for audit and SOC evidence workflows.

---

## Why use Cedar policy?

Cedar is a policy language designed for authorization.

AegisAgent uses policy for deterministic enforcement decisions instead of relying on an LLM to decide whether a privileged action is safe.

LLMs can summarize or explain. Policy enforces.

---

## Does AegisAgent store raw prompts?

The design principle is: do not store raw sensitive prompts by default.

The target prompt/model capture design stores safer metadata such as:

- prompt hash
- redacted preview
- model/provider
- source trust
- run and trace IDs
- action/receipt linkage
- redaction status
- retention policy

The current MVP focuses mainly on protected action metadata, approvals, receipts, and audit events.

---

## How is AegisAgent different from an MCP gateway?

An MCP gateway controls MCP tool access.

AegisAgent includes MCP governance, but its scope is broader:

- SDK-protected tool calls
- gateway authorization
- approval integrity
- action receipts
- source-trust policy
- future tool broker
- future egress proxy
- future runtime sensor and agent cage
- future SOC evidence graph

MCP is one important choke point, not the whole product.

---

## How is AegisAgent different from a SIEM?

A SIEM mostly collects and analyzes events after they happen.

AegisAgent is designed to sit inline before risky agent actions happen.

```text
AegisAgent: prevent or pause unsafe action before execution
SIEM: analyze events and alerts after collection
```

The roadmap includes SOC/evidence workflows, but AegisAgent is not trying to become a full generic SIEM.

---

## Is AegisAgent production-ready?

The repository contains a local/dev MVP and architecture docs for the target production system.

Before production use, the project roadmap calls for hardening such as:

- production authentication and authorization
- Postgres production mode
- TLS/mTLS
- tenant isolation tests
- signed command protocol
- replay protection
- metrics and tracing
- Kubernetes/Helm deployment
- backup/restore
- retention policies

Use the current system as a security architecture and MVP demo unless you have reviewed and hardened it for your environment.

---

## Can an LLM decide whether to allow an action?

No.

AegisAgent's enforcement path should be deterministic.

An LLM can help with summaries, investigation notes, or suggested policy changes, but it should not be the authority for allow/deny decisions.

---

## Why does AegisAgent say “trust the source, not the text”?

Because malicious text can look harmless and harmless-looking text can still come from an untrusted place.

A public GitHub issue, email, web page, or user comment should not have the same authority as a trusted internal deployment workflow.

Source trust is a deterministic input that policy can enforce.

---

## What should I try first?

Start here:

1. [Quickstart](quickstart.md)
2. [Demo: malicious GitHub issue](demo-github-attack.md)
3. [Core concepts](concepts.md)
4. [Current vs roadmap](current-vs-roadmap.md)
