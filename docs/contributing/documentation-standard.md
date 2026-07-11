# AegisAgent Documentation Standard

This standard defines how AegisAgent documentation teaches, proves, and stays accurate. Use it for every new or substantially rewritten page.

!!! info "The short version"
    Explain **why** before **how**, disclose implementation status before capability claims, show one runnable path, explain every diagram and example, and link every important claim to code or a canonical reference.

## 1. The documentation contract

Every page must help a reader answer five questions:

1. **Context:** What is this, in plain language?
2. **Reason:** Why does it exist, and what fails without it?
3. **Mechanism:** How does it work at increasing levels of depth?
4. **Application:** How can I build, run, verify, and operate it?
5. **Evidence:** How do I know it worked, and what does failure look like?

These questions combine two teaching models:

- **STAR:** situation, task, action, result.
- **CREATE:** context, reason, explain, apply, teach.

The models are not extra headings. They are checks on the narrative. A page that starts with commands but never explains the problem has skipped Context and Reason. A page that describes architecture but provides no verification has skipped Apply and Result.

## 2. Required page order

Substantial concept, component, integration, and operations pages use this order. A reference-only page may keep a generated or tabular format, but its owning guide must provide the teaching layer.

1. Title
2. Overview
3. Why This Exists
4. Problem Statement
5. Solution
6. Architecture
7. Component Breakdown
8. Data Flow
9. Request Flow
10. Control Flow
11. Sequence Diagram
12. State Diagram
13. Class Diagram
14. Deployment Architecture
15. Folder Structure
16. Configuration
17. Installation
18. Quick Start
19. Detailed Walkthrough
20. Code Explanation
21. Live Example
22. API
23. CLI
24. Configuration Reference
25. Security
26. Performance
27. Scaling
28. Monitoring
29. Logging
30. Alerting
31. Troubleshooting
32. Common Mistakes
33. Best Practices
34. FAQ
35. References

Do not add empty headings just to satisfy the outline. If a section is genuinely inapplicable, say why in one sentence and direct the reader to the owning page. For example, a protocol specification may say that deployment is owned by the gateway deployment guide.

## 3. Progressive explanation

Explain important concepts at five levels when the audience spans beginners and experts:

| Level | Reader question | Expected treatment |
|---|---|---|
| 1 — ELI5 | “What is the idea?” | Analogy and one sentence; no unexplained jargon |
| 2 — Beginner | “What parts are involved?” | Named components and a simple flow |
| 3 — Intermediate | “What happens to a request?” | Protocol, state, failure, and data details |
| 4 — Advanced | “Which invariants and tradeoffs matter?” | Trust boundaries, concurrency, storage, consistency |
| 5 — Production | “How do I operate this safely?” | SLOs, capacity, alerts, rollout, rollback, recovery |

Define a term the first time it appears. Prefer “a point every request must pass through” before “choke point,” then use the shorter term consistently.

## 4. Status and evidence rules

AegisAgent distinguishes **Implemented**, **Partial**, **Planned**, and **Missing**. Before documenting a capability:

1. Check [Implementation Status](../Implementation_Status.md).
2. Verify the cited route, trait, migration, SDK method, or deployment manifest exists.
3. Mark target designs explicitly. Never use present tense for planned behavior.
4. Link to the closest source file or generated reference.
5. Record measured performance with date, environment, sample size, and limitations.

Do not invent screenshots, logs, benchmarks, Terraform modules, Helm values, or cloud architectures. A clearly labeled conceptual example is allowed when it teaches a portable pattern, but it must not imply that AegisAgent ships that artifact.

## 5. Diagrams

Every substantial page needs at least one diagram. Choose diagrams by the relationship being taught:

| Relationship | Mermaid type |
|---|---|
| System or dependency topology | `flowchart` or `architecture-beta` |
| Ordered request interactions | `sequenceDiagram` |
| Lifecycle and valid transitions | `stateDiagram-v2` |
| Types, traits, and ownership | `classDiagram` |
| Persistent entities | `erDiagram` |
| Releases or incidents over time | `timeline` or `gitGraph` |
| User experience | `journey` |
| Proportions from measured data | `pie` |
| Concept taxonomy | `mindmap` |

Each diagram must have:

- a sentence before it explaining what to look for;
- accessible labels that remain understandable without color;
- a paragraph after it explaining the important path, boundary, or tradeoff;
- status markers for planned components;
- no more nodes than the teaching goal requires.

Mermaid sources reused across pages belong in `docs/diagrams/` and must be added to [the diagram index](../AegisAgent_Diagram_Index.md).

## 6. Interactive architecture

Use the existing [architecture explorer](../explorer/index.html) for clickable topology. It is driven by `docs/architecture-map.json` and has a 2D fallback.

When a page proposes a richer 3D view, specify the experience rather than pretending it ships:

- **Renderer:** Three.js or React Three Fiber for WebGL; React Flow for the accessible 2D mode.
- **Camera:** start with a readable overview, focus smoothly on selection, preserve keyboard navigation.
- **Nodes:** hover reveals status, latency, and owner; click opens the canonical component page.
- **Edges:** direction is explicit; particles represent live request or event flow only when telemetry exists.
- **Controls:** zoom, pan, reset, pause animation, filter by tenant/status/plane, and reduced-motion mode.
- **Live data:** show freshness and units; never render simulated values as production telemetry.
- **Fallback:** provide the same topology and facts in HTML and Mermaid.

## 7. Code and command examples

Every example must be copyable or explicitly labeled pseudocode.

For code:

- show the smallest complete example that teaches the point;
- explain each non-obvious line immediately after the block;
- identify inputs, outputs, side effects, error behavior, and secret handling;
- never use `.unwrap()` or `.expect()` in production Rust examples;
- use protobuf as the API type source of truth and keep REST examples aligned;
- keep REST and gRPC coverage together for endpoint documentation.

For commands:

- state the required working directory;
- explain every flag, port, environment variable, and placeholder;
- show expected output without claiming exact generated IDs or timestamps;
- provide a cleanup or rollback command when state changes;
- never put real secrets in shell history.

## 8. Production completeness

A production guide covers, or links directly to, all of the following:

| Area | Required evidence |
|---|---|
| Deployment | Docker, shipped Helm chart, or bare-metal path actually present in the repo |
| Verification | health/readiness/startup probes plus a functional request |
| Testing | unit, integration, workspace, protocol parity, and relevant E2E commands |
| Security | authentication, authorization, encryption, secrets, certificates, tenant isolation, audit, threat model |
| Performance | latency percentiles, CPU/memory/storage/network considerations, bottlenecks, benchmark command |
| Scaling | backend limits, replica rules, queues, cache scope, capacity signals |
| Observability | metrics, logs, traces, dashboards, alerts, correlation identifiers |
| Operations | backup, restore, high availability, rolling/canary/blue-green strategy, rollback, incident response |

Prefer a precise link to a canonical runbook over copying a procedure into multiple pages.

## 9. Page template

Copy [`component-page.md`](../templates/component-page.md) for a new component guide. Delete template comments, replace all placeholders, and run the validation commands below.

Documentation is audited by page profile rather than a single indiscriminate checklist:

| Profile | Primary purpose |
|---|---|
| Product | Outcomes, scope, requirements, acceptance, release gates |
| Component | Architecture, implementation, security, operation |
| Flow | One end-to-end interaction and its failure paths |
| Runbook | Detection, containment, recovery, verification, rollback |
| Onboarding | A role-specific path to first successful task |
| Decision | Context, options, decision, consequences |
| Reference | Precise generated, tabular, schema, or status information |
| Guide | Progressive teaching for a concept, integration, or operation |

The generated [Documentation Quality Report](../Documentation_Quality_Report.md) records structural coverage and the prioritized migration backlog. It does not replace factual review.

## 10. Review checklist

- [ ] A beginner can explain the component after Overview and Solution.
- [ ] The page states when to use and when not to use it.
- [ ] Implemented and planned behavior are visibly distinct.
- [ ] Architecture and request flow are diagrammed and explained.
- [ ] Commands are runnable from a stated directory.
- [ ] Examples cover success, failure, and recovery.
- [ ] REST and gRPC remain aligned where an endpoint is involved.
- [ ] Authentication, authorization, secrets, encryption, audit, and tenant isolation are addressed.
- [ ] Latency, CPU, memory, storage, network, bottlenecks, and scaling limits are addressed honestly.
- [ ] Deployment, verification, monitoring, alerting, rollback, backup, restore, and incident response are linked.
- [ ] Internal links and source paths resolve.
- [ ] No secret, invented metric, fake screenshot, or roadmap capability is presented as real.

Run from the repository root:

```bash
node scripts/validate-docs.mjs
node scripts/audit-doc-quality.mjs --check
mkdocs build --strict
```

`validate-docs.mjs` checks the repository-specific inventory, internal links, diagram registry, architecture map, implementation ledger, PRD traceability, and quality-report freshness. `audit-doc-quality.mjs --check` can also be run directly. `mkdocs build --strict` treats publishing warnings as failures.

## References

- [Mandatory architecture patterns](../architecture.md)
- [Documentation redesign plan](../Documentation_Redesign_Plan.md)
- [Documentation audit](../Documentation_Audit.md)
- [Implementation status](../Implementation_Status.md)
- [Diagram index](../AegisAgent_Diagram_Index.md)
