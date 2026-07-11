# Component name

> **Status:** Implemented | Partial | Planned | Missing  
> **Audience:** Students · Developers · Operators · Security · Architects  
> **Time:** _N_ minutes to understand · _N_ minutes to run

## Overview

Give the one-sentence definition, an ELI5 analogy, and the expected reader outcome.

## Why This Exists

Explain why the capability was built, when to use it, when not to use it, design goals, tradeoffs, and business impact.

## Problem Statement

Describe the situation, causes, consequences, and one realistic failure scenario.

## Solution

Explain the solution at beginner, intermediate, advanced, and production levels. State scope and non-goals.

## Architecture

Add the smallest useful Mermaid topology. Explain its trust boundaries and link to the interactive explorer when relevant.

## Component Breakdown

Map every component to its responsibility, implementation status, owner crate, and failure behavior.

## Data Flow

Show what data enters, how it transforms, where it persists, and what leaves. Identify sensitive fields and retention.

## Request Flow

Show the synchronous request path and its latency budget.

## Control Flow

Show decisions, branches, retries, and fail-closed behavior.

## Sequence Diagram

Use `sequenceDiagram`; explain success and failure paths.

## State Diagram

Use `stateDiagram-v2`; define valid and invalid transitions.

## Class Diagram

Use `classDiagram`; show traits, services, protocol adapters, and dependency direction.

## Deployment Architecture

Show local and production topology. Cover trust zones, ports, TLS, storage, observability, HA limits, rolling/blue-green/canary choices, rollback, backup, restore, and disaster recovery.

Describe an optional 3D view: renderer, camera, hover/click behavior, edge animation, live metrics, accessibility, and 2D fallback. Label it conceptual unless it is implemented.

## Folder Structure

Provide a current repository tree and explain why each path owns its responsibility.

## Configuration

Provide the smallest safe YAML or environment configuration. Explain every key, value, port, and secret source.

## Installation

List prerequisites and exact installation steps from a stated working directory.

## Quick Start

Provide a runnable happy path, expected output, verification, and cleanup.

## Detailed Walkthrough

Teach each step without skipping prerequisites or side effects.

## Code Explanation

Use current code or a complete minimal example. Explain each line or logical statement.

## Live Example

Provide small, medium/enterprise, failure, and recovery examples. Never fabricate screenshots or logs.

## API

Document both REST and gRPC. Protobuf is the source of truth. Explain authentication, headers/metadata, fields, responses, errors, idempotency, replay protection, and versioning.

## CLI

Document commands, flags, working directory, outputs, exit behavior, and cleanup.

## Configuration Reference

Table every supported setting: name, type, default, required, sensitive, restart behavior, and effect.

## Security

Cover authentication, authorization, encryption, secrets, certificates, RBAC, tenant isolation, audit, threat model, attack surface, and fail-closed behavior.

## Performance

Cover latency, CPU, memory, storage, network, benchmark methodology, limits, bottlenecks, and optimization.

## Scaling

Cover horizontal/vertical scaling, backend constraints, caches, queues, consistency, HA, and capacity signals.

## Monitoring

Document probes, metrics, traces, dashboards, freshness, units, and ownership.

## Logging

Document format, levels, correlation identifiers, sensitive-data redaction, retention, and sample output.

## Alerting

Provide actionable alert conditions, severity, duration, runbook, and false-positive notes.

## Troubleshooting

Use symptom → likely cause → verification → recovery → prevention.

## Common Mistakes

Explain mistakes and why they fail.

## Best Practices

Provide design, implementation, security, performance, and operations guidance.

## FAQ

Answer beginner, developer, operator, security, architecture, and interview-style questions.

## References

Link canonical docs, source files, standards, ADRs, runbooks, tests, and benchmarks.

