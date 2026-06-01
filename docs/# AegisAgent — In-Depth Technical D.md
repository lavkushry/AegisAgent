# AegisAgent — In-Depth Technical Design Document

**Product:** AegisAgent  
**Category:** Agentic Runtime Security / MCP Security Gateway / Agent Action Firewall  
**Document Type:** Technical Design Document — TDD  
**Version:** v0.1  
**Date:** 2026-05-29  
**Founder:** Lavkush Kumar

***

## 0. Research Foundation

This TDD is based on patterns from the strongest public agent-security and agent-framework work available right now: **Microsoft MCP Gateway**, **LlamaFirewall**, **AgentDojo**, **OpenAI Agents SDK**, **LangGraph human-in-the-loop**, **Cedar Policy**, and **OpenTelemetry**. Microsoft’s MCP Gateway is a reverse proxy and management layer for MCP servers with session-aware routing, authorization, lifecycle management, telemetry, access control, and observability.  LlamaFirewall provides a modular runtime guardrail framework for AI agents with scanners for prompt injection, alignment checks, and insecure code risks.  AgentDojo is a benchmark for tool-using agents executing over untrusted data, with 97 realistic tasks and 629 security test cases.  LangGraph provides human-in-the-loop middleware that can pause tool calls, persist state, and resume after approve/edit/reject/respond decisions.  OpenAI Agents SDK includes agents, tools, handoffs, guardrails, MCP server tool calling, sessions, human-in-the-loop, and tracing.  Cedar is an open-source policy language and authorization engine designed for fine-grained RBAC/ABAC-style permissions and formal analysis, natively written in Rust.  OpenTelemetry is the vendor-neutral standard for traces, metrics, logs, context propagation, and collector-based telemetry pipelines. [\[github.com\]](https://github.com/microsoft/mcp-gateway), [\[microsoft.github.io\]](https://microsoft.github.io/mcp-gateway/) [\[github.com\]](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall), [\[arxiv.org\]](https://arxiv.org/pdf/2505.03574) [\[github.com\]](https://github.com/ethz-spylab/agentdojo), [\[arxiv.org\]](https://arxiv.org/abs/2406.13352) [\[docs.langchain.com\]](https://docs.langchain.com/oss/python/langchain/human-in-the-loop) [\[openai.github.io\]](https://openai.github.io/openai-agents-python/), [\[developers...openai.com\]](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals) [\[github.com\]](https://github.com/cedar-policy), [\[cedarpolicy.com\]](https://cedarpolicy.com/) [\[opentelemetry.io\]](https://opentelemetry.io/)

***

# 1. Technical Vision

## 1.1 Core Technical Thesis

> **AegisAgent is a runtime policy enforcement point between AI agents and the actions they perform.**

AI-agent risk becomes serious when the model output turns into a tool call, API call, MCP call, file operation, deployment, database query, financial action, or external communication. AgentDojo shows that data returned by external tools can hijack AI agents through prompt injection, so the safest enforcement point is the boundary between agent reasoning and tool execution.  LlamaFirewall also argues that modern agents take higher-stakes actions from untrusted inputs and need real-time guardrail monitoring beyond chatbot-focused defenses. [\[arxiv.org\]](https://arxiv.org/abs/2406.13352), [\[github.com\]](https://github.com/ethz-spylab/agentdojo) [\[arxiv.org\]](https://arxiv.org/pdf/2505.03574), [\[github.com\]](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall)

## 1.2 One-Line Technical Definition

> **AegisAgent is an agent-aware API/MCP gateway that intercepts tool calls, evaluates policy, triggers human approval when needed, executes allowed actions through controlled proxies, and writes audit-grade traces.**

## 1.3 Primary Design Goals

AegisAgent must:

1. **Intercept every agent tool call** before execution.
2. **Resolve agent identity** and ownership.
3. **Classify action risk** using tool, resource, environment, source trust, and data sensitivity.
4. **Evaluate policy** using Cedar Policy natively, with optional OPA/Rego later.
5. **Allow, deny, redact, quarantine, or require approval**.
6. **Support MCP-native routing and governance**.
7. **Persist audit-grade evidence** for every decision and execution.
8. **Integrate with LangGraph, OpenAI Agents SDK, CrewAI, AutoGen, and custom agents**.
9. **Expose SIEM/observability exports** via OpenTelemetry and webhooks.

***

# 2. System Overview

## 2.1 High-Level Architecture

```text
+---------------------------+
| User / Application        |
+-------------+-------------+
              |
              v
+---------------------------+
| AI Agent Runtime          |
| LangGraph / OpenAI SDK    |
| CrewAI / AutoGen / Custom |
+-------------+-------------+
              |
              v
+---------------------------+
| AegisAgent SDK / Adapter  |
| Python / TypeScript / Go  |
+-------------+-------------+
              |
              v
+---------------------------------------------------+
| AegisAgent Control Plane + Runtime Gateway         |
|                                                   |
|  +-------------------+    +---------------------+ |
|  | Identity Resolver |    | Context Classifier  | |
|  +-------------------+    +---------------------+ |
|  +-------------------+    +---------------------+ |
|  | Policy Engine     |    | Risk Engine         | |
|  +-------------------+    +---------------------+ |
|  +-------------------+    +---------------------+ |
|  | Approval Engine   |    | Audit Writer        | |
|  +-------------------+    +---------------------+ |
|  +-------------------+    +---------------------+ |
|  | MCP Gateway       |    | Tool Proxy          | |
|  +-------------------+    +---------------------+ |
+----------------------+----------------------------+
                       |
                       v
+---------------------------------------------------+
| External Tools / MCP Servers                       |
| GitHub / Slack / Jira / AWS / DB / Stripe / K8s   |
+---------------------------------------------------+
```

This architecture intentionally separates **policy decision** from **policy enforcement**, which follows the Cedar model: applications query the policy engine with structured JSON input and receive structured decisions.  It also follows MCP Gateway’s separation between a **data plane** for routing MCP traffic and a **control plane** for managing adapters/tools/lifecycle. [\[cedarpolicy.com\]](https://cedarpolicy.com/), [\[github.com\]](https://github.com/cedar-policy) [\[microsoft.github.io\]](https://microsoft.github.io/mcp-gateway/), [\[github.com\]](https://github.com/microsoft/mcp-gateway/blob/main/README.md)

***

# 3. Core Product Scope

## 3.1 MVP Scope

The first technical MVP should protect one high-value workflow:

> **A coding agent connected to GitHub, Slack approval, and one MCP server.**

### MVP must-have capabilities

```text
Agent registry
Tool registry
MCP server registry
Runtime authorization API
Policy engine
GitHub tool proxy
Slack approval workflow
Audit event pipeline
Basic context trust classification
Dashboard timeline
Python SDK
TypeScript SDK
```

This MVP aligns with LangGraph’s tool-call interruption pattern, where actions like file writes or SQL execution can be paused and resumed after human review.  It also aligns with OpenAI Agents SDK’s guidance that guardrails and human review determine whether a run should continue, pause, or stop, especially around side-effecting tool calls and sensitive MCP actions. [\[docs.langchain.com\]](https://docs.langchain.com/oss/python/langchain/human-in-the-loop) [\[developers...openai.com\]](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals)

## 3.2 Out of Scope for MVP

```text
Full SIEM replacement
Full DLP platform
Full AI governance suite
Full model scanning
Full compliance automation
Full cloud security posture management
Automatic remediation
Multi-cloud enterprise deployment
Advanced anomaly ML
```

***

# 4. Component Design

***

## 4.1 AegisAgent SDK

### Purpose

The SDK integrates into agent frameworks and intercepts tool calls before execution.

### Supported SDKs

```text
Python SDK     → LangGraph, OpenAI Agents SDK, CrewAI, AutoGen
TypeScript SDK → OpenAI Agents JS, custom Node agents, MCP clients
Go SDK         → internal gateway/plugin integrations
```

OpenAI Agents SDK provides a lightweight framework with agents, tools, guardrails, handoffs, MCP server tool calling, sessions, human-in-the-loop, and tracing, so AegisAgent should wrap tools and emit compatible traces.  LangGraph provides HITL middleware that checks tool calls against configurable policies, pauses execution, persists graph state, and resumes after human decisions. [\[openai.github.io\]](https://openai.github.io/openai-agents-python/), [\[github.com\]](https://github.com/openai/openai-agents-python) [\[docs.langchain.com\]](https://docs.langchain.com/oss/python/langchain/human-in-the-loop)

### SDK Responsibilities

```text
Register agent metadata
Wrap tool functions
Send authorization request
Pause execution if approval is required
Execute allowed tool through proxy
Return denied/approval-pending response to agent
Attach context trust labels
Emit trace/span metadata
```

### Python SDK Example

```python
from aegisagent import AegisClient, protect_tool

aegis = AegisClient(
    api_key="aegis_xxx",
    agent_id="coding-agent-prod",
    environment="production"
)

@protect_tool(
    client=aegis,
    tool="github",
    action="merge_pull_request",
    risk="high"
)
def merge_pull_request(repo: str, pr_number: int, branch: str):
    return github.merge_pull_request(
        repo=repo,
        pr_number=pr_number,
        branch=branch
    )
```

### TypeScript SDK Example

```typescript
import { AegisClient, protectTool } from "@aegisagent/sdk";

const aegis = new AegisClient({
  apiKey: process.env.AEGIS_API_KEY!,
  agentId: "coding-agent-prod",
  environment: "production",
});

export const mergePullRequest = protectTool({
  client: aegis,
  tool: "github",
  action: "merge_pull_request",
  risk: "high",
  execute: async ({ repo, prNumber, branch }) => {
    return github.mergePullRequest({ repo, prNumber, branch });
  },
});
```

***

## 4.2 Runtime Gateway

### Purpose

The Runtime Gateway is the real-time enforcement point.

It receives tool-call authorization requests, evaluates risk/policy, and returns a decision.

### Responsibilities

```text
Authenticate SDK/gateway requests
Resolve tenant, agent, user, and session
Normalize tool-call payloads
Call context classifier
Call policy engine
Call risk engine
Create approval request if needed
Write audit event
Return decision
```

### Recommended Implementation

```text
Language: Rust
Framework: Axum / Tokio
Policy: Cedar Policy (embedded crate)
Database: SQLite (via SQLx)
Queue: Tokio channels or background async tasks
Telemetry: OpenTelemetry
```

Rust is selected because gateway workloads require concurrency, maximum performance, low memory overhead, no garbage collection pauses, and compile-time memory safety. Microsoft’s MCP Gateway is implemented as a reverse proxy/control plane for MCP routing, authorization, telemetry, and lifecycle management, which validates the gateway pattern for this product. [\[github.com\]](https://github.com/microsoft/mcp-gateway), [\[microsoft.github.io\]](https://microsoft.github.io/mcp-gateway/)

***

## 4.3 Policy Engine

### Purpose

The Policy Engine decides whether an action is allowed, denied, or requires approval.

### Recommendation

Use **Cedar Policy natively for MVP**.

Why Cedar first:

* designed specifically for fast, fine-grained RBAC/ABAC authorization
* natively written in Rust, offering microsecond-level local execution (<100 microseconds)
* supports rule annotations for attaching custom decisions like `require_approval`
* formally verified for correctness and safety
* simpler to read and write compared to OPA/Rego

Cedar decouples policy decisions from enforcement and lets services query decisions using structured JSON input. It is purpose-built for fine-grained authorization and formal reasoning. [\[cedarpolicy.com\]](https://cedarpolicy.com/), [\[github.com\]](https://github.com/cedar-policy)

### OPA Later

OPA/Rego can be evaluated later as a secondary general-purpose policy adapter if customers explicitly request Kubernetes/OPA ecosystem compatibility. [\[github.com\]](https://github.com/open-policy-agent/opa), [\[openpolicyagent.org\]](https://www.openpolicyagent.org/docs)

### Policy Input Example

```json
{
  "tenant": {
    "id": "tenant_123",
    "plan": "growth"
  },
  "agent": {
    "id": "coding-agent-prod",
    "environment": "production",
    "risk_tier": "high",
    "owner_team": "platform"
  },
  "user": {
    "id": "lavkush",
    "role": "engineer",
    "groups": ["platform-engineering"]
  },
  "tool_call": {
    "tool": "github",
    "action": "merge_pull_request",
    "resource": "repo/payments-service/pull/482",
    "mutates_state": true,
    "risk": "high",
    "parameters": {
      "base_branch": "main"
    }
  },
  "context": {
    "source_trust": "untrusted_external",
    "contains_sensitive_data": false
  }
}
```

### Cedar Policy Example

```cedar
// Permit read-only actions
permit (
    principal,
    action,
    resource
)
when {
    resource.mutates_state == false
};

// Production GitHub merges require approval
@decision("require_approval")
@approver_group("platform-leads")
@reason("Production GitHub merges require approval")
permit (
    principal,
    action == Action::"merge_pull_request",
    resource
)
when {
    resource.base_branch == "main" &&
    principal.environment == "production"
};

// High-risk mutating action after untrusted context requires approval
@decision("require_approval")
@approver_group("security-reviewers")
@reason("High-risk action after untrusted context")
permit (
    principal,
    action,
    resource
)
when {
    principal.source_trust == "untrusted_external" &&
    resource.mutates_state == true &&
    resource.risk == "high"
};
```

***

## 4.4 Risk Engine

### Purpose

Policy handles deterministic rules. Risk scoring handles prioritization and routing.

### Risk Inputs

```text
Agent risk tier
Tool action risk
Resource sensitivity
Environment
Context trust
MCP server trust
Data sensitivity
Historical behavior
Approval history
Blast radius
Reversibility
Time of day
User role
```

### Risk Scoring Model

```text
risk_score =
  action_weight
+ environment_weight
+ resource_sensitivity_weight
+ context_trust_penalty
+ mcp_server_penalty
+ sensitive_data_weight
+ anomaly_weight
- prior_approval_credit
```

### Risk Routing

```yaml
risk_routing:
  0_29:
    decision: allow
  30_59:
    decision: allow_and_log
  60_79:
    decision: require_approval
  80_94:
    decision: require_approval_and_notify_security
  95_100:
    decision: deny
```

Risk should not override explicit deny policies. It should enrich policy decisions and route approvals.

***

## 4.5 Approval Engine

### Purpose

The Approval Engine pauses risky actions and gets human authorization.

LangGraph’s HITL middleware defines approve, edit, reject, and respond as decision types, and saves graph state so execution can pause safely and resume later.  OpenAI’s guardrails/human-review guidance also states that human review is the approval path for tool calls, where the model can decide an action is needed but the run pauses until a person approves or rejects it. [\[docs.langchain.com\]](https://docs.langchain.com/oss/python/langchain/human-in-the-loop) [\[developers...openai.com\]](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals)

### Approval States

```text
CREATED
NOTIFIED
APPROVED
EDITED
REJECTED
ESCALATED
EXPIRED
CANCELLED
```

### Approval Flow

```text
1. Runtime Gateway returns require_approval.
2. Approval Engine creates approval_request.
3. Agent execution pauses.
4. Slack/Teams/dashboard notification sent.
5. Human reviews action details.
6. Human approves, edits, rejects, or escalates.
7. Decision is signed and audited.
8. Agent run resumes or terminates.
```

### Slack Approval Payload

```json
{
  "approval_id": "apr_01JABC",
  "agent": "coding-agent-prod",
  "user": "lavkush",
  "action": "github.merge_pull_request",
  "resource": "payments-service#482",
  "risk": "high",
  "reason": "Production merge after untrusted GitHub issue context",
  "buttons": ["Approve", "Edit", "Reject", "Escalate"]
}
```

***

## 4.6 MCP Gateway

### Purpose

The MCP Gateway is the MCP-native enforcement layer.

Microsoft’s MCP Gateway provides a data gateway for routing traffic to MCP servers with session affinity and a control plane for managing MCP server lifecycle, with enterprise integration points including telemetry, access control, and observability.  Other open-source MCP gateways also emphasize authentication, authorization, rate limiting, permissions, observability, metrics, and tool discovery. [\[github.com\]](https://github.com/microsoft/mcp-gateway), [\[microsoft.github.io\]](https://microsoft.github.io/mcp-gateway/) [\[github.com\]](https://github.com/matthisholleville/mcp-gateway), [\[github.com\]](https://github.com/HarrisonCN/mcp-gateway)

### MCP Gateway Responsibilities

```text
Terminate MCP client connections
Authenticate agent/client
Route to approved MCP servers
Expose only approved tools
Inspect tool metadata
Classify MCP tool risk
Authorize every MCP tool call
Apply rate limits
Write audit events
Propagate session affinity
```

### MCP Flow

```text
Agent MCP Client
   |
   v
AegisAgent MCP Gateway
   |
   +--> AuthN/AuthZ
   +--> Tool discovery filter
   +--> Policy decision
   +--> Approval if needed
   +--> Audit event
   |
   v
Approved MCP Server
```

### MCP Tool Manifest

```yaml
mcp_server:
  id: mcp-filesystem-prod
  name: Filesystem MCP Server
  owner_team: platform
  trust_level: restricted
  transport: streamable_http
  source: internal
  version: "1.3.2"

tools:
  - name: read_file
    risk: medium
    mutates_state: false
    data_access: file_content

  - name: write_file
    risk: high
    mutates_state: true
    approval_required: true

  - name: execute_command
    risk: critical
    mutates_state: true
    default_decision: deny
```

***

## 4.7 Context Trust Classifier

### Purpose

Context Trust Classifier labels input/tool-output content based on its trust level and injection risk.

AgentDojo shows that malicious data returned by tools can hijack agents through prompt injection, so AegisAgent needs to propagate trust labels from untrusted context into later tool-call decisions.  LlamaFirewall provides scanner-style layered defenses for prompt injection, alignment checks, insecure code risks, and customizable regex filters across agent workflows. [\[arxiv.org\]](https://arxiv.org/abs/2406.13352), [\[ukgovernme....github.io\]](https://ukgovernmentbeis.github.io/inspect_evals/evals/safeguards/agentdojo/index.html) [\[github.com\]](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall), [\[pypi.org\]](https://pypi.org/project/llamafirewall/)

### Trust Levels

```text
trusted_internal_signed
trusted_internal_unsigned
semi_trusted_customer
untrusted_external
malicious_suspected
unknown
```

### Classifier Inputs

```text
Source type
Source owner
Content origin
Tool result metadata
MCP server trust
Known injection patterns
Sensitive data detection
Regex scanner output
LLM scanner output
Hash/provenance signature
```

### Classifier Output

```json
{
  "source_trust": "untrusted_external",
  "injection_score": 72,
  "contains_sensitive_data": false,
  "classifiers": [
    "prompt_injection_pattern",
    "external_github_issue"
  ]
}
```

***

## 4.8 Audit and Trace Pipeline

### Purpose

AegisAgent must create complete audit timelines for security, debugging, compliance, and incident response.

OpenTelemetry provides vendor-neutral APIs, SDKs, collectors, traces, metrics, logs, baggage, and context propagation across services.  OpenAI Agents SDK includes built-in tracing for visualizing, debugging, monitoring, and evaluating agentic flows. [\[opentelemetry.io\]](https://opentelemetry.io/) [\[openai.github.io\]](https://openai.github.io/openai-agents-python/), [\[mckinsey.com\]](https://www.mckinsey.com/capabilities/risk-and-resilience/our-insights/securing-the-agentic-enterprise-opportunities-for-cybersecurity-providers)

### Event Types

```text
agent_registered
tool_registered
mcp_server_registered
agent_run_started
tool_call_intercepted
policy_decision_created
approval_created
approval_decided
tool_call_executed
tool_result_scanned
memory_read
memory_write
agent_run_completed
policy_updated
security_alert_created
```

### Audit Event Example

```json
{
  "event_id": "evt_01JABC",
  "tenant_id": "tenant_123",
  "timestamp": "2026-05-29T17:06:00+05:30",
  "event_type": "policy_decision_created",
  "agent_id": "coding-agent-prod",
  "user_id": "lavkush",
  "run_id": "run_456",
  "trace_id": "trace_789",
  "tool": "github",
  "action": "merge_pull_request",
  "resource": "payments-service#482",
  "source_trust": "untrusted_external",
  "risk_score": 91,
  "decision": "require_approval",
  "matched_policy_ids": [
    "github-prod-merge-requires-approval",
    "untrusted-context-sensitive-action"
  ],
  "input_hash": "sha256:abc",
  "output_hash": null
}
```

***

# 5. Data Model

## 5.1 Storage Choices

### MVP

```text
SQLite (in-process) → transactional data, policies, approvals, audit events
Tokio channels / Async tasks → async background audit writing
Object storage → long-term trace/event archive
```

### Scale Phase

```text
PostgreSQL / ClickHouse → high-volume audit analytics and transactional scaling
OpenSearch → search and investigation
S3/GCS/Azure Blob → immutable archive
```

SQLite is selected for the MVP because it runs in-process, bypassing all TCP socket overhead, and requires zero local setup. PostgreSQL and ClickHouse can be added in the Scale Phase when multi-node scalability and heavy event indexing are required.

***

## 5.2 Core Tables

### tenants

```sql
CREATE TABLE tenants (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  plan TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### agents

```sql
CREATE TABLE agents (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  agent_key TEXT NOT NULL,
  name TEXT NOT NULL,
  owner_team TEXT,
  owner_email TEXT,
  environment TEXT NOT NULL,
  framework TEXT,
  model_provider TEXT,
  model_name TEXT,
  purpose TEXT,
  risk_tier TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, agent_key)
);
```

### skills

```sql
CREATE TABLE skills (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  skill_key TEXT NOT NULL,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  auth_type TEXT,
  owner_team TEXT,
  default_risk TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, skill_key)
);
```

### skill\_actions

```sql
CREATE TABLE skill_actions (
  id UUID PRIMARY KEY,
  skill_id UUID NOT NULL REFERENCES skills(id),
  action_key TEXT NOT NULL,
  description TEXT,
  risk TEXT NOT NULL,
  mutates_state BOOLEAN NOT NULL DEFAULT false,
  data_access TEXT,
  approval_required BOOLEAN NOT NULL DEFAULT false,
  default_decision TEXT NOT NULL DEFAULT 'policy',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (skill_id, action_key)
);
```

### mcp\_servers

```sql
CREATE TABLE mcp_servers (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  server_key TEXT NOT NULL,
  name TEXT NOT NULL,
  owner_team TEXT,
  transport TEXT NOT NULL,
  source TEXT,
  trust_level TEXT NOT NULL,
  version TEXT,
  status TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, server_key)
);
```

### policies

```sql
CREATE TABLE policies (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  policy_key TEXT NOT NULL,
  name TEXT NOT NULL,
  language TEXT NOT NULL,
  body TEXT NOT NULL,
  version INTEGER NOT NULL,
  status TEXT NOT NULL,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, policy_key, version)
);
```

### decisions

```sql
CREATE TABLE decisions (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  agent_id UUID NOT NULL REFERENCES agents(id),
  user_id TEXT,
  run_id TEXT,
  trace_id TEXT,
  skill TEXT NOT NULL,
  action TEXT NOT NULL,
  resource TEXT,
  input_json JSONB NOT NULL,
  decision TEXT NOT NULL,
  risk_score INTEGER,
  reason TEXT,
  matched_policy_ids TEXT[],
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### approvals

```sql
CREATE TABLE approvals (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  decision_id UUID NOT NULL REFERENCES decisions(id),
  status TEXT NOT NULL,
  approver_group TEXT,
  approver_user_id TEXT,
  reason TEXT,
  original_skill_call JSONB NOT NULL,
  edited_skill_call JSONB,
  expires_at TIMESTAMPTZ,
  decided_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### audit\_events

```sql
CREATE TABLE audit_events (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  event_type TEXT NOT NULL,
  agent_id UUID,
  user_id TEXT,
  run_id TEXT,
  trace_id TEXT,
  span_id TEXT,
  skill TEXT,
  action TEXT,
  resource TEXT,
  event_json JSONB NOT NULL,
  input_hash TEXT,
  output_hash TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

***

# 6. API Design

## 6.1 Public Runtime APIs

### Register Agent

```http
POST /v1/agents/register
Authorization: Bearer <api_key>
Content-Type: application/json
```

```json
{
  "agent_key": "coding-agent-prod",
  "name": "Coding Agent Production",
  "owner_team": "platform",
  "environment": "production",
  "framework": "langgraph",
  "model_provider": "openai",
  "model_name": "gpt-5",
  "risk_tier": "high",
  "purpose": "Review PRs and draft code changes"
}
```

### Authorize Tool Call

```http
POST /v1/authorize
Authorization: Bearer <agent_token>
Content-Type: application/json
```

```json
{
  "request_id": "req_01JABC",
  "agent": {
    "id": "coding-agent-prod",
    "environment": "production"
  },
  "user": {
    "id": "lavkush",
    "role": "engineer"
  },
  "tool_call": {
    "tool": "github",
    "action": "merge_pull_request",
    "resource": "repo/payments-service/pull/482",
    "mutates_state": true,
    "parameters": {
      "base_branch": "main"
    }
  },
  "context": {
    "source_trust": "untrusted_external",
    "contains_sensitive_data": false
  },
  "trace": {
    "run_id": "run_456",
    "trace_id": "trace_789"
  }
}
```

### Authorization Response

```json
{
  "decision_id": "dec_01JABC",
  "decision": "require_approval",
  "risk_score": 91,
  "risk_level": "critical",
  "reason": "Production merge after untrusted external context requires approval.",
  "matched_policies": [
    "github-prod-merge-requires-approval",
    "untrusted-context-sensitive-action"
  ],
  "approval": {
    "approval_id": "apr_01JABC",
    "status": "created",
    "approver_group": "platform-leads",
    "expires_at": "2026-05-29T17:36:00+05:30"
  }
}
```

***

## 6.2 Approval APIs

### Approve

```http
POST /v1/approvals/{approval_id}/approve
Authorization: Bearer <user_token>
```

```json
{
  "approver_user_id": "saket",
  "reason": "PR reviewed and tests passed"
}
```

### Reject

```http
POST /v1/approvals/{approval_id}/reject
Authorization: Bearer <user_token>
```

```json
{
  "approver_user_id": "saket",
  "reason": "Unsafe change; ask agent to create draft PR only"
}
```

### Edit

```http
POST /v1/approvals/{approval_id}/edit
Authorization: Bearer <user_token>
```

```json
{
  "approver_user_id": "saket",
  "edited_tool_call": {
    "tool": "github",
    "action": "comment_on_pr",
    "resource": "repo/payments-service/pull/482",
    "parameters": {
      "comment": "Please wait for human code review before merge."
    }
  },
  "reason": "Downgraded merge to comment"
}
```

***

## 6.3 MCP APIs

### Register MCP Server

```http
POST /v1/mcp/servers
Authorization: Bearer <api_key>
```

```json
{
  "server_key": "mcp-filesystem-prod",
  "name": "Filesystem MCP Server",
  "transport": "streamable_http",
  "source": "internal",
  "trust_level": "restricted",
  "endpoint": "https://mcp-filesystem.internal/mcp"
}
```

### List Approved MCP Tools

```http
GET /v1/mcp/servers/{server_key}/tools
Authorization: Bearer <agent_token>
```

### MCP Tool Authorization

```http
POST /v1/mcp/authorize
Authorization: Bearer <agent_token>
```

```json
{
  "server_key": "mcp-filesystem-prod",
  "tool": "write_file",
  "resource": "/app/config/prod.yaml",
  "arguments": {
    "path": "/app/config/prod.yaml",
    "content_hash": "sha256:abc"
  }
}
```

***

# 7. Runtime Sequences

## 7.1 Allow Flow

```text
Agent proposes tool call
SDK intercepts call
SDK sends /v1/authorize
Gateway authenticates agent
Policy Engine evaluates request
Risk Engine scores low
Decision = allow
Tool Proxy executes tool
Result scanner classifies output
Audit event written
Result returned to agent
```

## 7.2 Deny Flow

```text
Agent proposes dangerous action
SDK sends /v1/authorize
Policy matches deny rule
Decision = deny
Audit event written
Agent receives safe denial message
Tool is never executed
```

## 7.3 Approval Flow

```text
Agent proposes high-risk action
Decision = require_approval
Approval request created
Agent execution pauses
Slack notification sent
Human approves/rejects/edits
Audit event written
If approved, tool executes
If rejected, agent receives feedback
```

## 7.4 MCP Flow

```text
Agent MCP client calls tool
AegisAgent MCP Gateway intercepts
MCP server/tool identity resolved
Tool metadata classified
Policy evaluated
Decision returned
Allowed call routed to MCP server
Response scanned
Audit event written
Response returned to agent
```

***

# 8. Security Design

## 8.1 Trust Boundaries

```text
Boundary 1: User/Application → Agent Runtime
Boundary 2: Agent Runtime → AegisAgent SDK
Boundary 3: SDK → AegisAgent Runtime Gateway
Boundary 4: Gateway → Policy Engine
Boundary 5: Gateway → External Tool/MCP Server
Boundary 6: Gateway → Approval Channels
Boundary 7: Tenant Data → Shared SaaS Infrastructure
```

## 8.2 Authentication

### SDK to Gateway

```text
Agent token
mTLS later for enterprise
Request signing
Short-lived credentials
Tenant-scoped API keys
```

### Human Approver

```text
SSO/OIDC
Slack signed requests
Role/group mapping
Optional SCIM later
```

## 8.3 Authorization

```text
Tenant isolation enforced at every query
Agent identity required for every runtime request
Policies scoped by tenant
Tool access scoped by agent and environment
MCP servers allowed only through registry
Default deny for unknown tools/actions
```

OPA’s model supports arbitrary structured input, which allows AegisAgent to include tenant, agent, user, tool, resource, environment, and context trust attributes in policy decisions.  Cedar can later support fine-grained application permissions with RBAC/ABAC-style policies and analyzability. [\[openpolicyagent.org\]](https://www.openpolicyagent.org/docs) [\[cedarpolicy.com\]](https://cedarpolicy.com/), [\[docs.aws.amazon.com\]](https://docs.aws.amazon.com/prescriptive-guidance/latest/saas-multitenant-api-access-authorization/cedar.html)

## 8.4 Secrets Handling

```text
Never expose customer tokens to agents directly
Store integration secrets in KMS/Vault
Use short-lived delegated tokens where possible
Proxy all sensitive tool calls
Hash sensitive inputs/outputs in audit events
Redact secrets before storage
```

## 8.5 Tenant Isolation

```text
tenant_id required in all relational tables
row-level security optional but recommended
per-tenant encryption keys later
strict API middleware tenant scoping
separate audit partitions for large tenants
```

## 8.6 Supply Chain Security

```text
Signed releases
SBOM generation
Dependency scanning
Container image signing
Reproducible builds later
SAST/DAST in CI
Pinned GitHub Actions
Secret scanning
```

***

# 9. Observability Design

## 9.1 OpenTelemetry Integration

AegisAgent should use OpenTelemetry for traces, metrics, logs, context propagation, and vendor-neutral export. OpenTelemetry is a CNCF-graduated observability framework with APIs, SDKs, agents, collectors, traces, metrics, logs, baggage, and OTLP support. [\[opentelemetry.io\]](https://opentelemetry.io/)

### Traces

```text
aegis.authorize
aegis.policy.evaluate
aegis.risk.score
aegis.approval.create
aegis.tool.execute
aegis.mcp.route
aegis.audit.write
```

### Metrics

```text
authorization_requests_total
authorization_latency_ms
policy_eval_latency_ms
approval_requests_total
approval_timeout_total
tool_calls_allowed_total
tool_calls_denied_total
mcp_calls_total
audit_write_failures_total
```

### Logs

```text
structured JSON logs
tenant_id
agent_id
run_id
trace_id
decision_id
approval_id
policy_version
```

***

# 10. Performance and Scalability

## 10.1 Latency Targets

```text
Authorization p50: < 30 ms
Authorization p95: < 100 ms
Policy evaluation p95: < 50 ms
Audit write async enqueue: < 20 ms
Approval creation: < 200 ms
MCP proxy overhead p95: < 150 ms
```

## 10.2 Scaling Strategy

### Runtime Gateway

```text
Stateless service
Horizontal scaling
Kubernetes HPA
Connection pooling
Read-through cache for policies/tools/agents
```

### Policy Engine

```text
Embedded Cedar Engine for low latency in MVP
Cedar sidecar or central service for enterprise
Policy bundle cache
Versioned policy rollout
```

### Audit Pipeline

```text
Sync minimal event write for critical decisions
Async enrichment through queue
Batch export to ClickHouse/OpenSearch later
Long-term archive to object storage
```

### MCP Gateway

```text
Session-aware routing
Sticky routing by session_id
Per-tenant rate limits
Per-agent concurrency limits
Circuit breakers for unhealthy MCP servers
```

Microsoft’s MCP Gateway explicitly uses session-aware stateful routing and can manage MCP lifecycle in Kubernetes, which supports this architecture direction. [\[github.com\]](https://github.com/microsoft/mcp-gateway), [\[github.com\]](https://github.com/microsoft/mcp-gateway/blob/main/README.md)

***

# 11. Deployment Architecture

## 11.1 MVP SaaS Deployment

```text
Cloud: AWS / Azure / GCP
Runtime: Kubernetes
Ingress: NGINX / Envoy / Cloud LB
API: Rust Runtime Gateway
App: Next.js Dashboard
DB: SQLite / PostgreSQL
Queue: In-memory channels or Redis Streams
Secrets: Cloud KMS + Secret Manager
Telemetry: OpenTelemetry Collector
Logs: Loki/OpenSearch
Metrics: Prometheus/Grafana
```

## 11.2 Self-Hosted Enterprise Deployment

```text
Helm chart
External PostgreSQL support
External Redis/NATS support
Private Docker registry
OIDC/SAML integration
SIEM export
Air-gapped mode later
```

## 11.3 Local Developer Mode

```text
Docker Compose
SQLite
Aegis Runtime Gateway (Rust)
Cedar
Dashboard
Mock GitHub tool
Mock MCP server
Mock Slack approval
```

***

# 12. Dashboard Design

## 12.1 Dashboard Pages

```text
Agents
Tools
MCP Servers
Policies
Approvals
Audit Timeline
Runs
Security Alerts
Settings
```

## 12.2 Agent Detail View

```text
Agent name
Owner
Framework
Environment
Model
Connected tools
MCP servers
Risk tier
Recent actions
Policy coverage
Approval history
Audit timeline
```

## 12.3 Approval Queue

```text
Pending approvals
Risk score
Agent
User
Tool/action/resource
Reason
Approve/edit/reject/escalate actions
```

## 12.4 Investigation Timeline

```text
Run started
User request hash
Tool outputs classified
Tool calls proposed
Policy decisions
Approval events
Tool executions
Final outcome
```

***

# 13. Integration Design

## 13.1 GitHub Integration

### Actions

```text
read_issue
read_pr
comment_on_pr
create_branch
create_pull_request
merge_pull_request
delete_branch
update_file
change_codeowners
```

### Risk Defaults

```text
read_issue: low
comment_on_pr: medium
create_pull_request: medium
merge_pull_request: high
change_codeowners: critical
delete_repository: critical
```

## 13.2 Slack Integration

### Uses

```text
Approval notifications
Security alerts
Policy violation alerts
Daily digest
```

## 13.3 MCP Integration

### Modes

```text
Transparent MCP proxy
Tool router mode
Approved tool catalog
MCP server registry
MCP security scanner later
```

Microsoft’s MCP Gateway uses adapters, tool management, tool gateway routing, authorization, telemetry, and observability, which should inspire AegisAgent’s MCP integration. [\[microsoft.github.io\]](https://microsoft.github.io/mcp-gateway/), [\[github.com\]](https://github.com/microsoft/mcp-gateway/blob/main/README.md)

## 13.4 Framework Integrations

### LangGraph

Use middleware or interrupt/resume.

```text
Tool call → Aegis authorize → allow/deny/interrupt
```

LangGraph’s HITL middleware already provides configurable tool-call interruption and persisted graph state. [\[docs.langchain.com\]](https://docs.langchain.com/oss/python/langchain/human-in-the-loop)

### OpenAI Agents SDK

Wrap function tools and MCP tools.

```text
Tool guardrail → Aegis authorize → human review if required
```

OpenAI’s guide states that tool guardrails can check arguments/results and human approvals can pause before side effects like shell commands or sensitive MCP actions. [\[developers...openai.com\]](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals)

### CrewAI / AutoGen

Use before-tool-call hooks or tool wrappers.

***

# 14. Reliability Design

## 14.1 Failure Modes

### Policy Engine unavailable

```text
Fail closed for production high-risk actions
Fail open only for explicitly configured low-risk read-only actions
Emit critical alert
```

### Approval channel unavailable

```text
Keep approval pending
Fallback to dashboard
Notify email/webhook
Auto-deny on timeout
```

### Audit pipeline unavailable

```text
For critical actions: block if audit cannot be written
For low-risk actions: buffer locally and retry
```

### Tool proxy unavailable

```text
Return retryable error
Do not let agent bypass proxy
```

***

# 15. Evaluation and Testing

## 15.1 Security Evaluation

Use AgentDojo-style evaluation because AgentDojo tests agents executing tools over untrusted data and includes realistic tasks, security test cases, attacks, and defenses. [\[arxiv.org\]](https://arxiv.org/abs/2406.13352), [\[agentdojo.spylab.ai\]](https://agentdojo.spylab.ai/)

### Evaluation Tests

```text
Indirect prompt injection from GitHub issue
Prompt injection from webpage
Malicious MCP tool description
Unauthorized merge PR
Unauthorized file write
Unauthorized external email
Sensitive data exfiltration attempt
Memory write from untrusted source
```

## 15.2 Unit Tests

```text
Policy evaluation tests
Risk scoring tests
SDK tool wrapping tests
Approval state machine tests
Audit event serialization tests
MCP routing tests
```

## 15.3 Integration Tests

```text
LangGraph tool approval
OpenAI Agents SDK tool wrapper
GitHub mock server
Slack approval callback
MCP server mock
OPA policy bundle reload
```

## 15.4 Load Tests

```text
100 authz requests/sec
1,000 authz requests/sec
MCP streaming sessions
Audit burst writes
Approval queue burst
```

***

# 16. CI/CD Design

## 16.1 Repositories

```text
aegisagent
  /gateway
  /sdk-python
  /sdk-typescript
  /dashboard
  /agents
  /skills
  /helm
  /examples
  /docs
```

## 16.2 CI Pipeline

```text
Lint
Type check
Unit tests
Integration tests
Policy tests
Container build
SBOM generation
Dependency scan
Image signing
Helm chart validation
```

## 16.3 Release Strategy

```text
Semantic versioning
Canary deployments
Feature flags
Policy bundle versioning
Backward-compatible API versions
```

***

# 17. MVP Build Plan

## Phase 1 — Core Runtime

```text
Agent registry
Tool registry
Authorize API
Cedar policy engine
SQLite schema
Audit writer
Python SDK
```

## Phase 2 — GitHub + Slack

```text
GitHub App integration
GitHub action manifest
Slack approval bot
Approval state machine
Dashboard approval queue
```

## Phase 3 — MCP Gateway

```text
MCP server registration
MCP tool discovery
MCP authorization
MCP proxy routing
MCP audit events
```

## Phase 4 — Context Trust

```text
Source trust labels
Regex prompt-injection scanner
LlamaFirewall-style scanner integration later
Untrusted-context policy templates
```

LlamaFirewall’s modular scanner architecture is a good future integration point because it supports prompt injection, alignment checks, CodeShield, and customizable regex filters. [\[github.com\]](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall), [\[pypi.org\]](https://pypi.org/project/llamafirewall/)

***

# 18. Recommended Technology Stack

## 18.1 Backend

```text
Rust
SQLite
In-memory channels (Tokio)
Cedar Policy
OpenTelemetry
Docker
Kubernetes
```

## 18.2 Frontend

```text
Next.js
TypeScript
Tailwind
shadcn/ui
Recharts
```

## 18.3 SDKs

```text
Python SDK first
TypeScript SDK second
Go SDK later
```

## 18.4 Security/Infra

```text
KMS / Vault
OIDC
GitHub App auth
Slack OAuth
mTLS later
SBOM
Sigstore/Cosign
```

***

# 19. Key Technical Decisions

## Decision 1: Use Cedar Policy natively

**Reason:** Cedar is purpose-built for application permissions, written in Rust, and runs locally with sub-millisecond latency. [\[cedarpolicy.com\]](https://cedarpolicy.com/)

## Decision 2: Build a gateway, not only an SDK

**Reason:** SDK-only products are easy to bypass. A gateway lets AegisAgent enforce tool/MCP calls centrally, similar to MCP Gateway patterns for routing, authorization, lifecycle management, telemetry, and observability. [\[github.com\]](https://github.com/microsoft/mcp-gateway), [\[microsoft.github.io\]](https://microsoft.github.io/mcp-gateway/)

## Decision 3: Start with GitHub + Slack + MCP

**Reason:** GitHub gives clear high-risk actions, Slack gives easy approvals, and MCP gives a fast-growing agent-tool connectivity wedge. MCP Gateway projects already show demand for routing, authentication, permissions, rate limiting, metrics, monitoring, and tool discovery. [\[github.com\]](https://github.com/matthisholleville/mcp-gateway), [\[github.com\]](https://github.com/HarrisonCN/mcp-gateway)

## Decision 4: Use OpenTelemetry from day one

**Reason:** Agent security needs traces across user request, agent run, policy decision, approval, tool execution, and audit event. OpenTelemetry provides vendor-neutral traces, metrics, logs, collectors, and context propagation. [\[opentelemetry.io\]](https://opentelemetry.io/)

## Decision 5: Treat approvals as first-class state machines

**Reason:** LangGraph and OpenAI both show that human approval must pause execution and resume safely, not happen as an external side conversation. [\[docs.langchain.com\]](https://docs.langchain.com/oss/python/langchain/human-in-the-loop), [\[developers...openai.com\]](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals)

***

# 20. Final Technical Architecture

```text
                         +----------------------+
                         |      Dashboard       |
                         | Next.js / TypeScript |
                         +----------+-----------+
                                    |
                                    v
+----------------+        +----------------------+       +------------------+
| Agent Runtime  | -----> | Aegis Runtime API    | ----> | Policy Engine    |
| LangGraph etc. |        | Rust / REST / gRPC   |       | Cedar Policy     |
+-------+--------+        +----------+-----------+       +------------------+
        |                            |
        |                            v
        |                  +----------------------+
        |                  | Risk + Context       |
        |                  | Classifier           |
        |                  +----------+-----------+
        |                            |
        |                            v
        |                  +----------------------+
        |                  | Approval Engine      |
        |                  | Slack / Teams / UI   |
        |                  +----------+-----------+
        |                            |
        v                            v
+----------------+        +----------------------+       +------------------+
| Aegis SDK      | -----> | Tool Proxy / MCP GW  | ----> | External Tools   |
| Python / TS    |        | Routing + AuthZ      |       | GitHub/MCP/AWS   |
+----------------+        +----------+-----------+       +------------------+
                                    |
                                    v
                         +----------------------+
                         | Audit + Tracing      |
                         | SQLite + OTel        |
                         +----------------------+
```

***

# 21. Founder-Level Technical Recommendation

Build AegisAgent as:

# **Agent Action Firewall**

The minimum valuable technical loop is:

```text
Agent proposes action
→ AegisAgent intercepts
→ Policy evaluates
→ Risk scores
→ Allow / deny / approval
→ Tool executes through proxy
→ Audit event written
```

This is the correct architecture because agent-security risk is concentrated at the point where reasoning becomes action. AgentDojo proves that tool-using agents can be hijacked through untrusted data, LlamaFirewall validates real-time guardrail monitoring for autonomous agents, LangGraph and OpenAI validate pause/resume human approval patterns, Microsoft MCP Gateway validates MCP routing/control-plane architecture, and Cedar/OpenTelemetry provide production-grade policy and observability foundations. [\[arxiv.org\]](https://arxiv.org/abs/2406.13352), [\[arxiv.org\]](https://arxiv.org/pdf/2505.03574), [\[docs.langchain.com\]](https://docs.langchain.com/oss/python/langchain/human-in-the-loop), [\[developers...openai.com\]](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals), [\[github.com\]](https://github.com/microsoft/mcp-gateway), [\[cedarpolicy.com\]](https://cedarpolicy.com/), [\[opentelemetry.io\]](https://opentelemetry.io/)

***

## 22. Next Document to Create

After this TDD, the next most important document is:

# **AegisAgent Threat Model**

Because this is a security startup, the threat model must define:

```text
attacker assumptions
tenant isolation
token handling
MCP trust boundaries
prompt injection paths
approval bypass risks
audit tampering risks
supply-chain risks
agent identity spoofing
policy bypass scenarios
```

That threat model should be written **before implementation** so the MVP is secure by design, not patched later.
