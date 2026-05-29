# AegisAgent — Deep Agent Workflow Design

**Product:** AegisAgent  
**Category:** Agentic Runtime Security / MCP Security / Agent Action Firewall  
**Document Type:** Agent Workflow Design  
**Version:** v0.1  
**Goal:** Design the safest, most practical end-to-end workflow for securing AI agent tool calls, MCP calls, approvals, audit logs, memory/RAG access, and incident investigation.

***

## 1. Design Thesis

AegisAgent should be designed around one core principle:

> **Every meaningful AI agent action must pass through a runtime decision point before it reaches a real tool, API, MCP server, database, code repository, cloud service, or production workflow.**

This thesis is strongly supported by AgentDojo, which shows that tool-using agents are vulnerable when external tool-returned data hijacks the agent through prompt injection, and by LlamaFirewall, which argues that chatbot-era guardrails do not fully address autonomous agents that perform high-stakes actions based on untrusted inputs. [\[arxiv.org\]](https://arxiv.org/abs/2406.13352), [\[arxiv.org\]](https://arxiv.org/pdf/2505.03574)

AegisAgent should therefore not be only a prompt filter, LLM wrapper, or logging dashboard. It should be a **runtime security workflow engine** that sits between the agent runtime and the action layer. MCP research also supports this design because MCP introduces dynamic discovery and bidirectional interaction between AI models and external tools/resources, creating new lifecycle and trust-boundary risks. [\[arxiv.org\]](https://arxiv.org/abs/2503.23278), [\[modelconte...ecurity.io\]](https://modelcontextprotocol-security.io/)

***

## 2. Design Objective

The workflow should answer this question before every risky action:

```text
Should this specific agent be allowed to perform this specific action
on this specific resource, using this specific tool, under this specific context,
at this specific time?
```

This question matters because Agent Security Bench formalizes vulnerabilities across system prompts, user prompt handling, tool usage, and memory retrieval, reporting high attack success rates and limited effectiveness from existing defenses.  AgentPoison further shows that memory and RAG-based agents can be manipulated through poisoned knowledge bases or long-term memory, so AegisAgent must include context and memory provenance in its workflow decisions. [\[openreview.net\]](https://openreview.net/forum?id=V4y0CpX4hK) [\[arxiv.org\]](https://arxiv.org/abs/2407.12784), [\[proceeding...neurips.cc\]](https://proceedings.neurips.cc/paper_files/paper/2024/hash/eb113910e9c3f6242541c1652e30dfd6-Abstract-Conference.html)

***

## 3. Primary Workflow Categories

AegisAgent should support six major workflows:

1. **Agent Registration Workflow**
2. **Tool/MCP Registration Workflow**
3. **Runtime Tool-Call Authorization Workflow**
4. **Human Approval Workflow**
5. **Memory/RAG Trust Workflow**
6. **Audit and Investigation Workflow**

These workflows are aligned with real agent framework patterns: LangGraph supports human-in-the-loop middleware that pauses tool calls and resumes execution after approval, OpenAI Agents SDK supports orchestration, tools, approvals, state, guardrails, and tracing, and Microsoft MCP Gateway implements a reverse proxy and management layer for MCP servers with routing, authorization, telemetry, access control, and observability. [\[docs.langchain.com\]](https://docs.langchain.com/oss/python/langchain/human-in-the-loop), [\[developers...openai.com\]](https://developers.openai.com/api/docs/guides/agents), [\[github.com\]](https://github.com/microsoft/mcp-gateway)

***

# 4. High-Level System Workflow

## 4.1 End-to-End Flow

```text
User / Application
   |
   v
AI Agent Runtime
(LangGraph / OpenAI Agents SDK / CrewAI / AutoGen / Custom Agent)
   |
   v
AegisAgent SDK / Proxy / MCP Gateway
   |
   +--> Agent Identity Resolver
   +--> Context Trust Classifier
   +--> Tool & MCP Registry
   +--> Policy Decision Engine
   +--> Risk Scoring Engine
   +--> Human Approval Engine
   +--> Secrets / Token Broker
   +--> Audit Event Writer
   +--> Observability Exporter
   |
   v
External Tool / MCP Server / API
(GitHub, Slack, Jira, AWS, Kubernetes, Database, Stripe, Filesystem)
```

This design follows the same architectural seam recommended by runtime guardrail patterns: the control should live at the tool boundary, not only inside prompts or after-the-fact logs. CrewAI production guidance also emphasizes that safe agents require a before-tool-call decision point, allow/deny decisions, audit logs, and kill-switch behavior. [\[api.aport.io\]](https://api.aport.io/blog/crewai-guardrails-safe-ai-agents-kill-switch-audit-guide/), [\[github.com\]](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall)

***

## 4.2 Why AegisAgent Must Sit Between Agent and Tool

AegisAgent must intercept the tool call because indirect prompt injection can arrive through external data and influence the agent’s next action. AgentDojo is explicitly built to evaluate agents executing tools over untrusted data, and its benchmark includes realistic tasks and security test cases for prompt-injection-driven agent hijacking. [\[arxiv.org\]](https://arxiv.org/abs/2406.13352), [\[proceeding...neurips.cc\]](https://proceedings.neurips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html)

MCP also increases the importance of this boundary because an MCP client/server setup lets AI models discover and interact with tools/resources dynamically; Microsoft’s MCP Gateway repository describes tool routing, session-aware routing, lifecycle management, authorization, telemetry, and observability as enterprise-ready integration points. [\[arxiv.org\]](https://arxiv.org/abs/2503.23278), [\[github.com\]](https://github.com/microsoft/mcp-gateway)

***

# 5. Workflow 1 — Agent Registration Workflow

## 5.1 Purpose

Before an agent can act, AegisAgent must know:

```text
Who is this agent?
Who owns it?
What is its purpose?
What environment does it run in?
Which tools can it access?
Which MCP servers can it call?
Which memory/RAG stores does it use?
What risk tier does it belong to?
```

This is necessary because identity vendors and security guidance increasingly treat agents as non-human actors that need mapping to owners, applications, permissions, and delegation chains. Orchid’s AI-agent governance positioning emphasizes mapping agents to originating identities, owners, applications, inherited permissions, access paths, chain-of-delegation auditing, and guardrails. [\[bing.com\]](https://bing.com/search?q=AI+agent+security+risks+OWASP+Top+10+LLM+applications+agentic+AI+2025)

## 5.2 Agent Registration Sequence

```text
1. Developer installs AegisAgent SDK.
2. Developer creates agent profile.
3. Agent profile is submitted to AegisAgent Control Plane.
4. Control Plane validates required metadata.
5. Security owner approves or auto-approves based on environment.
6. Agent receives agent_id and signing credentials.
7. Agent becomes visible in inventory.
8. Policies can now target this agent.
```

LangGraph, OpenAI Agents SDK, CrewAI, and AutoGen all support agent-style orchestration, but each framework represents agents differently; AegisAgent should normalize these identities into a single registry. OpenAI’s Agents SDK describes agents as applications that plan, call tools, collaborate across specialists, and keep enough state to complete multi-step work, while CrewAI describes production multi-agent systems with tools, memory, knowledge, guardrails, and observability. [\[developers...openai.com\]](https://developers.openai.com/api/docs/guides/agents), [\[docs.crewai.com\]](https://docs.crewai.com/)

## 5.3 Agent Profile Schema

```yaml
agent:
  id: coding-agent-prod
  name: Coding Agent Production
  owner_team: platform-engineering
  owner_email: platform@example.com
  environment: production
  framework: langgraph
  model_provider: openai
  model_name: gpt-5
  purpose: "Review PRs, create branches, draft fixes, comment on GitHub issues"
  risk_tier: high

runtime:
  deployment: kubernetes
  namespace: ai-agents-prod
  service_account: coding-agent-sa

connected_tools:
  - github
  - slack
  - jira

connected_mcp_servers:
  - mcp-filesystem-readonly
  - mcp-github-tools

memory:
  type: vector_db
  provider: pgvector
  trust_policy: signed_internal_docs_only

approval:
  default_approver_group: platform-leads
```

## 5.4 Agent Registration Decisions

AegisAgent should support these registration decisions:

```text
approved
approved_for_dev_only
requires_security_review
rejected
quarantined
```

This matches the lifecycle concept from MCP security research, which breaks server lifecycle into creation, deployment, operation, and maintenance, and applies safeguards across those phases. [\[arxiv.org\]](https://arxiv.org/abs/2503.23278)

***

# 6. Workflow 2 — Tool and MCP Registration Workflow

## 6.1 Purpose

AegisAgent must know every tool and MCP server before agents use them.

For each tool, AegisAgent should know:

```text
What actions exist?
Which actions are read-only?
Which actions mutate state?
Which actions are irreversible?
Which actions touch sensitive data?
Which actions require approval?
Which resources can be scoped?
```

This is necessary because broad tool access is too coarse. MCP security research warns that MCP enables dynamic discovery between AI models and external tools/resources, and CSA’s MCP security project highlights risks around tool calls, resource reads, provenance, isolation, traffic mediation, auditing, and operational security. [\[arxiv.org\]](https://arxiv.org/abs/2503.23278), [\[modelconte...ecurity.io\]](https://modelcontextprotocol-security.io/)

## 6.2 Tool Registration Sequence

```text
1. Developer connects GitHub, Slack, AWS, DB, or MCP server.
2. AegisAgent introspects available actions.
3. AegisAgent classifies actions by risk.
4. Security owner reviews generated tool manifest.
5. Tool manifest is versioned.
6. Policies are generated from templates.
7. Tool becomes available for agent use through the gateway.
```

Microsoft MCP Gateway’s repository describes MCP tools as registered resources with definitions, metadata, execution endpoints, and input schemas, which supports the need for a tool manifest and routing layer. [\[github.com\]](https://github.com/microsoft/mcp-gateway)

## 6.3 Tool Manifest Example

```yaml
tool:
  id: github
  type: rest_api
  owner: platform-engineering
  auth_type: github_app
  default_risk: medium

actions:
  - name: read_issue
    risk: low
    mutates_state: false
    approval_required: false

  - name: comment_on_pr
    risk: medium
    mutates_state: true
    approval_required: false

  - name: create_branch
    risk: medium
    mutates_state: true
    approval_required: false

  - name: merge_pull_request
    risk: high
    mutates_state: true
    approval_required: true

  - name: delete_repository
    risk: critical
    mutates_state: true
    approval_required: true
    default_decision: deny
```

## 6.4 MCP Server Manifest Example

```yaml
mcp_server:
  id: mcp-filesystem-prod
  transport: streamable_http
  owner: platform-engineering
  trust_level: restricted
  source: internal
  version: 1.3.2

tools:
  - name: read_file
    risk: medium
    data_access: file_content
    approval_required: false

  - name: write_file
    risk: high
    mutates_state: true
    approval_required: true

  - name: execute_command
    risk: critical
    mutates_state: true
    approval_required: true
    default_decision: deny
```

MCP Safety Audit research reports that MCP workflows may be exploitable for malicious code execution, remote access control, and credential theft, and introduces MCPSafetyScanner for assessing MCP server safety; this supports AegisAgent’s need to classify MCP tools and block dangerous actions. [\[huggingface.co\]](https://huggingface.co/papers/2504.03767)

***

# 7. Workflow 3 — Runtime Tool-Call Authorization Workflow

## 7.1 Purpose

This is the core workflow of AegisAgent.

Before a tool call executes, AegisAgent evaluates:

```text
agent identity
user identity
tool
action
resource
input parameters
environment
source trust
data sensitivity
MCP server trust
policy version
risk score
approval requirement
```

This design matches LangGraph’s human-in-the-loop middleware model, where tool calls are checked against configurable policies and execution can pause for approval, editing, rejection, or direct human response. [\[docs.langchain.com\]](https://docs.langchain.com/oss/python/langchain/human-in-the-loop)

## 7.2 Runtime Authorization Sequence

```text
1. User asks agent to perform task.
2. Agent plans next action.
3. Agent proposes tool call.
4. AegisAgent SDK intercepts tool call.
5. SDK signs request and sends decision request to AegisAgent.
6. AegisAgent resolves agent identity.
7. AegisAgent classifies context trust.
8. AegisAgent evaluates policy.
9. AegisAgent computes risk score.
10. Decision is returned:
    - allow
    - deny
    - require_approval
    - redact
    - quarantine
    - log_only
11. If allowed, tool executes through AegisAgent proxy.
12. Tool result is scanned/classified.
13. Audit event is written.
14. Agent receives sanitized result.
```

LlamaFirewall supports the idea of layered runtime scanning for prompt injection, alignment/misalignment, and insecure code risks, while OpenAI Agents SDK tracing records LLM generations, tool calls, handoffs, guardrails, and custom events during agent runs. [\[github.com\]](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall), [\[openai.github.io\]](https://openai.github.io/openai-agents-python/tracing/)

## 7.3 Decision Request Schema

```json
{
  "request_id": "req_01J...",
  "timestamp": "2026-05-29T17:15:00+05:30",
  "agent": {
    "id": "coding-agent-prod",
    "environment": "production",
    "framework": "langgraph",
    "risk_tier": "high"
  },
  "user": {
    "id": "lavkush",
    "role": "engineer",
    "auth_context": "sso"
  },
  "tool_call": {
    "tool": "github",
    "action": "merge_pull_request",
    "resource": "repo/payments-service/pull/482",
    "parameters": {
      "base_branch": "main",
      "head_branch": "agent/fix-payment-bug"
    }
  },
  "context": {
    "source": "github_issue",
    "source_trust": "untrusted",
    "contains_external_content": true,
    "contains_sensitive_data": false
  },
  "trace": {
    "conversation_id": "conv_123",
    "run_id": "run_456",
    "parent_span_id": "span_789"
  }
}
```

## 7.4 Decision Response Schema

```json
{
  "decision_id": "dec_01J...",
  "request_id": "req_01J...",
  "decision": "require_approval",
  "risk_score": 87,
  "risk_level": "high",
  "matched_policies": [
    "prod-github-merge-requires-approval",
    "untrusted-context-sensitive-action"
  ],
  "reason": "Agent attempted to merge into main after reading untrusted GitHub issue content.",
  "approval": {
    "approval_id": "apr_01J...",
    "approver_group": "platform-leads",
    "timeout_seconds": 1800
  },
  "audit": {
    "event_written": true,
    "event_id": "evt_01J..."
  }
}
```

AgentDojo and Agent Security Bench both justify storing context and policy decisions because attacks can occur through tool outputs, prompt handling, tool usage, and memory retrieval rather than only direct user input. [\[arxiv.org\]](https://arxiv.org/abs/2406.13352), [\[openreview.net\]](https://openreview.net/forum?id=V4y0CpX4hK)

***

# 8. Workflow 4 — Human Approval Workflow

## 8.1 Purpose

Human approval should be used only when risk is meaningful.

AegisAgent should not ask humans to approve every action. It should approve low-risk actions automatically, monitor medium-risk actions, require approval for high-risk actions, and deny critical actions by default unless an explicit break-glass policy exists.

LangGraph’s HITL middleware supports approve, edit, reject, and respond decision types, and it persists graph state so execution can pause and resume later.  AutoGen’s human-in-the-loop design also describes a UserProxyAgent that transfers control to the application/user and waits for feedback before continuing execution. [\[docs.langchain.com\]](https://docs.langchain.com/oss/python/langchain/human-in-the-loop) [\[microsoft.github.io\]](https://microsoft.github.io/autogen/stable/user-guide/agentchat-user-guide/tutorial/human-in-the-loop.html)

## 8.2 Approval Decision Types

```text
approve
edit
reject
respond
escalate
expire
auto_deny
```

LangGraph explicitly supports approve, edit, reject, and respond as built-in human decision types for interrupted tool calls. [\[docs.langchain.com\]](https://docs.langchain.com/oss/python/langchain/human-in-the-loop)

## 8.3 Human Approval Sequence

```text
1. Runtime policy returns require_approval.
2. AegisAgent freezes the tool call.
3. Agent state is checkpointed.
4. Approval request is sent to Slack, Teams, or dashboard.
5. Approver reviews:
   - agent identity
   - user intent
   - tool/action/resource
   - parameters
   - source trust
   - risk reason
   - policy match
6. Approver chooses approve/edit/reject/respond/escalate.
7. Decision is signed and written to audit log.
8. If approved, tool call executes.
9. If edited, modified tool call is re-evaluated.
10. If rejected, agent receives rejection reason.
11. Agent continues or terminates safely.
```

This sequence follows LangGraph’s persisted interrupt model, where execution pauses safely and resumes after a human decision, and aligns with OpenAI Agents SDK’s guidance that SDK-based agent apps own orchestration, tool execution, approvals, and state. [\[docs.langchain.com\]](https://docs.langchain.com/oss/python/langchain/human-in-the-loop), [\[developers...openai.com\]](https://developers.openai.com/api/docs/guides/agents)

## 8.4 Slack Approval Message

```text
AegisAgent Approval Request

Agent: coding-agent-prod
User: lavkush
Action: github.merge_pull_request
Resource: payments-service#482 → main
Risk: High
Reason: Production branch modification after untrusted GitHub issue context

Policy matched:
- prod-github-merge-requires-approval
- untrusted-context-sensitive-action

Buttons:
[Approve] [Edit] [Reject] [Escalate]
```

## 8.5 Approval Timeout Behavior

```yaml
approval_timeout_policy:
  default_timeout_minutes: 30
  on_timeout: auto_deny
  notify:
    - requester
    - approver_group
  audit: true
```

For concurrent or asynchronous human review, Microsoft Q\&A guidance for agentic human-in-the-loop scenarios recommends a dedicated queue or decision manager, state management for pending requests, and callback-style APIs for human intervention. [\[learn.microsoft.com\]](https://learn.microsoft.com/en-us/answers/questions/2168187/how-to-handle-the-human-in-the-loop-for-concurrent)

***

# 9. Workflow 5 — Context Trust and Prompt-Injection Workflow

## 9.1 Purpose

AegisAgent must classify the trust level of content before allowing it to influence actions.

Untrusted content includes:

```text
public webpages
GitHub issues from external users
Slack messages from guests
emails
support tickets
PDF uploads
MCP tool responses from unknown servers
third-party documents
database rows from user-generated content
```

AgentDojo demonstrates that external data returned by tools can hijack agents into malicious tasks, and LlamaFirewall highlights indirect prompt injection through webpages, emails, and other untrusted inputs as a unique risk for agents that take high-stakes actions. [\[arxiv.org\]](https://arxiv.org/abs/2406.13352), [\[failurefirst.org\]](https://failurefirst.org/daily-paper/llamafirewall-open-source-guardrail-system-secure-ai-agents/)

## 9.2 Context Trust Levels

```text
trusted_internal_signed
trusted_internal_unsigned
semi_trusted_customer
untrusted_external
malicious_suspected
unknown
```

## 9.3 Trust Classification Sequence

```text
1. Tool returns data to agent.
2. AegisAgent intercepts tool output.
3. Output source is classified.
4. Content is scanned for injection patterns.
5. Sensitive data is detected.
6. Context trust label is attached.
7. Trust label follows the agent run.
8. Future tool-call policies use this trust label.
```

LlamaFirewall provides scanner-style architecture for prompt injection and agent misalignment, while AgentDojo provides benchmark scenarios where malicious data returned by tools attempts to hijack an agent’s behavior. [\[github.com\]](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall), [\[arxiv.org\]](https://arxiv.org/abs/2406.13352)

## 9.4 Example Policy: Untrusted Context Cannot Trigger Sensitive Action

```yaml
id: block-untrusted-context-sensitive-actions
description: "Untrusted content cannot directly trigger sensitive mutating actions."

when:
  context.source_trust:
    in:
      - untrusted_external
      - malicious_suspected
  tool_call.mutates_state: true
  tool_call.risk:
    in:
      - high
      - critical

then:
  decision: require_approval
  reason: "High-risk mutating action triggered after untrusted context."
```

***

# 10. Workflow 6 — MCP Gateway Workflow

## 10.1 Purpose

AegisAgent should support MCP-native enforcement because MCP is becoming a common way for agents to connect with external tools and resources.

The MCP paper defines MCP as an emerging open standard for unified, bidirectional communication and dynamic discovery between AI models and external tools/resources, and Microsoft MCP Gateway provides a concrete implementation pattern for routing, authorization, lifecycle management, telemetry, and observability in Kubernetes environments. [\[arxiv.org\]](https://arxiv.org/abs/2503.23278), [\[github.com\]](https://github.com/microsoft/mcp-gateway)

## 10.2 MCP Call Flow

```text
AI Agent
   |
   v
MCP Client
   |
   v
AegisAgent MCP Gateway
   |
   +--> Validate agent identity
   +--> Validate MCP server identity
   +--> Validate tool metadata
   +--> Classify tool risk
   +--> Evaluate policy
   +--> Require approval if needed
   +--> Execute MCP tools/call
   +--> Scan result
   +--> Audit event
   |
   v
MCP Server
```

CSA’s MCP security project highlights hardening, provenance, isolation, traffic mediation, operational security, known vulnerabilities, audit/compliance, and MCP Top 10 risks, supporting the need for an MCP gateway workflow rather than direct agent-to-server calls. [\[modelconte...ecurity.io\]](https://modelcontextprotocol-security.io/)

## 10.3 MCP Tool Discovery Workflow

```text
1. MCP server connects to AegisAgent.
2. AegisAgent retrieves tool list and schemas.
3. AegisAgent computes tool risk score.
4. Tool descriptions are scanned for suspicious instructions.
5. Security owner approves MCP server/tool set.
6. AegisAgent publishes only approved tools to agents.
7. Agents call tools through AegisAgent, not directly.
```

MCP security research identifies lifecycle phases and threat scenarios across malicious developers, external attackers, malicious users, and security flaws, so AegisAgent should review MCP tools before publishing them to agents. [\[arxiv.org\]](https://arxiv.org/abs/2503.23278)

## 10.4 MCP Server Risk Score Inputs

```yaml
mcp_risk_inputs:
  source:
    - internal
    - verified_vendor
    - open_source
    - unknown
  transport_security:
    - tls_required
    - auth_required
  tool_capabilities:
    - read_files
    - write_files
    - execute_commands
    - access_network
    - access_credentials
    - mutate_cloud
  provenance:
    - signed_release
    - pinned_version
    - reviewed_code
  observability:
    - logs_enabled
    - audit_enabled
```

MCP Safety Audit reports MCP exploit classes such as malicious code execution, remote access control, and credential theft, which justifies scoring capabilities such as command execution, filesystem access, network access, and credential access. [\[huggingface.co\]](https://huggingface.co/papers/2504.03767)

***

# 11. Workflow 7 — Memory and RAG Trust Workflow

## 11.1 Purpose

AegisAgent should not trust agent memory blindly.

Memory/RAG stores influence future actions, so AegisAgent must control:

```text
memory writes
memory reads
RAG ingestion
retrieved chunks
document provenance
poisoning suspicion
cross-user memory sharing
```

AgentPoison shows that poisoning long-term memory or RAG knowledge bases can backdoor LLM agents without model training or fine-tuning, and reports high attack success with low poison rates. [\[arxiv.org\]](https://arxiv.org/abs/2407.12784), [\[billchan22....github.io\]](https://billchan226.github.io/AgentPoison)

## 11.2 Memory Write Workflow

```text
1. Agent proposes memory write.
2. AegisAgent intercepts memory write.
3. Source trust is evaluated.
4. Content is scanned for embedded instructions.
5. Memory sensitivity is classified.
6. Policy determines allow/deny/approval.
7. Approved memory is stored with provenance.
8. Memory write event is audited.
```

AgentPoison’s threat model is specifically about poisoning memory or knowledge bases used by LLM agents, so memory writes must be governed like tool calls. [\[github.com\]](https://github.com/AI-secure/AgentPoison), [\[proceeding...neurips.cc\]](https://proceedings.neurips.cc/paper_files/paper/2024/hash/eb113910e9c3f6242541c1652e30dfd6-Abstract-Conference.html)

## 11.3 Memory Object Schema

```json
{
  "memory_id": "mem_01J...",
  "agent_id": "support-agent-prod",
  "source": "zendesk_ticket",
  "source_trust": "semi_trusted_customer",
  "created_by": "agent",
  "approved_by": null,
  "sensitivity": "customer_data",
  "content_hash": "sha256:...",
  "embedding_model": "text-embedding-3-large",
  "poisoning_score": 41,
  "allowed_for_retrieval": true,
  "created_at": "2026-05-29T17:20:00+05:30"
}
```

## 11.4 RAG Retrieval Workflow

```text
1. Agent asks question.
2. Retriever fetches candidate chunks.
3. AegisAgent receives retrieved chunks.
4. Chunks are ranked by relevance and trust.
5. Suspicious chunks are filtered or downgraded.
6. Trust metadata is attached to context.
7. Agent receives trusted/sanitized context.
8. Future tool calls inherit context trust.
```

This workflow is justified by AgentPoison’s demonstration that poisoned retrieval can influence planning and execution in agents, especially when agents rely on retrieved demonstrations or knowledge. [\[billchan22....github.io\]](https://billchan226.github.io/AgentPoison), [\[arxiv.org\]](https://arxiv.org/abs/2407.12784)

***

# 12. Workflow 8 — Audit and Investigation Workflow

## 12.1 Purpose

AegisAgent must create a complete event trail for every important action.

OpenAI Agents SDK tracing captures LLM generations, tool calls, handoffs, guardrails, and custom events, which shows the kind of traceability modern agent systems need. [\[openai.github.io\]](https://openai.github.io/openai-agents-python/tracing/), [\[github.com\]](https://github.com/openai/openai-agents-python/blob/main/docs/tracing.md)

## 12.2 Audit Event Lifecycle

```text
1. Agent run starts.
2. AegisAgent creates run event.
3. Each tool call creates decision event.
4. Each approval creates approval event.
5. Each tool execution creates execution event.
6. Each tool result creates result event.
7. Each memory write/read creates memory event.
8. Run completion creates summary event.
9. Events are linked into an investigation timeline.
```

Microsoft MCP Gateway and CrewAI both emphasize observability/tracing for production agent systems, supporting the need to treat audit as a first-class workflow. [\[github.com\]](https://github.com/microsoft/mcp-gateway), [\[github.com\]](https://github.com/crewAIInc/crewAI)

## 12.3 Audit Event Schema

```json
{
  "event_id": "evt_01J...",
  "event_type": "tool_call_decision",
  "timestamp": "2026-05-29T17:25:00+05:30",
  "tenant_id": "tenant_abc",
  "agent_id": "coding-agent-prod",
  "user_id": "lavkush",
  "run_id": "run_456",
  "trace_id": "trace_789",
  "tool": "github",
  "action": "merge_pull_request",
  "resource": "payments-service#482",
  "source_trust": "untrusted_external",
  "risk_score": 87,
  "decision": "require_approval",
  "policy_version": "v12",
  "matched_policies": [
    "prod-github-merge-requires-approval"
  ],
  "input_hash": "sha256:...",
  "output_hash": null,
  "approval_id": "apr_01J..."
}
```

## 12.4 Investigation Timeline Example

```text
10:01 User asked coding-agent-prod to fix payment bug.
10:02 Agent read GitHub issue #482.
10:02 AegisAgent labeled issue content as untrusted_external.
10:03 Agent created branch agent/fix-payment-bug.
10:05 Agent opened PR #503.
10:06 Agent attempted to merge PR into main.
10:06 AegisAgent required approval.
10:08 Platform lead rejected merge request.
10:08 Agent received rejection reason.
10:09 Agent posted safe summary comment instead.
```

AgentDojo and LlamaFirewall both support the idea that agent failures must be understood across multi-step trajectories rather than single prompts. [\[arxiv.org\]](https://arxiv.org/abs/2406.13352), [\[arxiv.org\]](https://arxiv.org/pdf/2505.03574)

***

# 13. Recommended AegisAgent Internal Agents

AegisAgent itself can use internal agents, but carefully. These internal agents should assist with analysis, policy suggestions, and investigation — not directly execute customer actions.

## 13.1 Policy Advisor Agent

**Purpose:** Suggest policies from observed agent behavior.

```text
Input:
- recent tool calls
- risk patterns
- existing policies
- rejected approvals

Output:
- suggested policy changes
- risky gaps
- unused permissions
```

This is useful because Agent Security Bench shows vulnerabilities across multiple agent operation stages, so policies need continuous improvement. [\[openreview.net\]](https://openreview.net/forum?id=V4y0CpX4hK)

## 13.2 Incident Investigator Agent

**Purpose:** Build human-readable RCA timelines from audit logs.

```text
Input:
- run events
- tool calls
- approval decisions
- policy matches
- context trust labels

Output:
- timeline
- root cause summary
- blast radius
- recommended controls
```

OpenAI Agents SDK tracing supports this style because it structures workflows into traces and spans for debugging, visualization, and monitoring. [\[openai.github.io\]](https://openai.github.io/openai-agents-python/tracing/)

## 13.3 MCP Risk Analyst Agent

**Purpose:** Analyze MCP server manifests and tool descriptions.

```text
Input:
- MCP tool list
- input schemas
- permissions
- source repository
- known vulnerabilities

Output:
- risk score
- suspicious tools
- recommended allow/deny policies
```

MCP research identifies lifecycle risks and threat scenarios in MCP implementations, and MCP Safety Audit introduces an agentic scanner to assess MCP server security. [\[arxiv.org\]](https://arxiv.org/abs/2503.23278), [\[huggingface.co\]](https://huggingface.co/papers/2504.03767)

## 13.4 Memory Trust Agent

**Purpose:** Review suspicious memory/RAG chunks.

```text
Input:
- new memory writes
- retrieved chunks
- source trust
- poisoning score
- semantic similarity anomalies

Output:
- allow
- quarantine
- require review
- delete recommendation
```

AgentPoison directly supports this module because it shows that poisoned memory or RAG knowledge bases can backdoor agents while preserving benign behavior. [\[billchan22....github.io\]](https://billchan226.github.io/AgentPoison), [\[arxiv.org\]](https://arxiv.org/abs/2407.12784)

***

# 14. State Machine Design

## 14.1 Agent Action State Machine

```text
PROPOSED
   |
   v
INTERCEPTED
   |
   v
CLASSIFIED
   |
   v
POLICY_EVALUATED
   |
   +--> ALLOWED ---------> EXECUTED ---------> RESULT_SCANNED ---------> COMPLETED
   |
   +--> DENIED ----------> REJECTED_TO_AGENT -> COMPLETED
   |
   +--> APPROVAL_REQUIRED -> WAITING_FOR_APPROVAL
                                  |
                                  +--> APPROVED -> EXECUTED -> RESULT_SCANNED -> COMPLETED
                                  |
                                  +--> EDITED -> RE_EVALUATE
                                  |
                                  +--> REJECTED -> REJECTED_TO_AGENT -> COMPLETED
                                  |
                                  +--> EXPIRED -> AUTO_DENIED -> COMPLETED
   |
   +--> QUARANTINED -----> SECURITY_REVIEW
```

This state model is consistent with LangGraph’s interrupt/resume pattern and approval decision types, and with CrewAI guidance that tool calls should be checked before execution with deterministic allow/deny paths and audit trails. [\[docs.langchain.com\]](https://docs.langchain.com/oss/python/langchain/human-in-the-loop), [\[api.aport.io\]](https://api.aport.io/blog/crewai-guardrails-safe-ai-agents-kill-switch-audit-guide/)

## 14.2 Approval State Machine

```text
CREATED
   |
   v
NOTIFIED
   |
   +--> APPROVED
   +--> EDITED
   +--> REJECTED
   +--> ESCALATED
   +--> EXPIRED
   +--> CANCELLED
```

Human-in-loop workflows need resumable state; LangGraph uses persistence/checkpointing for safe pause/resume, while Microsoft guidance for asynchronous HIL recommends state management to track pending requests. [\[docs.langchain.com\]](https://docs.langchain.com/oss/python/langchain/human-in-the-loop), [\[learn.microsoft.com\]](https://learn.microsoft.com/en-us/answers/questions/2168187/how-to-handle-the-human-in-the-loop-for-concurrent)

***

# 15. Policy Engine Workflow

## 15.1 Policy Evaluation Inputs

```yaml
inputs:
  agent:
    id: string
    owner_team: string
    environment: string
    risk_tier: string

  user:
    id: string
    role: string
    groups: list

  tool_call:
    tool: string
    action: string
    resource: string
    parameters: object
    mutates_state: boolean

  context:
    source_trust: string
    contains_sensitive_data: boolean
    contains_external_content: boolean

  mcp:
    server_id: string
    server_trust: string
    tool_risk: string

  runtime:
    time: string
    ip: string
    session_id: string
```

## 15.2 Example Policy: GitHub Production Merge

```yaml
id: github-prod-merge-requires-approval
description: "Production branch merges require platform approval."

when:
  tool_call.tool: github
  tool_call.action: merge_pull_request
  tool_call.parameters.base_branch: main
  agent.environment: production

then:
  decision: require_approval
  approver_group: platform-leads
  reason: "Merging into production branch requires human approval."
```

## 15.3 Example Policy: Deny Dangerous MCP Tool

```yaml
id: deny-mcp-execute-command-prod
description: "Agents cannot execute shell commands through MCP in production."

when:
  mcp.server_id: "*"
  tool_call.action: execute_command
  agent.environment: production

then:
  decision: deny
  reason: "Command execution through MCP is disabled in production."
```

MCP Safety Audit’s examples of malicious code execution and credential theft justify strict default-deny rules for command execution and sensitive filesystem operations. [\[huggingface.co\]](https://huggingface.co/papers/2504.03767)

***

# 16. Risk Scoring Workflow

## 16.1 Risk Inputs

```text
base action risk
agent risk tier
resource sensitivity
environment
source trust
MCP server trust
data sensitivity
historical behavior
approval history
blast radius
reversibility
```

## 16.2 Risk Score Formula

```text
risk_score =
  action_risk
+ resource_sensitivity
+ environment_weight
+ source_trust_penalty
+ mcp_trust_penalty
+ data_sensitivity
+ anomaly_score
- existing_approval_credit
```

This scoring should not replace policy. It should support routing decisions such as allow, deny, approval, or escalation. AgentDojo, Agent Security Bench, and LlamaFirewall all show that attacks and defenses vary by context, tool use, and execution path, so risk should be contextual rather than static. [\[arxiv.org\]](https://arxiv.org/abs/2406.13352), [\[openreview.net\]](https://openreview.net/forum?id=V4y0CpX4hK), [\[arxiv.org\]](https://arxiv.org/pdf/2505.03574)

## 16.3 Risk Routing

```yaml
risk_routing:
  0-29:
    decision: allow
  30-59:
    decision: allow_and_log
  60-79:
    decision: require_approval
  80-94:
    decision: require_approval_and_security_notify
  95-100:
    decision: deny
```

***

# 17. Framework Integration Workflow

## 17.1 LangGraph Integration

AegisAgent should integrate naturally with LangGraph because LangGraph supports interruptible tool calls, policy-based human-in-the-loop middleware, and persisted state for pause/resume. [\[docs.langchain.com\]](https://docs.langchain.com/oss/python/langchain/human-in-the-loop)

```text
LangGraph Agent
   |
   v
Tool Call Middleware
   |
   v
AegisAgent Decision API
   |
   +--> allow: execute tool
   +--> require_approval: interrupt graph
   +--> deny: return rejection tool result
```

## 17.2 OpenAI Agents SDK Integration

OpenAI Agents SDK is appropriate for code-first agent applications where the app owns orchestration, tool execution, approvals, and state, and it has built-in tracing for LLM generations, tool calls, handoffs, guardrails, and custom events. [\[developers...openai.com\]](https://developers.openai.com/api/docs/guides/agents), [\[openai.github.io\]](https://openai.github.io/openai-agents-python/tracing/)

```text
OpenAI Agent Runner
   |
   v
Function Tool Wrapper
   |
   v
AegisAgent authorize()
   |
   v
Execute / Pause / Deny
```

## 17.3 CrewAI Integration

CrewAI provides agents, tasks, flows, guardrails, memory, knowledge, and observability, and production guidance emphasizes before-tool-call enforcement, kill switches, and action audit trails. [\[docs.crewai.com\]](https://docs.crewai.com/), [\[api.aport.io\]](https://api.aport.io/blog/crewai-guardrails-safe-ai-agents-kill-switch-audit-guide/)

```text
CrewAI Tool
   |
   v
before_tool_call hook
   |
   v
AegisAgent Decision API
   |
   v
execute or block
```

## 17.4 AutoGen Integration

AutoGen supports multi-agent applications that can act autonomously or alongside humans, and its human-in-the-loop docs describe UserProxyAgent feedback during a team run. [\[github.com\]](https://github.com/microsoft/autogen), [\[microsoft.github.io\]](https://microsoft.github.io/autogen/stable/user-guide/agentchat-user-guide/tutorial/human-in-the-loop.html)

```text
AutoGen AssistantAgent
   |
   v
Tool/Code Executor
   |
   v
AegisAgent Proxy
   |
   v
Human approval or execution
```

***

# 18. MVP Workflow Design

## 18.1 MVP Scenario

The best MVP workflow:

> **Secure a coding agent connected to GitHub, Slack, and one MCP server.**

This is practical because GitHub actions are easy to understand, Slack approval is easy to demo, and MCP introduces a modern tool-security wedge. AgentDojo and MCP research both support this use case because they focus on tool-using agents and MCP tool/resource interaction risks. [\[arxiv.org\]](https://arxiv.org/abs/2406.13352), [\[arxiv.org\]](https://arxiv.org/abs/2503.23278)

## 18.2 MVP Flow

```text
1. Developer registers coding-agent-prod.
2. Developer connects GitHub App.
3. Developer connects Slack workspace.
4. Developer connects mcp-filesystem-readonly.
5. AegisAgent generates default policies.
6. Agent reads GitHub issue.
7. AegisAgent labels issue as untrusted_external.
8. Agent proposes PR creation.
9. AegisAgent allows PR creation.
10. Agent proposes merge into main.
11. AegisAgent requires Slack approval.
12. Platform lead approves or rejects.
13. AegisAgent writes audit timeline.
```

## 18.3 MVP Must-Have States

```text
registered_agent
registered_tool
policy_active
tool_call_intercepted
decision_returned
approval_pending
approval_decided
tool_executed
audit_written
```

## 18.4 MVP Must-Have APIs

```text
POST /v1/agents/register
POST /v1/tools/register
POST /v1/mcp/register
POST /v1/authorize
POST /v1/approvals/{id}/approve
POST /v1/approvals/{id}/reject
GET  /v1/audit/events
GET  /v1/runs/{run_id}/timeline
```

***

# 19. Killer Demo Workflow

## 19.1 Demo Name

**“Malicious GitHub Issue vs Coding Agent”**

## 19.2 Demo Story

```text
A coding agent is asked to fix a bug from GitHub issue #482.
The issue contains malicious hidden instructions.
The agent reads the issue and tries to merge unsafe code.
AegisAgent detects untrusted context and high-risk action.
AegisAgent blocks or requires approval.
The full timeline is shown in audit logs.
```

This demo maps directly to AgentDojo’s threat model: malicious data returned by tools hijacks an agent to execute malicious tasks. [\[arxiv.org\]](https://arxiv.org/abs/2406.13352), [\[proceeding...neurips.cc\]](https://proceedings.neurips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html)

## 19.3 Demo Timeline

```text
T+00 User asks coding-agent-prod to solve issue #482.
T+05 Agent reads GitHub issue.
T+06 AegisAgent labels issue content untrusted_external.
T+15 Agent creates branch and draft PR.
T+20 Agent tries merge_pull_request into main.
T+21 AegisAgent computes risk_score=91.
T+22 AegisAgent sends Slack approval request.
T+40 Human rejects merge.
T+41 Agent receives safe rejection reason.
T+42 Audit timeline generated.
```

***

# 20. Evaluation Workflow

## 20.1 Use AgentDojo

AegisAgent should run AgentDojo-style tests because AgentDojo is an extensible evaluation framework for agents executing tools over untrusted data, with 97 realistic tasks and 629 security test cases. [\[arxiv.org\]](https://arxiv.org/abs/2406.13352), [\[proceeding...neurips.cc\]](https://proceedings.neurips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html)

## 20.2 Use Agent Security Bench

AegisAgent should also use Agent Security Bench because it covers 10 scenarios, more than 400 tools, 27 attack/defense methods, and vulnerabilities across prompts, tool usage, and memory retrieval. [\[openreview.net\]](https://openreview.net/forum?id=V4y0CpX4hK)

## 20.3 Use MCP Safety Scanner Concepts

For MCP-specific evaluation, AegisAgent should use MCP Safety Audit concepts because that work introduces MCPSafetyScanner and studies MCP exploit risks including malicious code execution, remote access control, and credential theft. [\[huggingface.co\]](https://huggingface.co/papers/2504.03767)

## 20.4 Use AgentPoison for Memory/RAG Tests

AegisAgent should use AgentPoison-style tests for memory/RAG workflows because AgentPoison demonstrates backdoor attacks through poisoned memory and knowledge bases in LLM agents. [\[github.com\]](https://github.com/AI-secure/AgentPoison), [\[arxiv.org\]](https://arxiv.org/abs/2407.12784)

***

# 21. Workflow Success Metrics

## 21.1 Security Metrics

```text
% tool calls covered by policy
% high-risk actions requiring approval
# blocked unauthorized actions
# blocked MCP dangerous tool calls
# untrusted-context escalations
# memory writes quarantined
# prompt-injection attempts detected
```

## 21.2 Operational Metrics

```text
median authorization latency
p95 authorization latency
approval response time
agent run continuation success rate
policy evaluation error rate
audit event write success rate
```

## 21.3 Business Metrics

```text
number of registered agents
number of protected tool calls
number of connected MCP servers
number of active policies
number of weekly approval decisions
number of customer teams using AegisAgent
```

Tracing and observability are critical for these metrics because OpenAI Agents SDK captures workflow traces/spans, and CrewAI positions tracing and observability as production features for monitoring agent workflows. [\[openai.github.io\]](https://openai.github.io/openai-agents-python/tracing/), [\[github.com\]](https://github.com/crewAIInc/crewAI)

***

# 22. Final Recommended Workflow Architecture

The best workflow architecture for AegisAgent is:

```text
Agent Runtime
   |
   v
AegisAgent SDK
   |
   v
Decision API
   |
   +--> Identity Resolver
   +--> Context Trust Classifier
   +--> Policy Engine
   +--> Risk Engine
   +--> Approval Engine
   +--> Audit Writer
   |
   v
Tool Proxy / MCP Gateway
   |
   v
External Systems
```

This architecture combines the strongest patterns from the research and GitHub ecosystem: AgentDojo’s untrusted-tool-data benchmark, LlamaFirewall’s runtime guardrail architecture, Microsoft MCP Gateway’s MCP proxy/control-plane pattern, LangGraph’s human-in-loop pause/resume workflow, OpenAI Agents SDK tracing, and AgentPoison’s memory/RAG threat model. [\[arxiv.org\]](https://arxiv.org/abs/2406.13352), [\[github.com\]](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall), [\[github.com\]](https://github.com/microsoft/mcp-gateway), [\[docs.langchain.com\]](https://docs.langchain.com/oss/python/langchain/human-in-the-loop), [\[openai.github.io\]](https://openai.github.io/openai-agents-python/tracing/), [\[arxiv.org\]](https://arxiv.org/abs/2407.12784)

***

# 23. Final Founder-Level Recommendation

For AegisAgent, do **not** start by building a broad AI security platform.

Start with this exact workflow:

> **Agent proposes tool call → AegisAgent evaluates policy → allow / deny / require approval → execute through proxy → audit everything.**

This is the minimum workflow that creates real value because it controls the agent at the moment of action, which is where the highest-risk failures happen. AgentDojo proves that tool-using agents can be hijacked through untrusted tool data, and LlamaFirewall reinforces the need for runtime guardrail monitoring for autonomous agents that take high-stakes actions. [\[arxiv.org\]](https://arxiv.org/abs/2406.13352), [\[arxiv.org\]](https://arxiv.org/pdf/2505.03574)

Your first product should be:

# **AegisAgent — Agent Action Firewall**

**First protected workflow:**

```text
GitHub + Slack approval + MCP gateway + policy engine + audit logs
```

**First demo:**

```text
Malicious GitHub issue tries to hijack coding agent.
AegisAgent blocks or approval-gates the dangerous action.
Audit timeline proves exactly what happened.
```

That workflow is narrow, powerful, research-backed, feasible for a solo founder, and easy for developers/security teams to understand.
