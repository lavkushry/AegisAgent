# AgentGuard: Agentic Security Control Plane

**Author:** Lavkush Kumar  
**Date:** 2026-05-29  
**Working title:** AgentGuard / MCP Firewall / Runtime Security Gateway for AI Agents

---

## 1. Executive Summary

AgentGuard is a **runtime security control plane for AI agents**. It protects tool-using and MCP-connected agents by enforcing **agent identity, least-privilege tool access, runtime policy checks, human approval, memory/RAG protection, and audit trails**. The core thesis is that AI agents are moving from passive chat to autonomous systems with planning, tool use, memory, and external actions, which creates risks beyond traditional chatbot safety and conventional application security. Recent survey work defines agentic AI systems as LLM-powered systems with planning, tool use, memory, and autonomy, and highlights amplified risks when agents act across software, web, and physical environments. citeturn3search80

The best initial wedge is **not generic AI security**. The sharper wedge is: **MCP and tool-use firewall for AI agents**. MCP is an emerging open standard for bi-directional communication and dynamic discovery between AI models and external tools/resources; research already identifies MCP lifecycle risks, malicious developers, external attackers, malicious users, implementation flaws, and the need for fine-grained safeguards. citeturn3search93turn3search95

---

## 2. Product Idea

### 2.1 Product Name

**AgentGuard**

Alternative names:

- **MCPGuard** — best if you focus only on MCP first.
- **AgentFirewall** — best for developer-friendly positioning.
- **AgentShield** — broader enterprise security name.

### 2.2 One-Line Positioning

> **AgentGuard is a runtime security gateway for AI agents and MCP tools. It gives engineering and security teams agent inventory, least-privilege tool access, prompt-injection-aware policy enforcement, human approval flows, and tamper-evident audit logs.**

This is aligned with OWASP’s AI Agent Security guidance, which lists direct/indirect prompt injection, tool abuse, privilege escalation, data exfiltration, memory poisoning, goal hijacking, excessive autonomy, high-impact action abuse, approval manipulation, cascading failures, sensitive data exposure, and supply-chain attacks as key agent risks. citeturn3search111

### 2.3 Target Users

**Primary buyer:** CTO, VP Engineering, Head of Security, AI Platform Lead, DevOps/Platform Lead, or Security Engineer responsible for AI governance.

**Initial ICP:**

- AI startups deploying production agents.
- SaaS companies using coding/support/sales agents.
- Fintech or healthcare SaaS teams needing auditability.
- Companies adopting MCP servers and tool-using LLM workflows.
- DevTool companies embedding agents in developer workflows.

### 2.4 Core Pain Points

Companies want agents that can use GitHub, Slack, Jira, AWS, databases, Stripe, Zendesk, email, files, vector databases, and MCP tools. But when an agent can act, security teams need answers to:

1. Which agents exist?
2. Which tools and credentials can each agent use?
3. Can untrusted content hijack the agent?
4. Can the agent perform destructive or high-impact actions?
5. Is there a complete audit trail?
6. Can risky actions require human approval?
7. Can memory/RAG stores be poisoned?
8. Are MCP servers trustworthy and policy-controlled?

Research shows these questions are real production risks. AgentDojo demonstrates that agents executing tools over untrusted data are vulnerable to prompt injection and provides 97 realistic tasks plus 629 security test cases. citeturn3search124turn3search125 InjecAgent evaluates tool-integrated LLM agents against indirect prompt injection with 1,054 test cases across 17 user tools and 62 attacker tools, and reports that ReAct-prompted GPT-4 was vulnerable 24% of the time under its benchmark. citeturn3search105turn3search106

---

## 3. Product Modules

### 3.1 Agent Inventory

Track every AI agent like a non-human identity:

```yaml
agent_id: coding-agent-prod
owner: platform-team
runtime: langgraph
model: gpt-4.1
connected_tools:
  - github
  - slack
  - postgres-readonly
  - mcp-filesystem
risk_level: high
allowed_actions:
  - read_repo
  - comment_pr
  - create_branch
approval_required:
  - merge_pr
  - delete_branch
  - run_prod_deploy
```

### 3.2 Runtime Tool Authorization

Every tool call goes through a policy decision point before execution. This is supported by SEAgent research, which frames agent misuse as privilege escalation and proposes a mandatory access-control framework using ABAC and information-flow monitoring for agent-tool interactions. citeturn3search117turn3search121

### 3.3 MCP Gateway

AgentGuard should proxy MCP calls and enforce:

- MCP server allowlist/blocklist.
- Tool discovery review.
- Tool description trust scoring.
- Per-tool authorization.
- Human approval for dangerous tools.
- Complete MCP request/response audit.

MCP security research defines a full MCP server lifecycle and a threat taxonomy across malicious developers, external attackers, malicious users, and security flaws; this directly supports building a gateway around MCP server creation, deployment, operation, and maintenance. citeturn3search93turn3search95

### 3.4 Prompt-Injection-Aware Guardrail

AgentGuard should tag data as **trusted** or **untrusted**. If a tool result comes from email, webpage, ticket, document, issue comment, or external website, it should not be allowed to cause high-impact tool calls without policy checks. AgentDojo and InjecAgent both show that external tool-returned content can hijack agents through indirect prompt injection. citeturn3search124turn3search105

### 3.5 Human Approval Workflow

High-impact actions should require approval:

- GitHub: merge PR, delete branch, change CODEOWNERS.
- AWS: mutate IAM, delete S3 bucket, rotate production secrets.
- Database: export customer table, run destructive query.
- Stripe: refund above threshold, change billing plan.
- Slack/email: send external message with sensitive data.

OWASP recommends least-privilege tool access, explicit authorization for sensitive operations, and oversight for high-impact actions. citeturn3search111

### 3.6 Memory and RAG Protection

AgentGuard should protect memory writes and RAG ingestion:

- Require provenance for new memory.
- Label memory as trusted/untrusted.
- Block memory writes from untrusted sources unless approved.
- Scan retrieved chunks for suspicious instructions.
- Maintain document lineage and ingestion audit.

AgentPoison shows that poisoning long-term memory or RAG knowledge bases can backdoor LLM agents with over 80% average attack success and less than 0.1% poison rate in tested agents. citeturn3search99turn3search100 PoisonedRAG shows that injecting only five malicious texts per target question into a large knowledge database can reach 90% attack success, and existing defenses were insufficient in their evaluation. citeturn3search86turn3search87

### 3.7 Audit Trail and Compliance Evidence

Every action should produce an immutable event:

```json
{
  "event_id": "evt_01HX...",
  "timestamp": "2026-05-29T11:01:03Z",
  "agent_id": "coding-agent-prod",
  "user_id": "lavkush",
  "tool": "github.merge_pull_request",
  "resource": "repo/payment-service#PR-482",
  "risk": "high",
  "decision": "approval_required",
  "approver": "platform-lead",
  "input_hash": "sha256:...",
  "output_hash": "sha256:..."
}
```

Runtime guardrail research emphasizes real-time monitoring as a final layer of defense for AI agents taking actions based on untrusted inputs; LlamaFirewall specifically argues that model fine-tuning and chatbot-focused guardrails do not fully address autonomous-agent risks. citeturn3search142

---

## 4. Research Matrix

| Area | Paper / Source | Key Finding | Product Implication |
|---|---|---|---|
| Landscape | **Agentic AI Security: Threats, Defenses, Evaluation, and Open Challenges** | Agentic systems combine planning, tool use, memory, and autonomy, creating new risks beyond traditional AI safety and software security. citeturn3search80 | Build a multi-layer security control plane, not only a prompt filter. |
| Curated research | **Awesome Agentic Security Papers** | Curates 150+ papers and organizes the field into applications, threats, and defenses. citeturn3search81 | Use it as the ongoing paper tracker for product research. |
| Prompt injection benchmark | **AgentDojo** | Provides 97 realistic tasks and 629 security test cases for agents using tools over untrusted data. citeturn3search124turn3search125 | Use AgentDojo to benchmark AgentGuard’s prompt-injection defenses. |
| Indirect prompt injection | **InjecAgent** | Contains 1,054 test cases across 17 user tools and 62 attacker tools; ReAct GPT-4 vulnerable 24% of the time in their benchmark. citeturn3search105turn3search106 | Treat external content as untrusted and prevent it from triggering sensitive tool calls. |
| Agent security benchmark | **Agent Security Bench (ASB)** | Benchmarks attacks/defenses across 10 scenarios, 400+ tools, 27 attack/defense methods, and reports high attack success with limited current defense effectiveness. citeturn3search148turn3search137 | Use ASB as a broad regression suite for prompt, tool, memory, and mixed attacks. |
| Privilege escalation | **SEAgent / Mandatory Access Control Framework** | Defines privilege escalation as agent actions exceeding least privilege and proposes ABAC-based MAC with information-flow monitoring. citeturn3search117turn3search121 | Implement ABAC/Cedar policies for agent-tool interactions. |
| MCP security | **Model Context Protocol: Landscape, Security Threats, and Future Research Directions** | Defines MCP lifecycle and threat taxonomy with 16 threat scenarios across attacker types and security flaws. citeturn3search93turn3search95 | Build an MCP gateway with lifecycle-aware controls and MCP server risk scoring. |
| Memory poisoning | **AgentPoison** | Backdoors memory/RAG-based agents without model training; reports ≥80% ASR with <0.1% poison rate in tested agents. citeturn3search99turn3search100 | Add memory provenance, memory write approval, and suspicious retrieval detection. |
| RAG poisoning | **PoisonedRAG** | Shows a practical knowledge-corruption attack against RAG with 90% ASR after injecting five malicious texts per target question. citeturn3search86turn3search87 | Add RAG ingestion scanning, source trust labels, and retrieval-time filtering. |
| Backdoored agents | **BadAgent** | Shows that LLM agents fine-tuned on poisoned data can execute harmful operations when triggers appear in input/environment. citeturn3search130turn3search131 | Add model/source provenance and runtime behavior monitoring; do not trust model alignment alone. |
| Runtime guardrails | **LlamaFirewall** | Proposes an open-source guardrail system for agents, arguing real-time guardrail monitoring is needed because agents take higher-stakes actions from untrusted inputs. citeturn3search142 | Product should operate on the execution path, not only at prompt/output layer. |
| Tool-use evaluation | **ToolSandbox** | Evaluates stateful tool execution, implicit state dependencies, on-policy conversational evaluation, and dynamic evaluation over trajectories. citeturn3search136 | Test AgentGuard on multi-step workflows, not only single tool calls. |
| Standards / best practices | **OWASP AI Agent Security Cheat Sheet** | Recommends least privilege, per-tool scoping, explicit authorization, memory protection, and audit trails. citeturn3search111 | Use OWASP language in sales, docs, and control mapping. |

---

## 5. Architecture

### 5.1 High-Level Architecture

```text
User / App
   |
   v
AI Agent Runtime
(LangGraph / CrewAI / AutoGen / OpenAI Agents SDK / custom)
   |
   v
AgentGuard SDK / Proxy
   |
   +--> Agent Identity Registry
   +--> Policy Engine
   +--> Prompt Injection / Untrusted Data Classifier
   +--> MCP Gateway
   +--> Human Approval Service
   +--> Audit Log Pipeline
   +--> Risk Scoring Engine
   |
   v
Tools / APIs / MCP Servers
(GitHub, Slack, AWS, DB, Stripe, Jira, Files, Vector DB)
```

### 5.2 Key Design Decision

AgentGuard should sit **between the agent and tools**. Prompt filtering alone is not enough because multiple papers show attacks can occur through external tool results, memory retrieval, tool metadata, and multi-step trajectories. AgentDojo focuses on agents executing tools over untrusted data, ASB evaluates vulnerabilities across system prompt, user prompt handling, tool usage, and memory retrieval, and LlamaFirewall argues for real-time guardrails as a final layer of defense. citeturn3search124turn3search148turn3search142

---

## 6. Technology Stack

### 6.1 MVP Stack Recommendation

| Layer | Recommended Tech | Why |
|---|---|---|
| Core gateway | **Rust** | Strong for security-sensitive proxying, memory safety, and sub-millisecond execution. |
| SDK | **Python + TypeScript** | Most agent frameworks are Python/TS-first; easy adoption. |
| Policy engine | **Cedar** | Purpose-built fine-grained authorization engine; natively integrated for microsecond checks. |
| API service | **Axum (Rust)** | High-performance, async, memory-safe API router. |
| Frontend | **Next.js + TypeScript + Tailwind** | Fast SaaS dashboard development. |
| Database | **SQLite** (MVP) / **PostgreSQL** | In-process DB for MVP to eliminate socket lag; Postgres for SaaS scaling. |
| Event/audit store | **SQLite** / **ClickHouse** | Async in-process SQLite writes for MVP; ClickHouse later for high volume. |
| Queue | **Redis Streams** or **NATS** | Lightweight event flow for approvals, scans, async jobs. |
| Auth | **Auth0 / Clerk / WorkOS** | Enterprise SSO later; WorkOS is strong for B2B SaaS. |
| Secrets | **HashiCorp Vault** or cloud KMS | Secure storage for tokens and integrations. |
| Deployment | **Docker + Kubernetes** | Enterprise-friendly and cloud portable. |
| Observability | **OpenTelemetry + Grafana/Prometheus** | Make security events observable and exportable. |
| LLM layer | **OpenAI / Azure OpenAI / Anthropic / local models** | Use model-agnostic adapters. |
| Vector/RAG integrations | **pgvector, Pinecone, Weaviate, Qdrant** | Cover common RAG deployments. |

The gateway is security-critical because it mediates tool execution, MCP calls, approvals, and audit logging. Rust is the recommended choice to guarantee compile-time memory safety, eliminate garbage collection latency spikes, and deliver sub-millisecond policy decisions natively.

### 6.3 Policy Format Example

```yaml
id: github-prod-merge-control
scope:
  agent: coding-agent-prod
  tool: github.merge_pull_request
conditions:
  repo_sensitivity: production
  branch: main
action: require_approval
approval:
  approvers:
    - platform-lead
    - security-oncall
  timeout_minutes: 30
audit:
  retain_days: 365
```

### 6.4 API Decision Example

```json
{
  "decision": "deny",
  "reason": "Untrusted webpage content attempted to trigger external email with sensitive data",
  "risk_score": 91,
  "matched_policy": "block-untrusted-to-external-exfiltration"
}
```

---

## 7. MVP Scope

### 7.1 MVP Goal

Build a developer-first product that can protect one real agent workflow end-to-end:

> **A coding/support agent connected to GitHub, Slack, and one MCP server.**

### 7.2 MVP Features

1. Agent registry.
2. SDK/proxy for tool calls.
3. YAML/Cedar policy engine.
4. GitHub integration.
5. Slack approval workflow.
6. MCP server proxy.
7. Audit log dashboard.
8. Basic prompt-injection/untrusted-content tagging.
9. Risk scoring for high-impact tool calls.

### 7.3 MVP Non-Goals

Do not build all enterprise integrations initially. Avoid becoming a full SIEM, full CASB, full DSPM, full CNAPP, or generic LLM red-teaming platform. Focus on **runtime control of agent tool calls**.

---

## 8. Paper Reading Roadmap

### Phase 1 — Understand the Landscape

1. **Agentic AI Security: Threats, Defenses, Evaluation, and Open Challenges** — broad taxonomy and secure-by-design framing. citeturn3search80
2. **Awesome Agentic Security Papers** — continuously updated paper list. citeturn3search81
3. **OWASP AI Agent Security Cheat Sheet** — practical customer-facing language and controls. citeturn3search111

### Phase 2 — Prompt Injection and Tool Hijacking

4. **AgentDojo** — benchmark for prompt injection attacks and defenses in tool-using agents. citeturn3search124turn3search125
5. **InjecAgent** — indirect prompt injection benchmark for tool-integrated agents. citeturn3search105turn3search106
6. **Agent Security Bench** — broad agent attack/defense benchmark. citeturn3search148turn3search137

### Phase 3 — Access Control and Runtime Enforcement

7. **SEAgent / Mandatory Access Control Framework** — ABAC/MAC policy model for privilege escalation. citeturn3search117turn3search121
8. **LlamaFirewall** — runtime guardrails and final-layer defense for secure AI agents. citeturn3search142
9. **ToolSandbox** — stateful tool-use benchmark for complex multi-step evaluation. citeturn3search136

### Phase 4 — MCP Security

10. **Model Context Protocol: Landscape, Security Threats, and Future Research Directions** — must-read for MCP gateway design. citeturn3search93turn3search95

### Phase 5 — Memory/RAG Poisoning

11. **AgentPoison** — memory/RAG poisoning for LLM agents. citeturn3search99turn3search100
12. **PoisonedRAG** — knowledge database corruption attacks against RAG. citeturn3search86turn3search87
13. **BadAgent** — backdoored LLM agents from poisoned fine-tuning data. citeturn3search130turn3search131

---

## 9. Competitive Differentiation

Many AI security products focus on prompt filtering, output filtering, data loss prevention, or red teaming. AgentGuard should differentiate through:

1. **Execution-path enforcement** — sits between agents and tools.
2. **MCP-native security** — gateway for MCP discovery, authorization, and audit.
3. **ABAC policy model** — agent, user, tool, action, resource, sensitivity, trust level.
4. **Human approval workflow** — practical control for high-impact actions.
5. **Tamper-evident audit trail** — compliance and incident response evidence.
6. **Memory/RAG trust controls** — provenance, poisoning resistance, retrieval-time checks.

The research supports this differentiation because attacks appear across prompt handling, tool usage, memory retrieval, and MCP/tool lifecycle boundaries; current defenses remain limited in benchmark results. citeturn3search148turn3search93turn3search99

---

## 10. 90-Day Execution Plan

### Days 1–15: Validation

- Interview 20 AI startup CTOs / platform engineers.
- Ask what agents they run, which tools they connect, and how they approve/audit actions.
- Validate the MCP-specific wedge.
- Publish one technical blog: **“How indirect prompt injection turns AI agents into confused deputies.”**

### Days 16–45: Build MVP

Build:

- Agent registry.
- Tool-call proxy.
- GitHub and Slack integration.
- Cedar/YAML policy engine.
- MCP proxy for one or two MCP servers.
- Audit log table and dashboard.

### Days 46–70: Benchmark and Demo

- Run AgentDojo and InjecAgent-inspired test cases.
- Create a demo where a malicious GitHub issue tries to make a coding agent leak secrets or merge unsafe code.
- Show AgentGuard blocking or requiring approval.

### Days 71–90: Private Beta

- Onboard 3–5 companies.
- Charge $299/month for early design partners.
- Convert the best use cases into case studies.

---

## 11. Pricing Hypothesis

| Plan | Price | Target |
|---|---:|---|
| Open Source Core | Free | Developers and adoption |
| Startup | $299/month | Small teams with 1–5 agents |
| Growth | $999/month | SaaS teams with multiple agents/tools |
| Enterprise | $3K–$10K/month | Regulated teams needing SSO, retention, SIEM export, approvals |

Target first milestone: **$25K–$40K MRR**. This is achievable with 25–40 Growth customers or a mix of Growth and Enterprise customers.

---

## 12. Final Recommendation

Build **AgentGuard as an MCP-first runtime security gateway for AI agents**.

The product should start with four things:

1. **Agent inventory**
2. **Runtime tool/MCP authorization**
3. **Human approval for risky actions**
4. **Audit logs**

Then expand into prompt-injection-aware untrusted-data controls and memory/RAG protection. This roadmap is strongly backed by research on AgentDojo, InjecAgent, ASB, SEAgent, MCP security, AgentPoison, PoisonedRAG, BadAgent, LlamaFirewall, and OWASP AI Agent Security guidance. citeturn3search124turn3search105turn3search148turn3search117turn3search93turn3search99turn3search86turn3search130turn3search142turn3search111
