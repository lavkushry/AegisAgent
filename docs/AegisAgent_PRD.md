# AegisAgent — Product Requirements Document (PRD)

**Product:** AegisAgent  
**Category:** Agentic Runtime Security / MCP Security Gateway / Agent Action Firewall  
**Document Type:** Product Requirements Document  
**Version:** v0.1  
**Date:** 2026-05-29  
**Owner:** Lavkush Kumar  
**Stage:** MVP Definition / Pre-Build Product Spec  

---

## 1. Executive Summary

AegisAgent is a **runtime security control plane for AI agents**. It protects AI agents that can call tools, use MCP servers, access repositories, interact with enterprise systems, and perform business-impacting actions. The product sits between the agent runtime and external systems, enforcing **agent identity, action-level authorization, human approval, MCP governance, context trust, and audit trails** before an agent action executes.

The developer market is ready for this product because AI coding and agentic workflows are moving into mainstream developer environments. Stack Overflow’s 2025 AI survey reports that **84%** of respondents are using or planning to use AI tools in development, **51%** of professional developers use AI tools daily, but only **3.1%** highly trust AI output and **46%** distrust it to some degree. citeturn15search448 Stack Overflow’s 2026 trust-gap analysis says usage rose to 84% while trust dropped to 29%, showing that developers want AI assistance but still need verification, human review, and production safeguards. citeturn15search445

GitHub’s ecosystem is becoming increasingly agentic. GitHub Copilot cloud agent can research a repository, create an implementation plan, make code changes, run in an ephemeral GitHub Actions-powered environment, and create pull requests from GitHub Issues, GitHub.com, VS Code, Azure Boards, Jira, Linear, Slack, Teams, and other entry points. citeturn15search399 GitHub’s blog describes Copilot coding agent as an asynchronous software engineering agent that can be assigned an issue, explore the repo, write code, run tests, open a PR, and ask for human review. citeturn15search400

MCP is becoming a major integration layer for agentic systems. GitHub launched the MCP Registry because MCP servers were scattered across registries, random repositories, and community threads, creating friction and potential security risks. citeturn15search417 The official `modelcontextprotocol/servers` repository has significant community adoption and explicitly warns that its reference servers are educational examples, not production-ready solutions, and that developers must evaluate security requirements based on their own threat model. citeturn15search416

Security risk is not theoretical. NSA guidance released on **May 20, 2026** says real-world MCP adoption has accelerated across business, finance, legal, software development, and sensitive tasks like querying personally identifiable information, while MCP introduces risks around serialization, trust boundaries, agent misuse, dynamic tool invocation, implicit trust relationships, and context sharing. citeturn15search408 AgentDojo shows that tool-using agents are vulnerable to prompt injection attacks where data returned by external tools can hijack agents into executing malicious tasks, and the benchmark includes **97 realistic tasks** and **629 security test cases**. citeturn15search421turn15search422

---

## 2. Product Vision

> **Secure the action, not just the prompt.**

AegisAgent’s vision is to make AI agents safe enough for production by ensuring every risky agent action is **intentional, authorized, approval-aware, and auditable**.

The product is based on a key market shift: AI risk is moving from text generation to action execution. Microsoft’s security analysis of OWASP Agentic Applications says agentic systems do not just generate content; they can retrieve sensitive data, invoke tools, and take action using real identities and permissions, meaning failures can become automated sequences of access, execution, and downstream impact. citeturn15search431 OWASP’s Top 10 for Agentic Applications 2026 identifies risks including agent goal hijacking, tool misuse, identity and privilege abuse, supply-chain vulnerabilities, unexpected code execution, memory/context poisoning, insecure inter-agent communication, cascading failures, human-agent trust exploitation, and rogue agents. citeturn15search427turn15search429

---

## 3. Problem Statement

AI agents are gaining access to real tools and production workflows faster than security teams can govern them. Developers are increasingly using AI tools, but trust in AI output remains low, especially for production and security-critical work. citeturn15search448turn15search445 Agents now operate inside GitHub workflows, can create branches and pull requests, run tests, and request review, which makes agent actions part of the normal software delivery lifecycle. citeturn15search399turn15search400

The painful problem is:

> **Teams cannot reliably approve, block, or audit risky AI-agent actions before they touch repositories, MCP tools, cloud systems, databases, or customer data.**

This problem becomes urgent because MCP makes it easier for agents to connect to tools and data sources, but the ecosystem is fragmented and security-sensitive. GitHub’s MCP Registry announcement explicitly says scattered MCP server discovery created a fractured environment with potential security risks. citeturn15search417 NSA guidance says traditional cybersecurity controls remain necessary but are not sufficient for MCP-based agentic systems because dynamic tool invocation, implicit trust, and context sharing introduce systemic risks. citeturn15search408

---

## 4. Goals and Non-Goals

### 4.1 Product Goals

1. **Protect risky agent actions before execution.**  
   AegisAgent must authorize, deny, or approval-gate tool calls before they execute because agent failures can become downstream access and execution events, not just bad text outputs. citeturn15search431turn15search429

2. **Make agent security developer-friendly.**  
   Developers validate tools through GitHub repositories, examples, docs, and community activity; GitHub’s MCP Registry emphasizes discoverability, GitHub-backed repositories, stars, community activity, and one-click installation as trust signals. citeturn15search417

3. **Provide MCP-native governance.**  
   MCP adoption is growing, but the official reference-server repository warns that examples are not production-ready and require threat-model-specific safeguards. citeturn15search416 NSA also advises caution because MCP deployments involve dynamic tool invocation, context sharing, and trust-boundary risks. citeturn15search408

4. **Generate audit-ready evidence.**  
   Agentic systems use identities and permissions to act across workflows, so teams need evidence of who initiated an action, which agent acted, what tool was called, which policy applied, and who approved. citeturn15search431turn15search408

5. **Reduce security review friction.**  
   Stack Overflow’s survey shows developers use AI heavily but distrust accuracy, which means teams need controls that let them adopt AI without relying blindly on model output. citeturn15search448turn15search445

### 4.2 Non-Goals for MVP

AegisAgent MVP will **not** be:

- A full SIEM.
- A full DLP platform.
- A full AI governance/GRC suite.
- A model training or model scanning platform.
- A generic chatbot moderation layer.
- A full cloud security posture management product.
- A fully automated remediation platform.

The MVP focuses narrowly on **agent action authorization, approval, MCP gateway controls, and audit timelines**.

---

## 5. Target Users and Personas

### 5.1 Primary Persona: AI Engineer / Agent Developer

**Needs:** simple SDK, quickstart, tool wrappers, local development, policy examples, clear deny reasons, and minimal friction.  
**Why now:** AI agents are entering normal SDLC workflows, with GitHub Copilot cloud agent supporting repository research, implementation planning, code changes, tests, and PR creation. citeturn15search399turn15search400

### 5.2 Primary Persona: Platform / DevOps Engineer

**Needs:** gateway deployment, GitHub/Slack/MCP integration, audit logs, reliability, observability, and operational runbooks.  
**Why now:** MCP servers connect AI agents to tools and data, and GitHub’s MCP Registry was created to reduce fragmented discovery and improve trust in agentic workflows. citeturn15search417turn15search415

### 5.3 Primary Persona: Security Engineer

**Needs:** least privilege, policy-as-code, approval controls, MCP risk visibility, context trust labels, audit evidence, and secure defaults.  
**Why now:** OWASP Agentic Top 10 highlights tool misuse, identity/privilege abuse, supply-chain vulnerabilities, code execution, and memory/context poisoning as key agentic risks. citeturn15search427turn15search429

### 5.4 Economic Buyer: CTO / VP Engineering / CISO

**Needs:** safe AI adoption, production guardrails, compliance evidence, reduced incident risk, and faster deployment approvals.  
**Why now:** Microsoft’s analysis says agentic systems collapse application risk, identity risk, and data risk into one operating model because they retrieve data, invoke tools, and act using real identities and permissions. citeturn15search431

---

## 6. Market and Community Requirements

### 6.1 Developer Community Requirements

AegisAgent must win developer trust by shipping:

- A clean GitHub repository with README, quickstart, examples, docs, SECURITY.md, CONTRIBUTING.md, and ROADMAP.md.
- A 10-minute local setup.
- Python and TypeScript SDKs.
- GitHub + Slack + MCP examples.
- Policy templates that developers can copy-paste.
- A demo that shows a malicious GitHub issue being blocked or approval-gated.

This matters because GitHub’s MCP Registry emphasizes discoverability, repository-backed server information, community activity, and frictionless installation as key developer trust mechanisms. citeturn15search417 Stack Overflow’s survey shows adoption is high but trust is low, which means developers will value transparent, inspectable security infrastructure more than opaque AI-only claims. citeturn15search448turn15search445

### 6.2 GitHub Ecosystem Requirements

The MVP must feel native inside GitHub:

- GitHub App installation.
- Repository-level agent policy.
- Branch and PR action classification.
- PR comments for denied or approval-gated actions.
- GitHub Checks for policy decisions.
- Audit links from PR comments.
- Default policy: merge to `main` requires approval.

GitHub Copilot cloud agent’s workflow already uses GitHub Issues, branches, pull requests, tests, review cycles, and GitHub Actions-powered environments, so AegisAgent must integrate where developers already review and approve work. citeturn15search399turn15search400

### 6.3 MCP Ecosystem Requirements

AegisAgent must provide MCP governance because MCP servers are proliferating. The official MCP Registry lists recently updated MCP servers across many domains, and the official servers repo has high community activity while warning that reference servers are not production-ready. citeturn15search415turn15search416 NSA guidance says real-world MCP adoption has accelerated and requires careful implementation because of trust boundaries, serialization risks, and agent misuse. citeturn15search408

---

## 7. MVP Scope

### 7.1 MVP Theme

# Secure a coding agent connected to GitHub + Slack + MCP

The MVP must prove this loop:

```text
Agent proposes action
→ AegisAgent intercepts
→ policy evaluates
→ decision returned
→ action allowed / denied / approval-gated
→ audit event written
```

This loop directly addresses the tool-using agent risk shown by AgentDojo, where data returned by external tools can hijack agents into executing malicious tasks. citeturn15search421turn15search422

### 7.2 MVP Must-Have Features

#### Feature 1 — Agent Registry

AegisAgent must allow teams to register agents with identity, owner, environment, framework, model provider, risk tier, and connected tools.

**Requirements:**

- Register agent through dashboard or API.
- Assign owner team and environment.
- Assign risk tier: low, medium, high, critical.
- Show connected tools and MCP servers.
- Generate agent token.
- Support agent status: active, disabled, quarantined.

**Acceptance Criteria:**

```text
Given a developer registers an agent,
when the agent calls /authorize,
then AegisAgent must resolve the agent identity and tenant before policy evaluation.
```

#### Feature 2 — Tool Action Registry

AegisAgent must classify tool actions by risk and mutation level.

**Initial GitHub actions:**

```text
read_issue
read_file
create_branch
create_pull_request
comment_on_pr
merge_pull_request
delete_branch
change_codeowners
```

**Default risk levels:**

```text
read_issue: low
read_file: low/medium depending on repo sensitivity
create_branch: medium
create_pull_request: medium
comment_on_pr: medium
merge_pull_request: high
change_codeowners: critical
delete_branch: high
```

**Rationale:** GitHub Copilot coding agent produces normal branches and pull requests, and developers review outputs through familiar PR workflows. citeturn15search400turn15search403

#### Feature 3 — Runtime Authorization API

AegisAgent must expose an authorization endpoint that evaluates every protected action.

**API:**

```http
POST /v1/authorize
```

**Decision outputs:**

```text
allow
deny
require_approval
log_only
quarantine
```

**Acceptance Criteria:**

```text
Given an agent attempts github.merge_pull_request into main,
when the repository is production-sensitive,
then AegisAgent must return require_approval by default.
```

#### Feature 4 — Policy Engine

AegisAgent must support policy-as-code for action decisions.

**MVP policy language:** YAML policy templates compiled into internal rules or OPA/Rego later.

**Example policy:**

```yaml
id: github-main-merge-approval
when:
  tool: github
  action: merge_pull_request
  branch: main
then:
  decision: require_approval
  approver_group: platform-leads
```

**Acceptance Criteria:**

```text
Given a policy requires approval for github.merge_pull_request,
when an agent attempts that action,
then AegisAgent must create an approval request and pause execution.
```

#### Feature 5 — Slack Approval Workflow

AegisAgent must send high-risk approval requests to Slack.

**Approval actions:**

```text
Approve
Reject
Edit
Escalate
```

**Acceptance Criteria:**

```text
Given an approval request is created,
when a valid approver clicks Approve,
then AegisAgent must verify the callback, bind the approval to the original action hash, execute or release the action, and write an audit event.
```

#### Feature 6 — MCP Gateway Lite

AegisAgent must provide basic MCP gateway controls.

**MVP capabilities:**

- Register MCP server.
- Discover MCP tools.
- Show tool manifest.
- Approve or disable tools.
- Deny unknown tools by default.
- Authorize MCP tool calls through the runtime API.
- Log MCP calls.

**Rationale:** NSA guidance says MCP has accelerated in production and introduces dynamic tool invocation, implicit trust, and context sharing risks that require careful implementation. citeturn15search408 GitHub’s MCP Registry exists because MCP server discovery was fragmented and security-sensitive. citeturn15search417

#### Feature 7 — Context Trust Labeling

AegisAgent must label external content as trusted, semi-trusted, untrusted, or suspicious.

**Initial sources:**

```text
GitHub issue from repo member: semi_trusted
GitHub issue from external contributor: untrusted_external
MCP response from approved internal server: trusted_internal
MCP response from unknown server: untrusted_external
```

**Acceptance Criteria:**

```text
Given an agent reads a public GitHub issue,
when it later attempts a high-risk mutating action,
then AegisAgent must require approval because the action follows untrusted context.
```

**Rationale:** AgentDojo demonstrates attacks where untrusted tool data hijacks agents into malicious tasks. citeturn15search421turn15search422

#### Feature 8 — Audit Timeline

AegisAgent must write audit events for every important action.

**Events:**

```text
agent_registered
tool_call_intercepted
policy_decision_created
approval_created
approval_decided
tool_call_executed
tool_call_denied
mcp_tool_discovered
mcp_tool_called
context_labeled
```

**Acceptance Criteria:**

```text
Given an agent action is approval-gated,
when a user opens the audit timeline,
then they must see agent identity, user identity, tool/action/resource, policy match, approval decision, timestamp, and final result.
```

---

## 8. User Stories

### 8.1 AI Engineer Stories

#### Story: Protect first tool call

As an AI engineer, I want to wrap a GitHub tool call with AegisAgent so that risky actions are checked before execution.

**Acceptance Criteria:**

```text
Given I install the SDK,
when I wrap github.merge_pull_request,
then AegisAgent must intercept the action and return allow, deny, or require_approval.
```

#### Story: Local quickstart

As an AI engineer, I want to run AegisAgent locally in under 10 minutes so that I can test policies before production.

**Acceptance Criteria:**

```text
Given I run docker compose up,
when I open the local dashboard,
then I can register an agent, connect mock GitHub, and run the demo policy.
```

### 8.2 Security Engineer Stories

#### Story: Require approval for production merge

As a security engineer, I want production branch merges by agents to require approval so that agents cannot autonomously modify production code.

**Acceptance Criteria:**

```text
Given an agent attempts to merge into main,
when the repo is marked production,
then the action requires approval and is audited.
```

#### Story: Deny unknown MCP tools

As a security engineer, I want unknown MCP tools to be denied by default so that agents cannot discover and use unreviewed capabilities.

**Acceptance Criteria:**

```text
Given an MCP server exposes a new tool,
when that tool is not in the approved manifest,
then AegisAgent denies the tool call and alerts the owner.
```

### 8.3 Platform Engineer Stories

#### Story: Observe protected agent actions

As a platform engineer, I want metrics on protected actions, approval latency, and policy decisions so that I can operate AegisAgent reliably.

**Acceptance Criteria:**

```text
Given AegisAgent is running,
when agents call tools,
then metrics for authorization latency, allow/deny counts, approval requests, and audit events are emitted.
```

### 8.4 CTO / VP Engineering Stories

#### Story: Prove safe AI-agent rollout

As a CTO, I want evidence that AI-agent actions are governed so that I can approve production adoption and answer customer security reviews.

**Acceptance Criteria:**

```text
Given a customer asks how agents are governed,
when I export an audit report,
then it shows agent inventory, policies, approvals, and action timelines.
```

---

## 9. Functional Requirements

### 9.1 Agent Management

- Create, update, disable, and quarantine agents.
- Assign owner, team, environment, framework, model provider, and risk tier.
- Issue and rotate agent tokens.
- Show agent activity and policy coverage.

### 9.2 Tool Management

- Register tools.
- Define actions.
- Mark actions as read-only or mutating.
- Assign risk level.
- Attach default policies.
- Support GitHub first.

### 9.3 MCP Management

- Register MCP server.
- Discover tools.
- Approve/deny tools.
- Hash tool manifests.
- Detect manifest drift.
- Log tool discovery and execution.
- Deny unknown MCP tools by default.

MCP management is required because the MCP ecosystem is growing while official reference servers warn they are not production-ready and NSA guidance warns that MCP deployments introduce new systemic risks. citeturn15search416turn15search408

### 9.4 Authorization and Policy

- Evaluate runtime action request.
- Match against policies.
- Return allow, deny, require_approval, quarantine, or log_only.
- Include reason and matched policy IDs.
- Support default deny for unknown tools/actions.

### 9.5 Approval Workflow

- Create approval request.
- Send Slack notification.
- Verify approval callback.
- Bind approval to action hash.
- Support approval expiry.
- Re-evaluate edited actions.
- Write audit events.

### 9.6 Audit and Investigation

- Store decision events.
- Store approval events.
- Store execution events.
- Link events by run ID and trace ID.
- Provide timeline UI.
- Export events later via webhook/SIEM.

### 9.7 Context Trust

- Label content source trust.
- Attach trust labels to future tool calls in the same run.
- Trigger policy decisions based on trust level.
- Provide default policies for untrusted context plus mutating actions.

---

## 10. Non-Functional Requirements

### 10.1 Performance

```text
Authorization API p95 latency: < 150 ms
Policy evaluation p95 latency: < 75 ms
Slack approval creation p95: < 5 seconds
Audit write enqueue success: 99.9%
MCP proxy overhead p95: < 250 ms
```

### 10.2 Reliability

```text
MVP SaaS availability target: 99.5%
Enterprise target later: 99.9%+
High-risk actions fail closed if policy/audit is unavailable
Low-risk read-only actions may fail open only if explicitly configured
```

### 10.3 Security

```text
Unknown agent: deny
Unknown tool: deny
Unknown MCP server: deny
Unknown MCP tool: deny
Critical action: deny by default
High-risk action: require approval by default
Approval callback: signature verified
Secrets: redacted from logs
Tenant data: isolated by tenant_id
```

### 10.4 Usability

```text
Local setup under 10 minutes
First protected GitHub action under 20 minutes
Default policies available out of the box
Readable deny reasons for developers
Detailed audit reasons for security users
```

---

## 11. MVP User Flow

### 11.1 First-Run Flow

```text
1. User signs up.
2. User creates organization.
3. User installs GitHub App.
4. User connects Slack approval channel.
5. User registers coding-agent-prod.
6. User applies default GitHub policy pack.
7. User runs demo attack.
8. AegisAgent blocks or approval-gates risky action.
9. User views audit timeline.
```

### 11.2 Protected Action Flow

```text
1. Agent reads GitHub issue.
2. AegisAgent labels issue context as untrusted_external.
3. Agent creates branch.
4. AegisAgent allows branch creation.
5. Agent opens PR.
6. AegisAgent allows PR creation.
7. Agent tries to merge PR into main.
8. AegisAgent requires Slack approval.
9. Human rejects or approves.
10. AegisAgent writes full audit timeline.
```

This flow directly maps to GitHub Copilot coding agent patterns, where agents work asynchronously on issues, create pull requests, run tests, and request human review. citeturn15search399turn15search400

---

## 12. Product UX Requirements

### 12.1 Dashboard Pages

```text
Overview
Agents
Tools
MCP Servers
Policies
Approvals
Audit Timeline
Settings
```

### 12.2 Overview Page

Must show:

```text
registered agents
protected actions today
blocked actions
pending approvals
connected MCP servers
high-risk policy matches
recent audit events
```

### 12.3 Agent Detail Page

Must show:

```text
agent metadata
owner
environment
risk tier
connected tools
connected MCP servers
recent actions
policy coverage
approval history
```

### 12.4 Approval Detail Page

Must show:

```text
agent
user
tool/action/resource
risk level
context trust
policy reason
parameters
approve/reject/edit/escalate buttons
```

### 12.5 Audit Timeline Page

Must show:

```text
chronological events
policy decisions
approval decisions
tool executions
MCP calls
context labels
input/output hashes
```

---

## 13. API Requirements

### 13.1 Register Agent

```http
POST /v1/agents
```

### 13.2 Register Tool

```http
POST /v1/tools
```

### 13.3 Register MCP Server

```http
POST /v1/mcp/servers
```

### 13.4 Authorize Action

```http
POST /v1/authorize
```

### 13.5 Approval Decision

```http
POST /v1/approvals/{approval_id}/approve
POST /v1/approvals/{approval_id}/reject
POST /v1/approvals/{approval_id}/edit
```

### 13.6 Audit Timeline

```http
GET /v1/runs/{run_id}/timeline
GET /v1/audit/events
```

---

## 14. Data Requirements

### 14.1 Core Entities

```text
tenant
user
agent
tool
tool_action
mcp_server
mcp_tool
policy
decision
approval
audit_event
context_label
```

### 14.2 Retention Requirements

```text
Free/OSS local: local only
Team: 7–30 days audit retention
Startup: 90 days
Growth: 1 year
Enterprise: custom retention
```

---

## 15. Success Metrics

### 15.1 Product Activation Metrics

```text
Time to first protected action < 20 minutes
% users completing GitHub + Slack integration
% users running demo attack
# registered agents
# connected MCP servers
```

### 15.2 Security Outcome Metrics

```text
# high-risk actions approval-gated
# unknown MCP tools denied
# untrusted-context mutations escalated
# blocked actions
% protected actions with audit evidence
```

### 15.3 Community Metrics

```text
GitHub stars
GitHub forks
weekly active cloners
docs quickstart completion
GitHub issues opened/closed
community discussions
```

Developer trust signals matter because GitHub’s MCP Registry announcement emphasizes GitHub-backed repositories, stars, community activity, and discoverability as signals for selecting MCP servers. citeturn15search417

### 15.4 Business Metrics

```text
design partners signed
pilot-to-paid conversion
monthly recurring revenue
average contract value
action volume per customer
retention after 90 days
```

---

## 16. Launch Requirements

### 16.1 Alpha Requirements

```text
Local Docker Compose
Python SDK
GitHub tool wrapper
Slack approval mock or real Slack app
Basic policy templates
Audit event table
Demo attack scenario
```

### 16.2 Private Beta Requirements

```text
Hosted SaaS
GitHub App
Slack approval integration
MCP gateway lite
Dashboard timeline
Tenant isolation
Basic billing disabled/manual
5 design partners
```

### 16.3 Public Beta Requirements

```text
Public GitHub repo
README quickstart
Docs site
SECURITY.md
Stable Python SDK
TypeScript SDK alpha
Policy pack examples
Hosted dashboard
Pricing page
```

---

## 17. Competitive Differentiation Requirements

AegisAgent must clearly differentiate from:

1. **Prompt guardrails:** AegisAgent governs actions, not only text.
2. **MCP registries:** AegisAgent enforces runtime policy, not only discovery.
3. **MCP gateways:** AegisAgent adds action-level authorization, approval, and audit.
4. **AI governance platforms:** AegisAgent operates in the execution path, not only inventory/reporting.
5. **Red-team tools:** AegisAgent blocks or approval-gates production actions, not only tests them.

This distinction is necessary because OWASP and Microsoft both emphasize that agentic risk is about systems that retrieve data, use tools, act with permissions, and cause downstream outcomes. citeturn15search427turn15search431

---

## 18. Risks and Mitigations

### Risk 1 — SDK Bypass

Agents may call tools directly without AegisAgent.

**Mitigation:** token broker, proxy-only credentials, network policy guidance, and direct-tool-use detection.

### Risk 2 — Approval Fatigue

Too many approval prompts may reduce adoption.

**Mitigation:** risk-based approvals, sensible defaults, deduplication, and low-risk auto-allow.

### Risk 3 — MCP Ecosystem Volatility

MCP is evolving quickly and security practices are still maturing.

**Mitigation:** modular MCP gateway, manifest pinning, tool discovery filtering, and strict default deny.

### Risk 4 — Developer Trust Barrier

Security tools with poor developer experience are ignored.

**Mitigation:** local quickstart, OSS gateway, excellent README, GitHub-native workflows, and copy-paste policy examples.

### Risk 5 — Sensitive Data in Logs

Audit logs may capture sensitive payloads.

**Mitigation:** hash/redact payloads by default, configurable capture level, and secret scanning.

---

## 19. Open Questions

1. Should OPA/Rego be included in MVP, or should MVP start with simpler YAML policies?
2. Should the first public launch focus on GitHub only or GitHub + MCP together?
3. Should AegisAgent store raw payloads by default, or only hashes and metadata?
4. Should the OSS gateway include Slack approvals, or should approvals be hosted-only?
5. Should AegisAgent support Teams approval in MVP or post-MVP?
6. Should MCP server risk scoring be rules-based first or LLM-assisted?
7. Should AegisAgent integrate with GitHub Advanced Security signals in MVP or later?

---

## 20. MVP Release Definition

AegisAgent MVP is ready when it can demonstrate:

```text
A coding agent reads a GitHub issue.
AegisAgent labels the issue as untrusted.
The agent creates a branch and PR.
The agent attempts to merge into main.
AegisAgent requires Slack approval.
A human rejects or approves.
AegisAgent writes a full audit timeline.
Unknown MCP tools are denied by default.
```

This MVP directly addresses the current developer and market reality: developers are adopting AI agents rapidly but do not fully trust their output, GitHub workflows are becoming agentic, MCP tool ecosystems are expanding, and security guidance warns that MCP/agentic systems require careful runtime controls. citeturn15search448turn15search399turn15search417turn15search408

---

## 21. Final Product Recommendation

Build AegisAgent as:

# **Agent Action Firewall for AI Agents and MCP Tools**

The MVP should focus on:

```text
GitHub + Slack approval + MCP gateway lite + policy templates + audit timeline
```

The first public promise should be:

> **Install AegisAgent in 10 minutes, protect your first AI-agent GitHub action, and get an audit trail for every allow, deny, and approval decision.**

The strongest product message remains:

> **Do not just secure the prompt. Secure the action.**
