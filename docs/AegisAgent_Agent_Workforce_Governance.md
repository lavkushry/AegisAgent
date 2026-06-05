# AegisAgent — Agent Workforce Governance (company-wide)

> **Status:** Design (2026-06-05). How a whole company tracks and governs its fleet of AI agents as a **digital workforce**.
> **Read first:** [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md) (the monitoring plane) · [`AegisAgent_SOC_UI_Design.md`](AegisAgent_SOC_UI_Design.md) (the console).
>
> Concept: **your AI agents are digital employees.** AegisAgent is the system that governs that workforce end to end — **HR + IAM + SOC, for agents** — with the differentiator that every action is *provable* (receipts), *provenance-gated*, and *approval-bound*. It tracks humans **only** as agent **owners** and **approvers** (the accountability layer), never as a human-employee monitoring tool (that boundary is deliberate — see §12).

---

## 1. The model: agents-as-employees

A company running dozens-to-thousands of agents has the same governance needs it has for staff. AegisAgent maps them onto the integrity primitives:

| Workforce need | Human-employee analogue | AegisAgent for the **agent** workforce |
|---|---|---|
| Directory / roster | HRIS (Workday) | Agent registry (`agents`: identity, **owner**, team, env, purpose, model, risk tier, status) |
| Onboarding + credentials | IT provisioning / SSO | Enrollment → short-lived token + **Token Broker** (agents never hold raw creds) |
| Role & least privilege | RBAC / access reviews | Cedar policy + per-agent tool/action **grants** + deterministic provenance gate |
| Daily activity | Activity monitoring | The **SOC**: ASE stream, per-agent feed, detections, risk score |
| Manager sign-off | Approval workflows | **Approval queue** (hash-bound, single-use) — supervision of high-risk actions |
| Accountability | Audit / performance record | **Hash-chained receipts** → provable, tamper-evident record per agent |
| Suspend / terminate | Offboarding / deprovision | **freeze / revoke / quarantine** (status flips, honored next action) |
| Company-wide rollup | Org dashboards | Multi-team **SOC Console** rollup: by team, by owner, leadership reporting |

The differentiator vs a generic "agent management" tool: the directory entry, the access grant, and the activity record are all **anchored on verifiable evidence** — you can *prove* what each digital employee did, not just log it.

---

## 2. The agent lifecycle — Joiner · Mover · Leaver (JML)

Borrow IAM's JML model; apply the integrity primitives at each stage.

### Joiner (onboarding / provisioning)
```
Admin/owner registers an agent  -> identity, owner (human, accountable), team, environment, purpose, risk tier
Issue a short-lived agent token (CSPRNG); Token Broker holds tool creds, agent never does
Grant least-privilege scopes      -> which tools/actions this agent may call (default-deny everything else)
Pin tools / MCP manifests         -> drift later = provenance downgrade + SOC alert
Agent appears in the directory; first action is monitored
```

### Mover (role change / re-scoping)
```
Owner change, team transfer, or new capability  -> re-grant scopes (add/remove tool/action)
Every grant change is itself a receipt (who changed what access, when, why)
Risk-tier change re-evaluates which actions auto-allow vs require approval
```

### Leaver (offboarding / suspension / termination)
```
freeze      -> suspend: agent denied on next action (reversible)
revoke      -> terminate: token invalidated, agent removed from active workforce
quarantine  -> isolate a suspect MCP server/tool the agent uses
All deterministic, tenant-scoped, audited; the action path reads agents.status, so it takes effect immediately
```

> Every JML transition emits a receipt → the agent's **employment record** is a tamper-evident chain from hire to termination.

---

## 3. Org model & accountability chain

To roll up "the whole company," add a hierarchy above the agent:

```
Tenant (the company / business unit)
  └── Org unit / Department        (e.g. Engineering, Support, Finance)
        └── Team                    (e.g. payments-platform)
              └── Owner (human)     (accountable for the agent — owner_email)
                    └── Agent       (the digital employee)
```

**Accountability invariant:** every agent has exactly one **human owner**; every action traces agent → owner → team → org. So "who is responsible for what this digital employee did" always has an answer, backed by a receipt. (`agents.owner_email` + `agents.owner_team` already exist; we add the team/org hierarchy.)

---

## 4. Identity & access (IAM for the agent workforce)

- **Identity:** each agent is a first-class principal (`Agent::"id"` in Cedar) with a tenant-scoped, short-lived, rotatable token.
- **Least-privilege grants:** an agent may only call the tools/actions explicitly granted (everything else default-denies). Grants are data (`agent_grants`, §8) so they're reviewable.
- **Access reviews / recertification:** periodic (e.g. quarterly) owner re-certification of each agent's grants — the "do they still need this access?" review. Stale grants flagged; expired grants auto-revoke.
- **Provisioning at scale:** SSO/OIDC for the humans; an enrollment API + (later) SCIM-style automation to onboard/deprovision agents in bulk from a source of truth.
- **Separation of duties:** the **approver** of a high-risk action must not be the agent's **owner** (configurable; enforced by approver-group policy).

This is "least-privilege access management for digital employees," gated deterministically (Design Law 1) — never on a text score.

---

## 5. Workforce monitoring (the SOC, rolled up company-wide)

Built on the Agent SOC (the ASE stream + detections). The workforce lens adds **rollups and per-agent profiles**:

- **Per-agent profile (the "employee file"):** activity feed, risk trend, tools/MCP used, approvals requested/granted, detections, incidents, status history — all receipt-backed.
- **Team rollup (manager view):** a team lead sees only their team's agents: count, high-risk, pending approvals, open incidents, recent denies.
- **Company rollup (CISO/VP view):** all teams — total/active/high-risk agents, incidents, approval SLA, MTTC, **broken down by org/team/owner**, top-risk agents, detection coverage.
- **Behavioral baseline (advisory):** what's normal for this agent; deviations raise *advisory* anomaly score (never gates — Design Law 1) for analyst triage.

Wireframe — company workforce rollup:
```
┌ Agent Workforce  [tenant ▾] [org: all ▾] [last 30d ▾] ─────────────────────────┐
│ [Agents 312] [Active 287] [High-risk 24] [Frozen 3] [Open incidents 2] [Pending appr 9] │
│ ┌ By team ───────────────────────────────┐  ┌ Top-risk agents ─────────────┐ │
│ │ payments-platform   42  ●high  2 inc    │  │ refund-bot        risk 91 ⚠  │ │
│ │ support-desk        88  ●med            │  │ deploy-agent-prod risk 84    │ │
│ │ data-eng            31  ●low            │  │ coding-agent-prod risk 78    │ │
│ └─────────────────────────────────────────┘  └──────────────────────────────┘ │
│ Owner accountability: every agent → human owner → receipt-backed action history │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Supervision & accountability

- **Approvals routed by team/owner group** — a risky action by Finance's `refund-bot` routes to the Finance approver group, not a generic queue.
- **Provable supervision:** the approval is hash-bound and single-use; the receipt records *which human* approved *which exact action* for *which agent* — supervisory accountability you can prove to an auditor.
- **Owner→action traceability:** any action opens to "agent X (owned by human Y, team Z) did this, triggered by source-trust S, decided by policy P, approved by H" — one provable record.

---

## 7. Governance & compliance (leadership + auditors)

- **Access reviews:** scheduled recertification campaigns; export who-can-do-what per team.
- **Policy-as-code per team:** Cedar bundles scoped per org/team; dry-run + canary rollout.
- **Reporting:** per-team risk posture, incident trends, approval SLAs, agent JML activity (hires/moves/terminations), **EU AI Act Article 14 evidence** per agent.
- **Evidence packs:** the receipt chain per agent/team is the tamper-evident compliance artifact — chain-of-custody for the whole digital workforce.

---

## 8. Data model additions (tenant-scoped, parameterized)

Built on the existing `agents` table (already has `owner_team`, `owner_email`, `environment`, `risk_tier`, `status`). Add:

```sql
-- Org hierarchy for rollups (company -> department -> team)
CREATE TABLE org_units (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  parent_id UUID REFERENCES org_units(id),      -- null = top (department)
  kind TEXT NOT NULL,                            -- 'department' | 'team'
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, parent_id, name)
);
CREATE INDEX idx_org_units_tenant ON org_units(tenant_id);

-- Link an agent to its team (owner_email already exists on agents)
ALTER TABLE agents ADD COLUMN team_id UUID REFERENCES org_units(id);
CREATE INDEX idx_agents_team ON agents(tenant_id, team_id);

-- Explicit least-privilege grants (reviewable access)
CREATE TABLE agent_grants (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  agent_id UUID NOT NULL REFERENCES agents(id),
  tool TEXT NOT NULL,
  action TEXT,                                   -- null = all actions of the tool
  granted_by TEXT NOT NULL,                       -- human who granted
  granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ,                          -- null = no auto-expiry
  UNIQUE (tenant_id, agent_id, tool, action)
);
CREATE INDEX idx_agent_grants_tenant_agent ON agent_grants(tenant_id, agent_id);

-- Access-review (recertification) records
CREATE TABLE access_reviews (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  agent_id UUID NOT NULL REFERENCES agents(id),
  reviewer TEXT NOT NULL,                          -- human owner/approver
  decision TEXT NOT NULL,                          -- 'recertified' | 'revoked' | 'modified'
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_access_reviews_tenant ON access_reviews(tenant_id);
```

Every grant change and access review also emits a **receipt** (the access-control history is tamper-evident). All queries bind `tenant_id`; parameterized SQLx only (the project's CWE-284/CWE-89 invariants).

---

## 9. API additions

```http
# Org / workforce structure
GET  /v1/org-units            | POST /v1/org-units            # departments/teams
GET  /v1/agents?team_id=&owner=&risk_tier=&status=            # directory query
GET  /v1/workforce/summary    ?org_unit=&window=              # company/team rollup

# Lifecycle (JML)
POST /v1/agents               # joiner: register (exists)
PATCH /v1/agents/:id          # mover: re-scope owner/team/risk
POST /v1/agents/:id/freeze | /revoke                          # leaver (exists in SOC API)

# Access management
GET  /v1/agents/:id/grants    | POST /v1/agents/:id/grants | DELETE .../grants/:gid
POST /v1/access-reviews       # recertification campaign / decision
GET  /v1/agents/:id/record    # the "employee file": receipt-backed history
```

All tenant-scoped, parameterized, fail-closed (e.g., granting to an unknown agent denies by default).

---

## 10. UI surfaces (extend the SOC Console)

Adds to the console ([`AegisAgent_SOC_UI_Design.md`](AegisAgent_SOC_UI_Design.md) §5/§8.6):
- **Workforce** (company rollup, §5 wireframe) — by org/team/owner.
- **Directory / Fleet** — searchable agent roster with owner, team, risk, status; JML actions.
- **Agent file** — per-agent profile (activity, grants, approvals, incidents, status history) — receipt-backed.
- **Access reviews** — recertification campaigns + per-agent grant review.
- RBAC: a team lead sees only their team's agents; a CISO sees the whole company (§11).

---

## 11. RBAC & visibility (who governs whom)

- **Tenant-scoped, then team-scoped.** A console role is bound to an org scope: `team-lead` sees/manages their team's agents; `org-admin` their department; `tenant-admin` the company. Every query is filtered server-side by both `tenant_id` and the user's org scope (hard invariant).
- **Roles:** `viewer` · `analyst` (investigate) · `approver` (act on the queue — ≠ owner) · `owner` (manage own agents' grants) · `org-admin` / `tenant-admin` (workforce + RBAC).
- Console actions (grant, freeze, recertify) each emit a receipt — governance of the workforce is itself inside the evidence boundary.

---

## 12. The boundary (reaffirmed)

AegisAgent governs the **agent** workforce. It touches **humans only** as: (a) **owners** (accountable for an agent), (b) **approvers** (supervise high-risk actions), (c) **operators** (console RBAC). It is **not** an HRIS, productivity tracker, or insider-threat/UEBA system for human staff — that's a different product and off the moat ("don't become the everything platform," Vision §10). If that need arises, integrate with the company's HR/IdP — don't absorb it.

---

## 13. Build phases

| Step | Deliverable | Depends on |
|---|---|---|
| **W0** | `org_units` + `agents.team_id` + directory query API | migration |
| **W1** | Workforce rollup (`/v1/workforce/summary`) + **Workforce/Fleet UI** | SOC event stream (Phase 0) |
| **W2** | `agent_grants` (least-privilege) + grant APIs + Cedar reads grants | policy integration |
| **W3** | JML flows (re-scope / freeze / revoke) + per-agent **agent file** | control endpoints |
| **W4** | `access_reviews` (recertification) + reviews UI | W2 |
| **W5** | Leadership reporting + per-team Article 14 evidence packs | receipts + rollups |

W0–W1 alone give the company-wide "track the whole agent workforce" view (directory + rollup + per-team breakdown + owner accountability).

---

## 14. Open questions

1. Org hierarchy depth: just `department → team`, or arbitrary nesting?
2. Are `agent_grants` enforced by Cedar at authorize time (hard least-privilege), or advisory for review first?
3. Recertification cadence + auto-revoke on missed review — default policy?
4. Do we model **agent-to-agent delegation** as a workforce relationship (a "manager" agent supervising "worker" agents) now, or later (Vision Phase 4 multi-agent)?
5. SCIM-style bulk provisioning from an external source of truth — which system (Entra Agent ID, ConductorOne) do we sync from first?
