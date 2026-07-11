/**
 * Deterministic gateway API fixtures for mocked Playwright flows (#1638).
 */

export type MockRole = "viewer" | "analyst" | "approver" | "admin";
export type ReceiptVerifyMode = "verified" | "failed" | "unknown";

export interface MockBanRecord {
  id: string;
  target_type: string;
  target_value: string;
  scope: string;
  reason: string | null;
  actor: string;
  status: string;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  revoked_by: string | null;
}

export interface MockQuarantineRecord {
  id: string;
  target_type: string;
  target_value: string;
  reason: string | null;
  actor: string;
  status: string;
  incident_id: string | null;
  created_at: string;
  released_at: string | null;
  released_by: string | null;
}

export interface MockPolicyRecord {
  id: string;
  policy_key: string;
  name: string;
  language: string;
  body: string;
  version: number;
  status: string;
  created_by: string | null;
  created_at: string;
}

export interface MockPolicyAuditLogEntry {
  id: string;
  policy_id: string;
  policy_key: string;
  action: string;
  actor: string | null;
  created_at: string;
}

export interface MockRuntimeState {
  agentStatus: string;
  mcpStatus: string;
  runStatus: string;
  bans: MockBanRecord[];
  quarantines: MockQuarantineRecord[];
  policies: MockPolicyRecord[];
  policyAuditLog: MockPolicyAuditLogEntry[];
}

export interface MockScenario {
  tenantId?: string;
  role?: MockRole;
  operatorId?: string;
  receiptVerifyMode?: ReceiptVerifyMode;
  failingPaths?: string[];
}

const NOW = "2026-06-28T12:00:00.000Z";

export function createMockRuntimeState(): MockRuntimeState {
  return {
    agentStatus: "active",
    mcpStatus: "active",
    runStatus: "running",
    bans: [
      {
        id: BAN_ID,
        target_type: "agent",
        target_value: AGENT_KEY,
        scope: "tenant",
        reason: "E2E fixture ban",
        actor: "e2e_operator",
        status: "active",
        created_at: NOW,
        expires_at: null,
        revoked_at: null,
        revoked_by: null,
      },
    ],
    quarantines: [
      {
        id: QUARANTINE_ID,
        target_type: "agent",
        target_value: AGENT_KEY,
        reason: "E2E fixture quarantine",
        actor: "e2e_operator",
        status: "active",
        incident_id: null,
        created_at: NOW,
        released_at: null,
        released_by: null,
      },
    ],
    policies: [
      {
        id: POLICY_ID,
        policy_key: "e2e_fixture_policy_mock",
        name: "E2E Fixture Policy",
        language: "cedar",
        body: 'permit(principal, action, resource) when { context.trust_level == "trusted_internal_signed" };',
        version: 1,
        status: "active",
        created_by: "e2e_operator",
        created_at: NOW,
      },
    ],
    policyAuditLog: [],
  };
}

export const MOCK_TENANT_A = "tenant_e2e_a";
export const MOCK_TENANT_B = "tenant_e2e_b";
export const FAKE_BEARER = "fake-bearer-e2e-only";
export const FAKE_SECRET = "sk-live-super-secret-do-not-leak";

export const AGENT_ID = "agent-uuid-e2e-001";
export const AGENT_KEY = "console-e2e-mock-agent";
export const APPROVAL_ID = "approval-e2e-001";
export const RECEIPT_ID = "receipt-e2e-001";
export const RECEIPT_ID_BROKEN = "receipt-e2e-broken";
export const INCIDENT_ID = "incident-e2e-001";
export const MCP_SERVER_KEY = "mcp-e2e-server";
export const RULE_KEY = "high-risk-merge";
export const RUN_ID = "run-e2e-001";
export const RUN_KEY = "run-key-e2e-001";
export const BAN_ID = "ban-e2e-001";
export const QUARANTINE_ID = "quarantine-e2e-001";
export const POLICY_ID = "policy-e2e-001";

function tenantAgents(tenantId: string, runtime?: MockRuntimeState) {
  if (tenantId === MOCK_TENANT_B) {
    return [{
      id: "agent-uuid-tenant-b",
      tenant_id: MOCK_TENANT_B,
      agent_key: "tenant-b-agent",
      name: "Tenant B Agent",
      owner_team: "security",
      environment: "staging",
      framework: "mock",
      model_provider: "mock",
      model_name: "mock",
      risk_tier: "low",
      status: "active",
      last_seen_at: NOW,
      force_approval: false,
    }];
  }
  const status = runtime?.agentStatus ?? "active";
  return [{
    id: AGENT_ID,
    tenant_id: MOCK_TENANT_A,
    agent_key: AGENT_KEY,
    name: "E2E Mock Agent",
    owner_team: "platform",
    environment: "production",
    framework: "playwright",
    model_provider: "mock",
    model_name: "mock-agent",
    risk_tier: "medium",
    status,
    last_seen_at: NOW,
    force_approval: false,
    frozen_reason: status === "frozen" ? "E2E containment" : null,
  }];
}

function tenantStats(tenantId: string) {
  return tenantId === MOCK_TENANT_B
    ? {
        total_decisions: 3,
        decisions_allow: 3,
        decisions_deny: 0,
        trust_level_breakdown: [{ trust_level: "trusted_internal_signed", count: 3 }],
      }
    : {
        total_decisions: 42,
        decisions_allow: 35,
        decisions_deny: 7,
        trust_level_breakdown: [
          { trust_level: "trusted_internal_signed", count: 30 },
          { trust_level: "semi_trusted_customer", count: 8 },
          { trust_level: "untrusted_external", count: 4 },
        ],
      };
}

function tenantApprovals(tenantId: string) {
  if (tenantId !== MOCK_TENANT_A) return [];
  return [{
    approval_id: APPROVAL_ID,
    agent_id: AGENT_ID,
    tool_name: "github.merge_pull_request",
    tool_call: {
      tool: "github",
      action: "merge_pull_request",
      resource: "octocat/demo#1",
      mutates_state: true,
      parameters: { base_branch: "main", api_key: FAKE_SECRET },
    },
    source_trust: "semi_trusted_customer",
    root_trust_level: "semi_trusted_customer",
    action_hash: "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    canonical_action: '{"tool":"github","action":"merge_pull_request"}',
    expires_in: "14m",
    status: "pending",
  }];
}

function tenantReceipts(tenantId: string) {
  if (tenantId !== MOCK_TENANT_A) return [];
  return [
    {
      id: RECEIPT_ID,
      receipt_hash: "sha256:receipt-good-receipt-good-receipt-good-receipt-good-re",
      prev_receipt_hash: "genesis",
      ts: NOW,
      agent_id: AGENT_ID,
      decision: "allow",
      source_trust: "trusted_internal_signed",
      action_hash: "sha256:action-good-action-good-action-good-action-good-action",
    },
    {
      id: RECEIPT_ID_BROKEN,
      receipt_hash: "sha256:receipt-bad-receipt-bad-receipt-bad-receipt-bad-receipt",
      prev_receipt_hash: "sha256:receipt-good-receipt-good-receipt-good-receipt-good-re",
      ts: NOW,
      agent_id: AGENT_ID,
      decision: "allow",
      source_trust: "trusted_internal_signed",
      action_hash: "sha256:action-bad-action-bad-action-bad-action-bad-action-bad",
    },
  ];
}

function tenantDecisions(tenantId: string) {
  if (tenantId !== MOCK_TENANT_A) return [];
  return [{
    id: "decision-e2e-001",
    agent_id: AGENT_ID,
    tool: "github",
    action: "read_issue",
    decision: "allow",
    source_trust: "trusted_internal_signed",
    root_trust_level: "trusted_internal_signed",
    action_hash: "sha256:decision-action-decision-action-decision-action-decisi",
    receipt_hash: "sha256:decision-receipt-decision-receipt-decision-receipt-de",
    receipt_id: RECEIPT_ID,
    ts: NOW,
    reason: "Permitted by policy",
    authorization: `Bearer ${FAKE_SECRET}`,
  }];
}

function tenantAlerts(tenantId: string) {
  if (tenantId !== MOCK_TENANT_A) return [];
  return [{
    id: "alert-e2e-001",
    alert_id: "alert-e2e-001",
    rule: RULE_KEY,
    rule_key: RULE_KEY,
    severity: "high",
    agent_id: AGENT_ID,
    summary: "Mock high-risk merge detected",
    created_at: NOW,
    occurred_at: NOW,
    payload: { api_key: FAKE_SECRET, token: "nested-secret" },
  }];
}

function tenantIncidents(tenantId: string) {
  if (tenantId !== MOCK_TENANT_A) return [];
  return [{
    id: INCIDENT_ID,
    kind: "receipt-chain-broken",
    summary: "Ordered receipt linkage failed verification",
    severity: "high",
    status: "open",
    agent_id: AGENT_ID,
    opened_at: NOW,
  }];
}

function incidentGraph() {
  // Field names must match the real EvidenceNode contract
  // (group/timestamp/metadata) for decision-graph + receipt filters.
  return {
    nodes: [
      {
        id: `agent:${AGENT_ID}`,
        group: "agent",
        label: "E2E Mock Agent",
        timestamp: NOW,
        metadata: null,
      },
      {
        id: "tool_call:decision-e2e-001",
        group: "tool_call",
        label: "github.merge_pull_request",
        timestamp: NOW,
        metadata: null,
      },
      {
        id: "decision:decision-e2e-001",
        group: "decision",
        label: "require_approval",
        timestamp: NOW,
        metadata: { risk_score: 72, reason: "high-risk mutating action" },
      },
      {
        id: `approval:${APPROVAL_ID}`,
        group: "approval",
        label: "pending",
        timestamp: NOW,
        metadata: null,
      },
      {
        id: `receipt:${RECEIPT_ID}`,
        group: "receipt",
        label: "Receipt link",
        timestamp: NOW,
        metadata: {
          id: RECEIPT_ID,
          receipt_hash:
            "sha256:receipt-good-receipt-good-receipt-good-receipt-good-re",
          prev_receipt_hash: "genesis",
          ts: NOW,
        },
      },
      {
        id: `incident:${INCIDENT_ID}`,
        group: "incident",
        label: "Ordered receipt linkage failed",
        timestamp: NOW,
        metadata: null,
      },
    ],
    edges: [
      {
        from: `agent:${AGENT_ID}`,
        to: "tool_call:decision-e2e-001",
        label: "triggered_by",
        timestamp: NOW,
      },
      {
        from: "tool_call:decision-e2e-001",
        to: "decision:decision-e2e-001",
        label: "decided",
        timestamp: NOW,
      },
      {
        from: "decision:decision-e2e-001",
        to: `approval:${APPROVAL_ID}`,
        label: "approved",
        timestamp: NOW,
      },
      {
        from: "decision:decision-e2e-001",
        to: `receipt:${RECEIPT_ID}`,
        label: "produced",
        timestamp: NOW,
      },
      {
        from: `incident:${INCIDENT_ID}`,
        to: "decision:decision-e2e-001",
        label: "linked_to",
        timestamp: NOW,
      },
    ],
  };
}

/** Run/agent-scoped graph reuses the same shape as the incident graph. */
function runOrAgentGraph() {
  return incidentGraph();
}

function tenantAgentRun(tenantId: string, runtime?: MockRuntimeState) {
  if (tenantId !== MOCK_TENANT_A) return [];
  return [
    {
      id: RUN_ID,
      agent_id: AGENT_ID,
      run_key: RUN_KEY,
      source_component: "sdk",
      mode: "enforce",
      status: runtime?.runStatus ?? "running",
      started_at: NOW,
      finished_at: null,
      root_trace_id: "trace-e2e-001",
      root_trust_level: "trusted_internal_signed",
      policy_bundle_id: null,
      claimed_by: null,
    },
  ];
}

function tenantRunTimeline(tenantId: string) {
  if (tenantId !== MOCK_TENANT_A) return [];
  return [
    {
      id: "audit-e2e-001",
      event_type: "authorize_decision",
      agent_id: AGENT_ID,
      run_id: RUN_ID,
      skill: "github",
      action: "read_issue",
      resource: "octocat/demo-repo#1",
      decision_id: "decision-e2e-001",
      created_at: NOW,
    },
  ];
}

function tenantRunEvents(tenantId: string) {
  if (tenantId !== MOCK_TENANT_A) return [];
  return [
    {
      id: "runtime-event-e2e-001",
      event_id: "runtime-event-e2e-001",
      event_type: "sandbox_started",
      severity: "info",
      agent_id: AGENT_ID,
      run_id: RUN_ID,
      source_component: "cage-runner",
      decision: null,
      reason: null,
      observed_at: NOW,
    },
  ];
}

function tenantPromptEvents(tenantId: string) {
  if (tenantId !== MOCK_TENANT_A) return [];
  return [
    {
      id: "prompt-event-e2e-001",
      event_id: "prompt-event-e2e-001",
      run_id: RUN_ID,
      trace_id: "trace-e2e-001",
      prompt_hash: "a".repeat(64),
      redacted_prompt_preview: "Summarize the attached [REDACTED] file",
      role: "user",
      source_trust: "trusted_internal_signed",
      model_provider: "openai",
      retention_policy: "30d",
      redaction_status: "redacted",
      created_at: NOW,
    },
  ];
}

function tenantModelCalls(tenantId: string) {
  if (tenantId !== MOCK_TENANT_A) return [];
  return [
    {
      id: "model-call-e2e-001",
      event_id: "model-call-e2e-001",
      run_id: RUN_ID,
      trace_id: "trace-e2e-001",
      provider: "openai",
      model: "gpt-5",
      request_hash: "b".repeat(64),
      response_hash: "c".repeat(64),
      started_at: NOW,
      finished_at: NOW,
      token_counts_json: '{"prompt":10,"completion":20}',
      status: "success",
      redaction_status: "redacted",
      received_at: NOW,
    },
  ];
}

function tenantEgressEvents(tenantId: string) {
  if (tenantId !== MOCK_TENANT_A) return [];
  return [
    {
      id: "egress-event-e2e-001",
      event_id: "egress-event-e2e-001",
      event_type: "egress_check",
      severity: "info",
      agent_id: AGENT_ID,
      run_id: RUN_ID,
      decision: "allow",
      reason: "matched tenant allow rule",
      observed_at: NOW,
    },
  ];
}

function tenantMcpServers(tenantId: string, runtime?: MockRuntimeState) {
  if (tenantId !== MOCK_TENANT_A) return [];
  return [{
    server_key: MCP_SERVER_KEY,
    name: "E2E MCP Server",
    status: runtime?.mcpStatus ?? "active",
    manifest_hash: "sha256:manifest-pinned",
    transport: "http",
    trust_level: "trusted_internal_signed",
  }];
}

function socRules() {
  return [{
    rule_key: RULE_KEY,
    name: "High risk merge",
    severity: "high",
    condition: { event_type: "authorize_decision", decision: "require_approval" },
    summary_template: "Merge requires approval",
    source: "builtin",
    enabled: true,
  }];
}

function detectionRules() {
  return [{
    id: "custom-rule-001",
    rule_key: "custom-e2e-rule",
    name: "Custom E2E Rule",
    severity: "medium",
    condition: { decision: "deny" },
    summary_template: "Denied action",
    source: "tenant",
    enabled: true,
  }];
}

export function receiptVerifyResponse(mode: ReceiptVerifyMode, receiptId?: string) {
  if (mode === "verified") {
    return { status: "verified", verified: true, ok: true, message: "Receipt cryptographic signature matches the hash chain." };
  }
  if (mode === "failed" || receiptId === RECEIPT_ID_BROKEN) {
    return {
      status: "failed",
      verified: false,
      ok: false,
      broken_at_row: 2,
      error: "prev_receipt_hash mismatch at index 1",
      message: "Receipt verification failed or the chain is broken.",
    };
  }
  return { status: "unknown", message: "The gateway did not explicitly confirm receipt verification." };
}

export function resolveMockResponse(
  method: string,
  path: string,
  tenantId: string,
  scenario: MockScenario,
  runtime: MockRuntimeState = createMockRuntimeState(),
  body?: unknown,
): { status: number; body: unknown } | null {
  const failPaths = scenario.failingPaths ?? [];
  if (failPaths.includes(path)) {
    return { status: 500, body: { error: "Simulated gateway failure" } };
  }

  if (path === "/v1/session") {
    return {
      status: 200,
      body: {
        tenant_id: tenantId,
        role: scenario.role ?? "viewer",
        user_id: scenario.operatorId ?? "platform_admin",
      },
    };
  }

  if (path === "/v1/stats") return { status: 200, body: tenantStats(tenantId) };
  if (path === "/v1/soc/summary") {
    return {
      status: 200,
      body: {
        incidents_open: tenantId === MOCK_TENANT_A ? 1 : 0,
        alerts_total: tenantId === MOCK_TENANT_A ? 1 : 0,
        approvals_pending: tenantId === MOCK_TENANT_A ? 1 : 0,
      },
    };
  }
  if (path === "/v1/soc/stream") {
    return { status: 501, body: { error: "SSE not available in mock gateway" } };
  }
  if (path.startsWith("/v1/decisions/timeseries")) {
    return {
      status: 200,
      body: [
        { bucket: "2026-06-28T10:00:00.000Z", count: 4 },
        { bucket: "2026-06-28T11:00:00.000Z", count: 6 },
      ],
    };
  }
  if (path === "/v1/agents") return { status: 200, body: tenantAgents(tenantId, runtime) };
  if (path === "/v1/agents/risk-scoreboard") {
    if (tenantId !== MOCK_TENANT_A) return { status: 200, body: [] };
    return {
      status: 200,
      body: [
        {
          agent_id: AGENT_ID,
          agent_key: AGENT_KEY,
          current_avg_risk_score: 62.4,
          decision_count_24h: 18,
          trend: "rising",
        },
        {
          agent_id: "agent-uuid-e2e-002",
          agent_key: "batch-worker",
          current_avg_risk_score: 28.1,
          decision_count_24h: 40,
          trend: "stable",
        },
        {
          agent_id: "agent-uuid-e2e-003",
          agent_key: "read-only-bot",
          current_avg_risk_score: 8.5,
          decision_count_24h: 5,
          trend: "falling",
        },
      ],
    };
  }
  if (path === `/v1/agents/${AGENT_ID}`) {
    const agent = tenantAgents(tenantId, runtime).find((row) => row.id === AGENT_ID);
    return agent ? { status: 200, body: agent } : { status: 404, body: { error: "not found" } };
  }
  if (path === `/v1/agents/${AGENT_ID}/permissions`) {
    return {
      status: 200,
      body: {
        permissions: [{
          id: "perm-1",
          tenant_id: tenantId,
          agent_id: AGENT_ID,
          tool_key: "github",
          created_at: NOW,
        }],
      },
    };
  }
  if (method === "POST" && /^\/v1\/agents\/[^/]+\/(freeze|unfreeze|restore|revoke)$/.test(path)) {
    const action = path.split("/").pop();
    runtime.agentStatus =
      action === "freeze" ? "frozen" : action === "unfreeze" ? "active" : action === "restore" ? "active" : "revoked";
    const agent = tenantAgents(tenantId, runtime)[0];
    return { status: 200, body: agent };
  }

  if (path === "/v1/approvals") return { status: 200, body: tenantApprovals(tenantId) };
  if (method === "POST" && path === `/v1/approvals/${APPROVAL_ID}/approve`) {
    return { status: 200, body: { status: "approved", approval_id: APPROVAL_ID } };
  }
  if (method === "POST" && path === `/v1/approvals/${APPROVAL_ID}/reject`) {
    return { status: 200, body: { status: "rejected", approval_id: APPROVAL_ID } };
  }

  if (path.startsWith("/v1/receipts")) {
    if (method === "POST" && (path === "/v1/receipts/verify-range" || path === "/v1/receipts/verify-chain")) {
      const mode = scenario.receiptVerifyMode ?? "verified";
      if (mode === "verified") {
        return { status: 200, body: { status: "verified", verified: true, ok: true, message: "Chain tamper-free." } };
      }
      if (mode === "failed") return { status: 200, body: receiptVerifyResponse("failed") };
      return { status: 200, body: receiptVerifyResponse("unknown") };
    }
    const receiptMatch = path.match(/^\/v1\/receipts\/([^/]+)\/verify$/);
    if (receiptMatch) {
      const id = decodeURIComponent(receiptMatch[1]);
      const mode = id === RECEIPT_ID_BROKEN ? "failed" : (scenario.receiptVerifyMode ?? "verified");
      return { status: 200, body: receiptVerifyResponse(mode, id) };
    }
    if (path.startsWith("/v1/receipts")) return { status: 200, body: tenantReceipts(tenantId) };
  }

  if (method === "POST" && path === "/v1/soc/query") {
    const request = (body ?? {}) as {
      entity?: string;
      aggregate?: string;
      group_by?: string;
    };
    // count_over_time → timeseries envelope (matches gateway SocQueryResponse).
    if (request.aggregate === "count_over_time") {
      const rows =
        tenantId === MOCK_TENANT_A
          ? [
              { bucket: "2026-06-28T10:00:00.000Z", count: 4 },
              { bucket: "2026-06-28T11:00:00.000Z", count: 6 },
              { bucket: "2026-06-28T12:00:00.000Z", count: 3 },
            ]
          : [{ bucket: "2026-06-28T10:00:00.000Z", count: 1 }];
      return {
        status: 200,
        body: {
          version: 1,
          entity: request.entity ?? "decision",
          aggregate: "count_over_time",
          rows,
          field_descriptors: [
            { name: "bucket", type: "time", facetable: false },
            { name: "count", type: "number", facetable: false },
          ],
          meta: {},
        },
      };
    }
    // count_by → gateway shape { value, count } (heatmap / facet panels).
    if (request.aggregate === "count_by") {
      const groupBy = request.group_by ?? "decision";
      const rows =
        tenantId === MOCK_TENANT_A
          ? groupBy === "source_trust"
            ? [
                { value: "trusted_internal_unsigned", count: 8 },
                { value: "semi_trusted_customer", count: 3 },
                { value: "untrusted_external", count: 1 },
              ]
            : groupBy === "decision"
              ? [
                  { value: "allow", count: 10 },
                  { value: "deny", count: 2 },
                  { value: "require_approval", count: 1 },
                ]
              : [{ value: AGENT_ID, count: 3 }]
          : [];
      return {
        status: 200,
        body: {
          version: 1,
          entity: request.entity ?? "decision",
          aggregate: "count_by",
          group_by: groupBy,
          rows,
          field_descriptors: [
            { name: "value", type: "string", facetable: true },
            { name: "count", type: "number", facetable: false },
          ],
          meta: {},
        },
      };
    }
    // Other aggregates → envelope with empty/minimal rows.
    if (request.aggregate) {
      return {
        status: 200,
        body: {
          version: 1,
          entity: request.entity ?? "decision",
          aggregate: request.aggregate,
          group_by: request.group_by,
          rows: [],
          field_descriptors: [],
          meta: {},
        },
      };
    }
    if ((request.entity ?? "decision") === "decision") {
      return {
        status: 200,
        body: {
          version: 1,
          entity: "decision",
          rows: tenantDecisions(tenantId),
          field_descriptors: [],
          meta: { total: tenantDecisions(tenantId).length },
        },
      };
    }
    return {
      status: 200,
      body: { version: 1, entity: request.entity ?? "ase", rows: [], meta: {} },
    };
  }
  if (path.startsWith("/v1/decisions")) return { status: 200, body: tenantDecisions(tenantId) };
  if (path === "/v1/alerts" || path.startsWith("/v1/alerts?")) return { status: 200, body: tenantAlerts(tenantId) };
  if (path === "/v1/incidents" || path.startsWith("/v1/incidents?")) return { status: 200, body: tenantIncidents(tenantId) };
  if (path === `/v1/incidents/${INCIDENT_ID}`) return { status: 200, body: tenantIncidents(tenantId)[0] };
  if (path === `/v1/incidents/${INCIDENT_ID}/narrate`) {
    return {
      status: 200,
      body: {
        narrative: "Ordered receipt linkage failed during automated verification.",
        summary: "Incident involves a broken receipt chain link.",
      },
    };
  }
  if (path === `/v1/graph/incident/${INCIDENT_ID}`) return { status: 200, body: incidentGraph() };
  if (path === `/v1/graph/run/${RUN_ID}`) return { status: 200, body: runOrAgentGraph() };
  if (path.startsWith(`/v1/graph/agent/${AGENT_ID}`)) return { status: 200, body: runOrAgentGraph() };

  // Agent Cage Runs (Phase 9.2)
  if (path === "/v1/agent-cage/runs" || path.startsWith("/v1/agent-cage/runs?")) {
    return { status: 200, body: tenantAgentRun(tenantId, runtime) };
  }
  if (path === `/v1/agent-cage/runs/${RUN_ID}`) {
    const run = tenantAgentRun(tenantId, runtime)[0];
    return run ? { status: 200, body: run } : { status: 404, body: { error: "not found" } };
  }
  if (
    method === "POST" &&
    /^\/v1\/agent-cage\/runs\/[^/]+\/(pause|resume|kill|quarantine)$/.test(path)
  ) {
    const action = path.split("/").pop();
    runtime.runStatus =
      action === "pause" ? "paused" : action === "resume" ? "running" : action === "kill" ? "killed" : "quarantined";
    return {
      status: 200,
      body: { command_id: `command-e2e-${action}`, status: "issued", action },
    };
  }
  if (path === `/v1/runs/${RUN_ID}/timeline`) return { status: 200, body: tenantRunTimeline(tenantId) };
  if (path.startsWith(`/v1/runtime/runs/${RUN_ID}/events`)) return { status: 200, body: tenantRunEvents(tenantId) };
  if (path.startsWith(`/v1/runtime/runs/${RUN_ID}/prompt-events`)) return { status: 200, body: tenantPromptEvents(tenantId) };
  if (path.startsWith(`/v1/runtime/runs/${RUN_ID}/model-calls`)) return { status: 200, body: tenantModelCalls(tenantId) };

  // Ban Center (Phase 9.3)
  if (path === "/v1/bans" || path.startsWith("/v1/bans?")) {
    if (method === "POST") {
      const req = (body ?? {}) as Partial<MockBanRecord>;
      const created: MockBanRecord = {
        id: `ban-e2e-created-${runtime.bans.length + 1}`,
        target_type: req.target_type ?? "agent",
        target_value: req.target_value ?? "unknown",
        scope: req.scope ?? "tenant",
        reason: req.reason ?? null,
        actor: req.actor ?? "e2e_operator",
        status: "active",
        created_at: NOW,
        expires_at: null,
        revoked_at: null,
        revoked_by: null,
      };
      runtime.bans.push(created);
      return { status: 201, body: created };
    }
    return { status: 200, body: tenantId === MOCK_TENANT_A ? runtime.bans : [] };
  }
  const revokeBanMatch = path.match(/^\/v1\/bans\/([^/]+)\/revoke$/);
  if (method === "POST" && revokeBanMatch) {
    const id = decodeURIComponent(revokeBanMatch[1]);
    const ban = runtime.bans.find((b) => b.id === id);
    if (!ban) return { status: 404, body: { error: "not found" } };
    ban.status = "revoked";
    ban.revoked_at = NOW;
    ban.revoked_by = (body as { revoked_by?: string } | undefined)?.revoked_by ?? "e2e_operator";
    return { status: 200, body: ban };
  }

  // Quarantine Center (Phase 9.3)
  if (path === "/v1/quarantine" || path.startsWith("/v1/quarantine?")) {
    if (method === "POST") {
      const req = (body ?? {}) as Partial<MockQuarantineRecord>;
      const created: MockQuarantineRecord = {
        id: `quarantine-e2e-created-${runtime.quarantines.length + 1}`,
        target_type: req.target_type ?? "agent",
        target_value: req.target_value ?? "unknown",
        reason: req.reason ?? null,
        actor: req.actor ?? "e2e_operator",
        status: "active",
        incident_id: req.incident_id ?? null,
        created_at: NOW,
        released_at: null,
        released_by: null,
      };
      runtime.quarantines.push(created);
      return { status: 201, body: created };
    }
    return { status: 200, body: tenantId === MOCK_TENANT_A ? runtime.quarantines : [] };
  }
  const releaseQuarantineMatch = path.match(/^\/v1\/quarantine\/([^/]+)\/release$/);
  if (method === "POST" && releaseQuarantineMatch) {
    const id = decodeURIComponent(releaseQuarantineMatch[1]);
    const q = runtime.quarantines.find((row) => row.id === id);
    if (!q) return { status: 404, body: { error: "not found" } };
    q.status = "released";
    q.released_at = NOW;
    q.released_by = (body as { released_by?: string } | undefined)?.released_by ?? "e2e_operator";
    return { status: 200, body: q };
  }

  // Egress Events (Phase 9.2)
  if (path.startsWith("/v1/egress/events")) {
    return { status: 200, body: tenantId === MOCK_TENANT_A ? tenantEgressEvents(tenantId) : [] };
  }
  if (method === "POST" && path === "/v1/egress/block") {
    const req = (body ?? {}) as { destination?: string; actor?: string; reason?: string };
    const created: MockBanRecord = {
      id: `ban-e2e-egress-${runtime.bans.length + 1}`,
      target_type: "destination",
      target_value: req.destination ?? "unknown",
      scope: "tenant",
      reason: req.reason ?? null,
      actor: req.actor ?? "e2e_operator",
      status: "active",
      created_at: NOW,
      expires_at: null,
      revoked_at: null,
      revoked_by: null,
    };
    runtime.bans.push(created);
    return { status: 201, body: created };
  }
  if (method === "POST" && path === "/v1/egress/unblock") {
    const req = (body ?? {}) as { ban_id?: string; revoked_by?: string };
    const ban = runtime.bans.find((b) => b.id === req.ban_id);
    if (!ban) return { status: 404, body: { error: "not found" } };
    ban.status = "revoked";
    ban.revoked_at = NOW;
    ban.revoked_by = req.revoked_by ?? "e2e_operator";
    return { status: 200, body: ban };
  }

  // Policy Center (Phase 9.3)
  if (path === "/v1/policies" || path.startsWith("/v1/policies?")) {
    if (method === "POST") {
      const req = (body ?? {}) as { policy_key?: string; name?: string; body?: string };
      const created: MockPolicyRecord = {
        id: `policy-e2e-created-${runtime.policies.length + 1}`,
        policy_key: req.policy_key ?? "unknown",
        name: req.name ?? "Untitled policy",
        language: "cedar",
        body: req.body ?? "",
        version: 1,
        status: "active",
        created_by: "e2e_operator",
        created_at: NOW,
      };
      runtime.policies.push(created);
      runtime.policyAuditLog.push({
        id: `policy-audit-e2e-${runtime.policyAuditLog.length + 1}`,
        policy_id: created.id,
        policy_key: created.policy_key,
        action: "created",
        actor: "e2e_operator",
        created_at: NOW,
      });
      return { status: 201, body: created };
    }
    return { status: 200, body: tenantId === MOCK_TENANT_A ? runtime.policies : [] };
  }
  if (path === "/v1/policies/audit-log") {
    return { status: 200, body: tenantId === MOCK_TENANT_A ? runtime.policyAuditLog : [] };
  }
  const rollbackPolicyMatch = path.match(/^\/v1\/policies\/([^/]+)\/rollback$/);
  if (method === "POST" && rollbackPolicyMatch) {
    const id = decodeURIComponent(rollbackPolicyMatch[1]);
    const policy = runtime.policies.find((p) => p.id === id);
    if (!policy) return { status: 404, body: { error: "not found" } };
    policy.version = Math.max(1, policy.version - 1);
    runtime.policyAuditLog.push({
      id: `policy-audit-e2e-${runtime.policyAuditLog.length + 1}`,
      policy_id: policy.id,
      policy_key: policy.policy_key,
      action: "rolled_back",
      actor: "e2e_operator",
      created_at: NOW,
    });
    return { status: 200, body: policy };
  }
  const policyByIdMatch = path.match(/^\/v1\/policies\/([^/]+)$/);
  if (policyByIdMatch) {
    const id = decodeURIComponent(policyByIdMatch[1]);
    const policy = runtime.policies.find((p) => p.id === id);
    if (!policy) return { status: 404, body: { error: "not found" } };
    if (method === "PUT") {
      const req = (body ?? {}) as { name?: string; body?: string; status?: string };
      if (req.name !== undefined) policy.name = req.name;
      if (req.body !== undefined) policy.body = req.body;
      if (req.status !== undefined) policy.status = req.status;
      policy.version += 1;
      runtime.policyAuditLog.push({
        id: `policy-audit-e2e-${runtime.policyAuditLog.length + 1}`,
        policy_id: policy.id,
        policy_key: policy.policy_key,
        action: "updated",
        actor: "e2e_operator",
        created_at: NOW,
      });
      return { status: 200, body: policy };
    }
    if (method === "DELETE") {
      runtime.policies = runtime.policies.filter((p) => p.id !== id);
      runtime.policyAuditLog.push({
        id: `policy-audit-e2e-${runtime.policyAuditLog.length + 1}`,
        policy_id: id,
        policy_key: policy.policy_key,
        action: "deleted",
        actor: "e2e_operator",
        created_at: NOW,
      });
      return { status: 200, body: { deleted: true } };
    }
  }

  if (path === "/v1/mcp/servers") return { status: 200, body: tenantMcpServers(tenantId, runtime) };
  if (path === `/v1/mcp/servers/${encodeURIComponent(MCP_SERVER_KEY)}/tools`) {
    return {
      status: 200,
      body: [{ tool_key: "create_issue", name: "Create issue", status: "approved", risk: "medium", mutates_state: true }],
    };
  }
  if (path === `/v1/mcp/servers/${encodeURIComponent(MCP_SERVER_KEY)}/manifest-history`) {
    return {
      status: 200,
      body: { server_key: MCP_SERVER_KEY, snapshots: [{ manifest_hash: "sha256:manifest-pinned", created_at: NOW, event_type: "discovery" }] },
    };
  }
  if (method === "POST" && path === `/v1/mcp/servers/${encodeURIComponent(MCP_SERVER_KEY)}/quarantine`) {
    runtime.mcpStatus = "quarantined";
    return { status: 200, body: tenantMcpServers(tenantId, runtime)[0] };
  }
  if (method === "POST" && path === `/v1/mcp/servers/${encodeURIComponent(MCP_SERVER_KEY)}/restore`) {
    runtime.mcpStatus = "active";
    return { status: 200, body: tenantMcpServers(tenantId, runtime)[0] };
  }

  if (path === "/v1/soc/rules") return { status: 200, body: socRules() };
  if (path === "/v1/detection_rules") return { status: 200, body: detectionRules() };
  if (method === "POST" && path === `/v1/soc/rules/${RULE_KEY}/backtest`) {
    return {
      status: 200,
      body: {
        decisions_scanned: 12,
        match_count: 2,
        estimated_daily_alert_volume: 0.25,
        matched_decision_ids: ["decision-e2e-001"],
      },
    };
  }

  // Settings page capability discovery (discoverSettingsCapabilities): each
  // probed endpoint must be explicitly handled here, even the ones the real
  // gateway doesn't implement yet, so `mock.unhandled` stays empty and the
  // probe's success/failure accurately reflects real gateway behavior.
  if (path === `/v1/tenants/${encodeURIComponent(tenantId)}`) {
    return {
      status: 200,
      body: { id: tenantId, name: "E2E Tenant", plan: "enterprise", created_at: "2026-01-01T00:00:00.000Z" },
    };
  }
  if (path === "/v1/tenants/risk-weights") {
    return {
      status: 200,
      body: {
        environment_weight_mutating: 15,
        context_trust_penalty_trusted_internal_signed: 0,
        context_trust_penalty_trusted_internal_unsigned: 5,
        context_trust_penalty_semi_trusted_customer: 15,
        context_trust_penalty_untrusted_external: 30,
        context_trust_penalty_malicious_suspected: 50,
        context_trust_penalty_unknown: 20,
        mcp_trust_penalty: 10,
        anomaly_weight_pct: 100,
        approval_credit: 10,
      },
    };
  }
  if (path.startsWith("/v1/webhook_subscriptions")) {
    return { status: 200, body: [] };
  }
  if (path.startsWith("/v1/soc/silences")) {
    return { status: 200, body: [] };
  }
  if (path === "/v1/admin/retention") {
    // Not implemented on the real gateway either — mirrors its actual 404 so
    // `probeGatewayEndpoint` correctly reports this capability as absent.
    return { status: 404, body: { error: "not found" } };
  }

  // Tenant dashboard editor (#1634 / Phase D)
  if (path === "/v1/soc/dashboards") {
    return { status: 200, body: [] };
  }
  if (path.startsWith("/v1/soc/dashboards/")) {
    return { status: 404, body: { error: "not found" } };
  }

  return null;
}