/**
 * Deterministic gateway API fixtures for mocked Playwright flows (#1638).
 */

export type MockRole = "viewer" | "analyst" | "approver" | "admin";
export type ReceiptVerifyMode = "verified" | "failed" | "unknown";

export interface MockRuntimeState {
  agentStatus: string;
  mcpStatus: string;
}

export interface MockScenario {
  tenantId?: string;
  role?: MockRole;
  operatorId?: string;
  receiptVerifyMode?: ReceiptVerifyMode;
  failingPaths?: string[];
}

export function createMockRuntimeState(): MockRuntimeState {
  return { agentStatus: "active", mcpStatus: "active" };
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

const NOW = "2026-06-28T12:00:00.000Z";

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
  // Field names must match the real EvidenceNode contract (ui/src/app/api.ts)
  // -- group/timestamp/metadata, not kind/ts/data -- since
  // incidentGraphNodesToReceiptRows filters on `node.group === "receipt"`.
  return {
    nodes: [{
      id: `receipt:${RECEIPT_ID}`,
      group: "receipt",
      label: "Receipt link",
      timestamp: NOW,
      metadata: {
        id: RECEIPT_ID,
        receipt_hash: "sha256:receipt-good-receipt-good-receipt-good-receipt-good-re",
        prev_receipt_hash: "genesis",
        ts: NOW,
      },
    }],
  };
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
  if (path === "/v1/agents/risk-scoreboard") return { status: 200, body: [] };
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
    // count_by / other aggregates → row array used by tables.
    if (request.aggregate) {
      return {
        status: 200,
        body: {
          version: 1,
          entity: request.entity ?? "decision",
          aggregate: request.aggregate,
          group_by: request.group_by,
          rows:
            tenantId === MOCK_TENANT_A
              ? [{ agent_id: AGENT_ID, count: 3 }]
              : [],
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