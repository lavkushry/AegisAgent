export interface FetchOptions {
  gatewayUrl: string;
  bearerToken: string;
  tenantId: string;
}

export class GatewayRequestError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "GatewayRequestError";
  }
}

export interface TenantStats {
  total_decisions?: number;
  decisions_allow?: number;
  decisions_deny?: number;
  total_receipts?: number;
  receipt_chain_verified?: boolean;
}

export interface SocSummary {
  approvals_pending?: number;
  incidents_open?: number;
  alerts_total?: number;
  hourly_decisions_24h?: number[];
}

export interface AlertRecord {
  id: string;
  alert_id: string;
  rule: string;
  severity: string;
  summary: string;
  agent_id: string;
  created_at: string;
  occurred_at: string;
  source_event_id?: string;
}

export interface IncidentRecord {
  id: string;
  kind: string;
  summary: string;
  severity: string;
  status: string;
  agent_id: string;
  opened_at: string;
}

export interface AuthorizeToolCall {
  tool: string;
  action: string;
  resource?: string | null;
  mutates_state: boolean;
  parameters: unknown;
}

export interface ApprovalRecord {
  id?: string;
  approval_id?: string;
  tool_name?: string;
  tool_call?: AuthorizeToolCall;
  edited_tool_call?: AuthorizeToolCall;
  agent_id?: string;
  source_trust?: string;
  action_hash?: string;
  original_action_hash?: string;
  edited_action_hash?: string;
  effective_action_hash?: string;
  is_edited?: boolean;
  expires_in?: string;
  expires_at?: string;
  status?: string;
  approver_group?: string;
}

export interface AgentRiskRecord {
  agent_id?: string;
  avg_risk_score?: number;
  trend?: string;
}

export interface AgentRecord {
  id?: string;
  status?: string;
  risk_tier?: string;
}

export interface McpServerRecord {
  server_key: string;
  status?: string;
  manifest_hash?: string;
  transport?: string;
}

export interface McpManifestRecord {
  event_type?: string;
  manifest_hash?: string;
  manifest_json?: string;
  description?: string;
  details?: string;
  created_at?: string;
  ts?: string;
}

interface McpManifestHistoryEnvelope {
  server_key?: string;
  snapshots?: McpManifestRecord[];
}

export interface ReceiptRecord {
  id: string;
  tool?: string;
  receipt_hash?: string;
  prev_receipt_hash?: string;
  ts?: string;
  created_at?: string;
  agent_id?: string;
  run_id?: string;
  trace_id?: string;
}

export interface DecisionRecord {
  [key: string]: unknown;
  id: string;
  decision?: string;
  tool?: string;
  skill?: string;
  tool_call?: { name?: string; parameters?: Record<string, unknown> };
  agent_id?: string;
  root_trust_level?: string;
  source_trust?: string;
  created_at?: string;
  ts?: string;
  reason?: string;
  matched_policies?: string[];
  matched_policy_ids?: string[];
  run_id?: string;
  action_hash?: string;
  composite_risk_score?: number;
}

export interface EvidenceNode {
  id: string;
  group?: string;
  label?: string;
  timestamp?: string;
  metadata?: unknown;
}

export interface IncidentGraph {
  nodes: EvidenceNode[];
}

export interface IncidentNarration {
  narrative?: string;
  summary?: string;
}

export interface SocRuleRecord {
  id?: string;
  rule_key: string;
  name: string;
  severity: string;
  condition: unknown;
  summary_template: string;
  source?: string;
  enabled: boolean;
}

export interface BacktestResult {
  decisions_scanned: number;
  match_count: number;
  estimated_daily_alert_volume: number;
  matched_decision_ids: string[];
}

export function buildGatewayHeaders(options: FetchOptions, hasBody = false) {
  const tenantId = options.tenantId.trim();
  if (!tenantId) {
    throw new Error("A tenant must be selected before calling the AegisAgent gateway.");
  }

  const headers: Record<string, string> = {
    "Accept": "application/json",
    "X-Aegis-Tenant-ID": tenantId,
  };
  const token = options.bearerToken.trim();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  if (hasBody) {
    headers["Content-Type"] = "application/json";
  }
  return headers;
}

export async function fetchFromGateway<T>(
  options: FetchOptions,
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const url = `${options.gatewayUrl.replace(/\/+$/, "")}${path}`;
  const hasBody = body !== undefined;
  
  const config: RequestInit = {
    method,
    headers: buildGatewayHeaders(options, hasBody),
  };

  if (hasBody) {
    config.body = JSON.stringify(body);
  }

  const response = await fetch(url, config);

  if (response.status === 204) {
    return {} as T;
  }

  if (!response.ok) {
    let errorMsg = `HTTP ${response.status}: ${response.statusText}`;
    try {
      const errJson: unknown = await response.json();
      if (
        typeof errJson === "object" &&
        errJson !== null &&
        "message" in errJson &&
        typeof errJson.message === "string"
      ) {
        errorMsg = errJson.message;
      }
    } catch {
      // Preserve the status-based error when the gateway does not return JSON.
    }
    throw new GatewayRequestError(errorMsg, response.status);
  }

  return response.json() as Promise<T>;
}

export async function downloadFromGateway(
  options: FetchOptions,
  path: string,
): Promise<Blob> {
  const url = `${options.gatewayUrl.replace(/\/+$/, "")}${path}`;
  const response = await fetch(url, { headers: buildGatewayHeaders(options) });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }
  return response.blob();
}

// Stats & Summaries
export function getStats(opts: FetchOptions) {
  return fetchFromGateway<TenantStats>(opts, "/v1/stats");
}

export function getSocSummary(opts: FetchOptions) {
  return fetchFromGateway<SocSummary>(opts, "/v1/soc/summary");
}

// Alerts & Incidents
export function getAlerts(opts: FetchOptions, limit = 50) {
  return fetchFromGateway<AlertRecord[]>(opts, `/v1/alerts?limit=${limit}`);
}

export function getIncidents(opts: FetchOptions, limit = 50) {
  return fetchFromGateway<IncidentRecord[]>(opts, `/v1/incidents?limit=${limit}`);
}

export function getIncidentDetail(opts: FetchOptions, id: string) {
  return fetchFromGateway<IncidentRecord>(opts, `/v1/incidents/${id}`);
}

// Approvals Queue
export function getApprovals(opts: FetchOptions) {
  return fetchFromGateway<ApprovalRecord[]>(opts, "/v1/approvals");
}

export function approveApproval(
  opts: FetchOptions,
  approvalId: string,
  approverUserId: string,
  reason: string,
) {
  const id = encodeURIComponent(approvalId);
  return fetchFromGateway<Record<string, unknown>>(opts, `/v1/approvals/${id}/approve`, "POST", {
    approver_user_id: approverUserId,
    reason,
  });
}

export function rejectApproval(
  opts: FetchOptions,
  approvalId: string,
  approverUserId: string,
  reason: string,
) {
  const id = encodeURIComponent(approvalId);
  return fetchFromGateway<Record<string, unknown>>(opts, `/v1/approvals/${id}/reject`, "POST", {
    approver_user_id: approverUserId,
    reason,
  });
}

export function editApproval(
  opts: FetchOptions,
  approvalId: string,
  approverUserId: string,
  editedToolCall: AuthorizeToolCall,
  reason: string,
) {
  const id = encodeURIComponent(approvalId);
  return fetchFromGateway<Record<string, unknown>>(opts, `/v1/approvals/${id}/edit`, "POST", {
    approver_user_id: approverUserId,
    edited_tool_call: editedToolCall,
    reason,
  });
}

// Agents Fleet
export function getAgents(opts: FetchOptions) {
  return fetchFromGateway<AgentRecord[]>(opts, "/v1/agents");
}

export function freezeAgent(opts: FetchOptions, agentId: string, reason?: string) {
  const id = encodeURIComponent(agentId);
  const body = reason?.trim() ? { reason: reason.trim() } : undefined;
  return fetchFromGateway<AgentRecord>(opts, `/v1/agents/${id}/freeze`, "POST", body);
}

export function unfreezeAgent(opts: FetchOptions, agentId: string) {
  const id = encodeURIComponent(agentId);
  return fetchFromGateway<AgentRecord>(opts, `/v1/agents/${id}/unfreeze`, "POST");
}

export function getAgentScoreboard(opts: FetchOptions) {
  return fetchFromGateway<AgentRiskRecord[]>(opts, "/v1/agents/risk-scoreboard");
}

// MCP Servers
export function getMcpServers(opts: FetchOptions) {
  return fetchFromGateway<McpServerRecord[]>(opts, "/v1/mcp/servers");
}

export function normalizeMcpManifestHistory(
  response: McpManifestRecord[] | McpManifestHistoryEnvelope | null | undefined,
): McpManifestRecord[] {
  if (Array.isArray(response)) {
    return response;
  }
  if (response && Array.isArray(response.snapshots)) {
    return response.snapshots;
  }
  return [];
}

export async function getMcpManifestHistory(opts: FetchOptions, serverKey: string) {
  const encodedServerKey = encodeURIComponent(serverKey);
  const response = await fetchFromGateway<McpManifestRecord[] | McpManifestHistoryEnvelope>(
    opts,
    `/v1/mcp/servers/${encodedServerKey}/manifest-history`,
  );
  return normalizeMcpManifestHistory(response);
}

export function getMcpTools(opts: FetchOptions, serverKey: string) {
  const encodedServerKey = encodeURIComponent(serverKey);
  return fetchFromGateway<Array<Record<string, unknown>>>(opts, `/v1/mcp/servers/${encodedServerKey}/tools`);
}

export function quarantineMcpServer(opts: FetchOptions, serverKey: string) {
  const encodedServerKey = encodeURIComponent(serverKey);
  return fetchFromGateway<McpServerRecord>(opts, `/v1/mcp/servers/${encodedServerKey}/quarantine`, "POST");
}

export function restoreMcpServer(opts: FetchOptions, serverKey: string) {
  const encodedServerKey = encodeURIComponent(serverKey);
  return fetchFromGateway<McpServerRecord>(opts, `/v1/mcp/servers/${encodedServerKey}/restore`, "POST");
}

// Receipts
export function getReceipts(opts: FetchOptions, limit = 50) {
  return fetchFromGateway<ReceiptRecord[]>(opts, `/v1/receipts?limit=${limit}`);
}

export function verifyReceipt(opts: FetchOptions, receiptId: string) {
  return fetchFromGateway<Record<string, unknown>>(opts, `/v1/receipts/${receiptId}/verify`);
}

// Query / Explore (Discover)
export function getDecisions(opts: FetchOptions, limit = 50, q = "") {
  const path = q ? `/v1/decisions?limit=${limit}&q=${encodeURIComponent(q)}` : `/v1/decisions?limit=${limit}`;
  return fetchFromGateway<DecisionRecord[]>(opts, path);
}

export interface DecisionFilters {
  limit?: number;
  agentId?: string;
  decision?: string;
  sourceTrust?: string;
  skill?: string;
  from?: string;
  to?: string;
  q?: string;
}

// Compiled AQL -> the gateway's parameterized /v1/decisions filters.
export function searchDecisions(opts: FetchOptions, filters: DecisionFilters) {
  const params = new URLSearchParams();
  params.set("limit", String(filters.limit ?? 50));
  if (filters.agentId) params.set("agent_id", filters.agentId);
  if (filters.decision) params.set("decision", filters.decision);
  if (filters.sourceTrust) params.set("source_trust", filters.sourceTrust);
  if (filters.skill) params.set("skill", filters.skill);
  if (filters.from) params.set("from", filters.from);
  if (filters.to) params.set("to", filters.to);
  if (filters.q) params.set("q", filters.q);
  return fetchFromGateway<DecisionRecord[]>(opts, `/v1/decisions?${params.toString()}`);
}

// Evidence graph
export function getIncidentGraph(opts: FetchOptions, incidentId: string) {
  return fetchFromGateway<IncidentGraph>(opts, `/v1/graph/incident/${incidentId}`);
}

// SOC Rules & Backtesting
export interface UpsertRulePayload {
  rule_key: string;
  name: string;
  severity: string;
  condition: string; // YAML condition string
  summary_template: string;
  enabled: boolean;
}

export function getSocRules(opts: FetchOptions) {
  return fetchFromGateway<SocRuleRecord[]>(opts, "/v1/soc/rules");
}

export function getDetectionRules(opts: FetchOptions) {
  return fetchFromGateway<SocRuleRecord[]>(opts, "/v1/detection_rules");
}

export function createSocRule(opts: FetchOptions, payload: UpsertRulePayload) {
  return fetchFromGateway<SocRuleRecord>(opts, "/v1/soc/rules", "POST", payload);
}

export function deleteDetectionRule(opts: FetchOptions, ruleId: string) {
  return fetchFromGateway<Record<string, unknown>>(opts, `/v1/detection_rules/${ruleId}`, "DELETE");
}

export function backtestSocRule(opts: FetchOptions, ruleKey: string, from?: string, to?: string) {
  const body = from && to ? { from, to } : {};
  return fetchFromGateway<BacktestResult>(opts, `/v1/soc/rules/${ruleKey}/backtest`, "POST", body);
}
