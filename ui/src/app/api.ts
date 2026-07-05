export interface FetchOptions {
  gatewayUrl: string;
  bearerToken: string;
  tenantId: string;
  signal?: AbortSignal;
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

export interface TenantRecord {
  id: string;
  name: string;
  plan: string;
  created_at: string;
  auto_respond_enabled?: boolean;
  auto_rotate_token_on_leak_enabled?: boolean;
}

export interface RiskWeights {
  environment_weight_mutating: number;
  context_trust_penalty_trusted_internal_signed: number;
  context_trust_penalty_trusted_internal_unsigned: number;
  context_trust_penalty_semi_trusted_customer: number;
  context_trust_penalty_untrusted_external: number;
  context_trust_penalty_malicious_suspected: number;
  context_trust_penalty_unknown: number;
  mcp_trust_penalty: number;
  anomaly_weight_pct: number;
  approval_credit: number;
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
  decision_id?: string;
  tool_name?: string;
  tool_call?: AuthorizeToolCall;
  edited_tool_call?: AuthorizeToolCall;
  agent_id?: string;
  run_id?: string | null;
  trace_id?: string | null;
  parent_run_id?: string | null;
  source_trust?: string;
  root_trust_level?: string;
  action_hash?: string;
  original_action_hash?: string;
  edited_action_hash?: string;
  effective_action_hash?: string;
  is_edited?: boolean;
  expires_in?: string;
  expires_at?: string;
  status?: string;
  approver_group?: string;
  approver_user_id?: string;
  reason?: string | null;
  decision_reason?: string | null;
  matched_policies?: string[];
  risk_score?: number | null;
  risk_level?: string | null;
  composite_risk_score?: number | null;
}

export interface AgentRiskRecord {
  agent_id?: string;
  agent_key?: string;
  current_avg_risk_score?: number;
  avg_risk_score?: number;
  decision_count_24h?: number;
  trend?: string;
}

export interface AgentRecord {
  id: string;
  tenant_id?: string;
  agent_key: string;
  name: string;
  owner_team?: string | null;
  owner_email?: string | null;
  environment: string;
  framework?: string | null;
  model_provider?: string | null;
  model_name?: string | null;
  purpose?: string | null;
  risk_tier: string;
  status: string;
  last_seen_at?: string | null;
  frozen_reason?: string | null;
  quarantined_at?: string | null;
  force_approval?: boolean;
  allowed_environments?: string | null;
  mtls_cn?: string | null;
  created_at?: string;
  updated_at?: string;
}

export interface AgentToolPermission {
  id: string;
  tenant_id: string;
  agent_id: string;
  tool_key: string;
  created_at: string;
}

export interface McpServerRecord {
  id?: string;
  tenant_id?: string;
  server_key: string;
  name?: string;
  owner_team?: string | null;
  transport?: string;
  source?: string | null;
  trust_level?: string;
  endpoint?: string;
  version?: string | null;
  status?: string;
  /** Pinned mcp-manifest-1 hash from gateway discovery. */
  manifest_hash?: string;
  last_discovery_at?: string | null;
  inspection_enabled?: boolean;
  created_at?: string;
}

export interface McpManifestSnapshot {
  id?: string;
  tenant_id?: string;
  server_key?: string;
  manifest_hash?: string;
  manifest_json?: string;
  created_at?: string;
}

/** @deprecated Use McpManifestSnapshot — kept for datasource frame compatibility. */
export type McpManifestRecord = McpManifestSnapshot & {
  event_type?: string;
  description?: string;
  details?: string;
  ts?: string;
};

export interface McpToolRecord {
  id?: string;
  tool_key: string;
  name?: string;
  description?: string | null;
  risk?: string;
  mutates_state?: boolean;
  approval_required?: boolean;
  status?: string;
  created_at?: string;
  updated_at?: string;
}

interface McpManifestHistoryEnvelope {
  server_key?: string;
  snapshots?: McpManifestSnapshot[];
}

interface McpToolsEnvelope {
  server_key?: string;
  tools?: McpToolRecord[];
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

async function readGatewayJson<T>(response: Response): Promise<T> {
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

async function gatewayRequest(
  options: FetchOptions,
  path: string,
  method = "GET",
  body?: unknown,
): Promise<Response> {
  const url = `${options.gatewayUrl.replace(/\/+$/, "")}${path}`;
  const hasBody = body !== undefined;

  const config: RequestInit = {
    method,
    headers: buildGatewayHeaders(options, hasBody),
    signal: options.signal,
  };

  if (hasBody) {
    config.body = JSON.stringify(body);
  }

  return fetch(url, config);
}

export async function fetchFromGateway<T>(
  options: FetchOptions,
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const response = await gatewayRequest(options, path, method, body);
  return readGatewayJson<T>(response);
}

export interface GatewayListResult<T> {
  data: T;
  nextCursor?: string;
}

/** Like fetchFromGateway, but surfaces cursor-pagination via X-Next-Cursor. */
export async function fetchListFromGateway<T>(
  options: FetchOptions,
  path: string,
  method = "GET",
  body?: unknown,
): Promise<GatewayListResult<T>> {
  const response = await gatewayRequest(options, path, method, body);
  const nextCursor = response.headers.get("x-next-cursor")?.trim() || undefined;
  return {
    data: await readGatewayJson<T>(response),
    nextCursor,
  };
}

export async function downloadFromGateway(
  options: FetchOptions,
  path: string,
): Promise<Blob> {
  const url = `${options.gatewayUrl.replace(/\/+$/, "")}${path}`;
  const response = await fetch(url, { headers: buildGatewayHeaders(options), signal: options.signal });
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

export function getAgent(opts: FetchOptions, agentId: string) {
  const id = encodeURIComponent(agentId);
  return fetchFromGateway<AgentRecord>(opts, `/v1/agents/${id}`);
}

export function listAgentPermissions(opts: FetchOptions, agentId: string) {
  const id = encodeURIComponent(agentId);
  return fetchFromGateway<{ permissions: AgentToolPermission[] }>(
    opts,
    `/v1/agents/${id}/permissions`,
  ).then((response) => response.permissions ?? []);
}

export function freezeAgent(opts: FetchOptions, agentId: string, reason?: string) {
  const id = encodeURIComponent(agentId);
  const body = reason?.trim() ? { reason: reason.trim() } : undefined;
  return fetchFromGateway<AgentRecord>(opts, `/v1/agents/${id}/freeze`, "POST", body);
}

export function unfreezeAgent(opts: FetchOptions, agentId: string, reason?: string) {
  const id = encodeURIComponent(agentId);
  const body = reason?.trim() ? { reason: reason.trim() } : undefined;
  return fetchFromGateway<AgentRecord>(opts, `/v1/agents/${id}/unfreeze`, "POST", body);
}

export function revokeAgent(opts: FetchOptions, agentId: string, reason?: string) {
  const id = encodeURIComponent(agentId);
  const body = reason?.trim() ? { reason: reason.trim() } : undefined;
  return fetchFromGateway<AgentRecord>(opts, `/v1/agents/${id}/revoke`, "POST", body);
}

export function restoreAgent(opts: FetchOptions, agentId: string, reason?: string) {
  const id = encodeURIComponent(agentId);
  const body = reason?.trim() ? { reason: reason.trim() } : undefined;
  return fetchFromGateway<AgentRecord>(opts, `/v1/agents/${id}/restore`, "POST", body);
}

export function getAgentScoreboard(opts: FetchOptions) {
  return fetchFromGateway<AgentRiskRecord[]>(opts, "/v1/agents/risk-scoreboard");
}

// MCP Servers
export function getMcpServers(opts: FetchOptions) {
  return fetchFromGateway<McpServerRecord[]>(opts, "/v1/mcp/servers");
}

export function normalizeMcpManifestHistory(
  response: McpManifestSnapshot[] | McpManifestHistoryEnvelope | null | undefined,
): McpManifestSnapshot[] {
  if (Array.isArray(response)) {
    return response;
  }
  if (response && Array.isArray(response.snapshots)) {
    return response.snapshots;
  }
  return [];
}

export function normalizeMcpTools(
  response: McpToolRecord[] | McpToolsEnvelope | null | undefined,
): McpToolRecord[] {
  if (Array.isArray(response)) {
    return response;
  }
  if (response && Array.isArray(response.tools)) {
    return response.tools;
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

export async function getMcpTools(opts: FetchOptions, serverKey: string) {
  const encodedServerKey = encodeURIComponent(serverKey);
  const response = await fetchFromGateway<McpToolRecord[] | McpToolsEnvelope>(
    opts,
    `/v1/mcp/servers/${encodedServerKey}/tools`,
  );
  return normalizeMcpTools(response);
}

export function quarantineMcpServer(opts: FetchOptions, serverKey: string, reason?: string) {
  const encodedServerKey = encodeURIComponent(serverKey);
  const body = reason?.trim() ? { reason: reason.trim() } : undefined;
  return fetchFromGateway<McpServerRecord>(
    opts,
    `/v1/mcp/servers/${encodedServerKey}/quarantine`,
    "POST",
    body,
  );
}

export function restoreMcpServer(opts: FetchOptions, serverKey: string, reason?: string) {
  const encodedServerKey = encodeURIComponent(serverKey);
  const body = reason?.trim() ? { reason: reason.trim() } : undefined;
  return fetchFromGateway<McpServerRecord>(
    opts,
    `/v1/mcp/servers/${encodedServerKey}/restore`,
    "POST",
    body,
  );
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

// Webhook contact points (tenant-scoped SOC notification routing)
export interface WebhookSubscriptionRecord {
  id: string;
  tenant_id: string;
  url: string;
  secret_hash?: string | null;
  event_types: string;
  status: string;
  min_severity: string;
  format: string;
  delivery_status: string;
  consecutive_failures: number;
  last_delivery_at?: string | null;
  last_success_at?: string | null;
  created_at: string;
  /** Returned once at creation only — never persisted in listings. */
  delivery_secret?: string;
}

export interface CreateWebhookSubscriptionPayload {
  url: string;
  secret?: string;
  event_types?: string;
  min_severity?: "info" | "high";
  format?: "json" | "cef";
}

export function listWebhookSubscriptions(opts: FetchOptions, limit = 50) {
  return fetchListFromGateway<WebhookSubscriptionRecord[]>(
    opts,
    `/v1/webhook_subscriptions?limit=${limit}`,
  );
}

export function createWebhookSubscription(opts: FetchOptions, payload: CreateWebhookSubscriptionPayload) {
  return fetchFromGateway<WebhookSubscriptionRecord>(opts, "/v1/webhook_subscriptions", "POST", {
    event_types: payload.event_types ?? "alert,incident",
    min_severity: payload.min_severity ?? "info",
    format: payload.format ?? "json",
    ...payload,
  });
}

export function deleteWebhookSubscription(opts: FetchOptions, id: string) {
  return fetchFromGateway<Record<string, unknown>>(opts, `/v1/webhook_subscriptions/${id}`, "DELETE");
}

export function reactivateWebhookSubscription(opts: FetchOptions, id: string) {
  return fetchFromGateway<WebhookSubscriptionRecord>(
    opts,
    `/v1/webhook_subscriptions/${id}/reactivate`,
    "POST",
  );
}

// Deterministic active-response playbooks (read-only in alerting UI)
export interface PlaybookRecord {
  id: string;
  tenant_id: string;
  name: string;
  trigger_kind: string;
  trigger_severity: string;
  trigger_agent_id?: string | null;
  trigger_environment?: string | null;
  steps_json: string;
  enabled: boolean;
  created_at: string;
}

export function listPlaybooks(opts: FetchOptions, limit = 50) {
  return fetchListFromGateway<PlaybookRecord[]>(opts, `/v1/playbooks?limit=${limit}`);
}

// #1627: alerting settings APIs
export interface AlertSilenceRecord {
  id: string;
  tenant_id: string;
  rule_key?: string | null;
  agent_id?: string | null;
  comment?: string | null;
  starts_at: string;
  ends_at: string;
  created_by?: string | null;
  status: string;
  created_at: string;
}

export interface CreateSilencePayload {
  rule_key?: string;
  agent_id?: string;
  comment?: string;
  starts_at?: string;
  ends_at: string;
  created_by?: string;
}

export function listSilences(opts: FetchOptions, limit = 50) {
  return fetchListFromGateway<AlertSilenceRecord[]>(opts, `/v1/soc/silences?limit=${limit}`);
}

export function createSilence(opts: FetchOptions, payload: CreateSilencePayload) {
  return fetchFromGateway<{ silence: AlertSilenceRecord }>(opts, "/v1/soc/silences", "POST", payload);
}

export function deleteSilence(opts: FetchOptions, id: string) {
  return fetchFromGateway<Record<string, unknown>>(opts, `/v1/soc/silences/${id}`, "DELETE");
}

export interface ContactPointRecord {
  id: string;
  tenant_id: string;
  name: string;
  channel_type: string;
  url?: string | null;
  webhook_subscription_id?: string | null;
  settings_json: string;
  health_status: string;
  created_at: string;
  updated_at: string;
}

export function listContactPoints(opts: FetchOptions, limit = 50) {
  return fetchListFromGateway<ContactPointRecord[]>(opts, `/v1/soc/contact-points?limit=${limit}`);
}

// #1634: tenant-owned dashboard schemas
export interface SocDashboardRecord {
  id: string;
  tenant_id: string;
  uid: string;
  title: string;
  schema_version: number;
  schema_json: string;
  created_at: string;
  updated_at: string;
}

export function listSocDashboards(opts: FetchOptions) {
  return fetchFromGateway<SocDashboardRecord[]>(opts, "/v1/soc/dashboards");
}

export function getSocDashboard(opts: FetchOptions, uid: string) {
  return fetchFromGateway<SocDashboardRecord>(opts, `/v1/soc/dashboards/${encodeURIComponent(uid)}`);
}

export function createSocDashboard(opts: FetchOptions, schema: unknown) {
  return fetchFromGateway<SocDashboardRecord>(opts, "/v1/soc/dashboards", "POST", schema);
}

export function updateSocDashboard(opts: FetchOptions, uid: string, schema: unknown) {
  return fetchFromGateway<SocDashboardRecord>(
    opts,
    `/v1/soc/dashboards/${encodeURIComponent(uid)}`,
    "PUT",
    schema,
  );
}

export function deleteSocDashboard(opts: FetchOptions, uid: string) {
  return fetchFromGateway<Record<string, unknown>>(
    opts,
    `/v1/soc/dashboards/${encodeURIComponent(uid)}`,
    "DELETE",
  );
}

export interface NotificationPolicyRecord {
  id: string;
  tenant_id: string;
  name: string;
  enabled: boolean;
  matchers_json: string;
  contact_point_ids_json: string;
  group_by?: string | null;
  repeat_interval_secs?: number | null;
  created_at: string;
  updated_at: string;
}

export function listNotificationPolicies(opts: FetchOptions, limit = 50) {
  return fetchListFromGateway<NotificationPolicyRecord[]>(
    opts,
    `/v1/soc/notification-policies?limit=${limit}`,
  );
}

export function getTenant(opts: FetchOptions, tenantId: string) {
  return fetchFromGateway<TenantRecord>(opts, `/v1/tenants/${encodeURIComponent(tenantId)}`);
}

export function getTenantRiskWeights(opts: FetchOptions) {
  return fetchFromGateway<RiskWeights>(opts, "/v1/tenants/risk-weights");
}

export interface GatewayHealthStatus {
  live: boolean;
  ready: boolean;
}

export async function probeGatewayHealth(gatewayUrl: string, signal?: AbortSignal): Promise<GatewayHealthStatus> {
  const base = gatewayUrl.replace(/\/+$/, "");
  const probe = async (path: string) => {
    try {
      const response = await fetch(`${base}${path}`, { signal });
      return response.ok;
    } catch {
      return false;
    }
  };
  const [live, ready] = await Promise.all([probe("/livez"), probe("/readyz")]);
  return { live, ready };
}

export async function probeGatewayEndpoint(opts: FetchOptions, path: string): Promise<boolean> {
  try {
    await fetchFromGateway<unknown>(opts, path);
    return true;
  } catch (error) {
    if (error instanceof GatewayRequestError && [404, 405, 501].includes(error.status)) {
      return false;
    }
    return true;
  }
}
