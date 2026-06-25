export interface FetchOptions {
  gatewayUrl: string;
  bearerToken: string;
}

function getHeaders(token: string) {
  const headers: Record<string, string> = {
    "Accept": "application/json",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

export async function fetchFromGateway<T>(
  options: FetchOptions,
  path: string,
  method = "GET",
  body?: any
): Promise<T> {
  const url = `${options.gatewayUrl.replace(/\/+$/, "")}${path}`;
  const headers = getHeaders(options.bearerToken);
  
  const config: RequestInit = {
    method,
    headers: {
      ...headers,
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
  };

  if (body) {
    config.body = JSON.stringify(body);
  }

  const response = await fetch(url, config);

  if (response.status === 204) {
    return {} as T;
  }

  if (!response.ok) {
    let errorMsg = `HTTP ${response.status}: ${response.statusText}`;
    try {
      const errJson = await response.json();
      if (errJson && errJson.message) {
        errorMsg = errJson.message;
      }
    } catch (_) {}
    throw new Error(errorMsg);
  }

  return response.json() as Promise<T>;
}

// Stats & Summaries
export function getStats(opts: FetchOptions) {
  return fetchFromGateway<any>(opts, "/v1/stats");
}

export function getSocSummary(opts: FetchOptions) {
  return fetchFromGateway<any>(opts, "/v1/soc/summary");
}

// Alerts & Incidents
export function getAlerts(opts: FetchOptions, limit = 50) {
  return fetchFromGateway<any[]>(opts, `/v1/alerts?limit=${limit}`);
}

export function getIncidents(opts: FetchOptions, limit = 50) {
  return fetchFromGateway<any[]>(opts, `/v1/incidents?limit=${limit}`);
}

export function getIncidentDetail(opts: FetchOptions, id: string) {
  return fetchFromGateway<any>(opts, `/v1/incidents/${id}`);
}

// Approvals Queue
export function getApprovals(opts: FetchOptions) {
  return fetchFromGateway<any[]>(opts, "/v1/approvals");
}

export function approveApproval(
  opts: FetchOptions,
  approvalId: string,
  approverUserId: string,
  reason?: string
) {
  return fetchFromGateway<any>(opts, `/v1/approvals/${approvalId}/approve`, "POST", {
    approverUserId,
    reason: reason || "Approved from SOC console UI",
  });
}

export function rejectApproval(
  opts: FetchOptions,
  approvalId: string,
  approverUserId: string,
  reason?: string
) {
  return fetchFromGateway<any>(opts, `/v1/approvals/${approvalId}/reject`, "POST", {
    approverUserId,
    reason: reason || "Rejected from SOC console UI",
  });
}

// Agents Fleet
export function getAgents(opts: FetchOptions) {
  return fetchFromGateway<any[]>(opts, "/v1/agents");
}

export function freezeAgent(opts: FetchOptions, agentId: string) {
  return fetchFromGateway<any>(opts, `/v1/agents/${agentId}/freeze`, "POST");
}

export function unfreezeAgent(opts: FetchOptions, agentId: string) {
  return fetchFromGateway<any>(opts, `/v1/agents/${agentId}/unfreeze`, "POST");
}

export function getAgentScoreboard(opts: FetchOptions) {
  return fetchFromGateway<any[]>(opts, "/v1/agents/risk-scoreboard");
}

// MCP Servers
export function getMcpServers(opts: FetchOptions) {
  return fetchFromGateway<any[]>(opts, "/v1/mcp/servers");
}

export function getMcpManifestHistory(opts: FetchOptions, serverKey: string) {
  return fetchFromGateway<any[]>(opts, `/v1/mcp/servers/${serverKey}/manifest-history`);
}

export function getMcpTools(opts: FetchOptions, serverKey: string) {
  return fetchFromGateway<any[]>(opts, `/v1/mcp/servers/${serverKey}/tools`);
}

export function quarantineMcpServer(opts: FetchOptions, serverKey: string) {
  return fetchFromGateway<any>(opts, `/v1/mcp/servers/${serverKey}/quarantine`, "POST");
}

export function restoreMcpServer(opts: FetchOptions, serverKey: string) {
  return fetchFromGateway<any>(opts, `/v1/mcp/servers/${serverKey}/restore`, "POST");
}

// Receipts
export function getReceipts(opts: FetchOptions, limit = 50) {
  return fetchFromGateway<any[]>(opts, `/v1/receipts?limit=${limit}`);
}

export function verifyReceipt(opts: FetchOptions, receiptId: string) {
  return fetchFromGateway<any>(opts, `/v1/receipts/${receiptId}/verify`);
}

// Query / Explore (Discover)
export function getDecisions(opts: FetchOptions, limit = 50, q = "") {
  const path = q ? `/v1/decisions?limit=${limit}&q=${encodeURIComponent(q)}` : `/v1/decisions?limit=${limit}`;
  return fetchFromGateway<any[]>(opts, path);
}

export interface DecisionFilters {
  limit?: number;
  agentId?: string;
  decision?: string;
  sourceTrust?: string;
  q?: string;
}

// Compiled AQL -> the gateway's parameterized /v1/decisions filters.
export function searchDecisions(opts: FetchOptions, filters: DecisionFilters) {
  const params = new URLSearchParams();
  params.set("limit", String(filters.limit ?? 50));
  if (filters.agentId) params.set("agent_id", filters.agentId);
  if (filters.decision) params.set("decision", filters.decision);
  if (filters.sourceTrust) params.set("source_trust", filters.sourceTrust);
  if (filters.q) params.set("q", filters.q);
  return fetchFromGateway<any[]>(opts, `/v1/decisions?${params.toString()}`);
}

// Evidence graph
export function getIncidentGraph(opts: FetchOptions, incidentId: string) {
  return fetchFromGateway<any>(opts, `/v1/graph/incident/${incidentId}`);
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
  return fetchFromGateway<any[]>(opts, "/v1/soc/rules");
}

export function getDetectionRules(opts: FetchOptions) {
  return fetchFromGateway<any[]>(opts, "/v1/detection_rules");
}

export function createSocRule(opts: FetchOptions, payload: UpsertRulePayload) {
  return fetchFromGateway<any>(opts, "/v1/soc/rules", "POST", payload);
}

export function deleteDetectionRule(opts: FetchOptions, ruleId: string) {
  return fetchFromGateway<any>(opts, `/v1/detection_rules/${ruleId}`, "DELETE");
}

export function backtestSocRule(opts: FetchOptions, ruleKey: string, from?: string, to?: string) {
  const body = from && to ? { from, to } : {};
  return fetchFromGateway<any>(opts, `/v1/soc/rules/${ruleKey}/backtest`, "POST", body);
}

