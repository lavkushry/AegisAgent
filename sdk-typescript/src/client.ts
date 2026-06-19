import { createHmac } from "node:crypto";

/**
 * AegisAgent TypeScript SDK — HTTP client.
 *
 * Wraps the three gateway endpoints used by the fail-closed protect() wrapper:
 *   POST /v1/authorize
 *   GET  /v1/approvals/:id
 *   POST /v1/approvals/:id/consume
 *
 * Design invariants (mirroring Go sdk-go/aegis/client.go):
 *   - Every request carries Authorization: Bearer <agentToken> and
 *     X-Aegis-Tenant-ID: <tenantId>.
 *   - Non-2xx responses throw AegisGatewayError (statusCode + body excerpt).
 *   - Network errors propagate as-is (caller treats them fail-closed).
 *   - No secrets (tokens, payloads) are logged.
 *   - JSON fields from the gateway use snake_case; we expose them as camelCase
 *     typed properties for idiomatic TypeScript use.
 */

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/** Gateway returned a non-2xx HTTP status. */
export class AegisGatewayError extends Error {
  readonly statusCode: number;
  readonly body: string;

  constructor(statusCode: number, body: string) {
    super(`aegis: gateway error ${statusCode}`);
    this.name = "AegisGatewayError";
    this.statusCode = statusCode;
    this.body = body;
  }
}

// ---------------------------------------------------------------------------
// Request / response shapes
// ---------------------------------------------------------------------------

/** Payload for POST /v1/authorize. */
export interface AuthorizeRequest {
  tool: string;
  action: string;
  resource?: string;
  mutatesState: boolean;
  parameters: Record<string, unknown>;
  sourceTrust?: string;
}

/** Approval info embedded in an AuthorizeResponse when decision is "require_approval". */
export interface ApprovalInfo {
  approvalId: string;
  actionHash: string;
  approverGroup?: string;
  expiresAt?: string;
}

/** Decoded body of POST /v1/authorize 200. */
export interface AuthorizeResponse {
  decision: string;
  actionHash: string;
  reason?: string;
  approval?: ApprovalInfo;
}

/** Decoded body of GET /v1/approvals/:id 200. */
export interface ApprovalStatus {
  status: string;
  actionHash: string;
  reason?: string;
  expiresAt?: string;
}

/** Decoded body of POST /v1/approvals/:id/consume 200. */
export interface ConsumeResponse {
  actionHash: string;
}

/** Decoded body of POST /v1/approvals/:id/approve|reject 200. */
export interface ApprovalDecisionResponse {
  status: string;
  approvalId: string;
}

/** A single SOC detection alert (GET /v1/alerts). */
export interface SocAlert {
  id: string;
  tenantId: string;
  rule: string;
  severity: string;
  agentId: string;
  sourceEventId: string;
  summary: string;
  createdAt: string;
}

/** A single SOC correlation incident (GET /v1/incidents). */
export interface SocIncident {
  id: string;
  tenantId: string;
  kind: string;
  severity: string;
  agentId: string;
  summary: string;
  sourceEventIds: string;
  openedAt: string;
  status: string;
  closedAt?: string;
}

/** Tenant-scoped aggregate SOC counts (GET /v1/soc/summary). */
export interface SocSummary {
  alertsTotal: number;
  alertsHigh: number;
  incidentsTotal: number;
  incidentsOpen: number;
  incidentsClosed: number;
}

/** Optional filters for listAlerts()/listIncidents(). */
export interface ListAlertsOptions {
  limit?: number;
  offset?: number;
  severity?: string;
  agentId?: string;
}

export interface ListIncidentsOptions extends ListAlertsOptions {
  status?: string;
}

// ---------------------------------------------------------------------------
// Client options
// ---------------------------------------------------------------------------

export interface ClientOptions {
  /** Gateway base URL, e.g. "http://127.0.0.1:8080". Trailing slash stripped. */
  baseUrl: string;
  /** Bearer token obtained after agent registration. */
  agentToken: string;
  /** Forwarded as X-Aegis-Tenant-ID on every request. */
  tenantId: string;
  /** Request timeout in milliseconds. Default: 5000. */
  timeoutMs?: number;
  /**
   * When set, every POST /v1/authorize call includes an
   * X-Aegis-Request-Signature: sha256=<hmac-hex> header.
   */
  signingKey?: string;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

const DEFAULT_TIMEOUT_MS = 5_000;

export class AegisClient {
  private readonly baseUrl: string;
  private readonly agentToken: string;
  private readonly tenantId: string;
  private readonly timeoutMs: number;
  private readonly signingKey?: string;

  constructor(opts: ClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.agentToken = opts.agentToken;
    this.tenantId = opts.tenantId;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.signingKey = opts.signingKey;
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  private headers(): Record<string, string> {
    return {
      "Authorization": `Bearer ${this.agentToken}`,
      "X-Aegis-Tenant-ID": this.tenantId,
      "Content-Type": "application/json",
    };
  }

  /** Fetch with a per-request AbortSignal-based timeout. */
  private async fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await fetch(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }

  /** Read up to 2 KiB of the response body for error messages. */
  private async readBodyExcerpt(resp: Response): Promise<string> {
    try {
      const text = await resp.text();
      return text.slice(0, 2048);
    } catch {
      return "(unreadable)";
    }
  }

  // -------------------------------------------------------------------------
  // authorize()
  // -------------------------------------------------------------------------

  /**
   * POST /v1/authorize
   *
   * Throws AegisGatewayError on non-2xx; propagates network errors as-is.
   */
  async authorize(req: AuthorizeRequest): Promise<AuthorizeResponse> {
    const body = JSON.stringify({
      tool: req.tool,
      action: req.action,
      resource: req.resource ?? null,
      mutates_state: req.mutatesState,
      parameters: req.parameters,
      ...(req.sourceTrust !== undefined ? { source_trust: req.sourceTrust } : {}),
    });

    const reqHeaders: Record<string, string> = this.headers();
    if (this.signingKey) {
      const mac = createHmac("sha256", this.signingKey);
      mac.update(body);
      reqHeaders["X-Aegis-Request-Signature"] = `sha256=${mac.digest("hex")}`;
    }

    const resp = await this.fetchWithTimeout(`${this.baseUrl}/v1/authorize`, {
      method: "POST",
      headers: reqHeaders,
      body,
    });

    if (!resp.ok) {
      throw new AegisGatewayError(resp.status, await this.readBodyExcerpt(resp));
    }

    const data = (await resp.json()) as {
      decision: string;
      action_hash?: string;
      reason?: string;
      approval?: {
        approval_id: string;
        action_hash: string;
        approver_group?: string;
        expires_at?: string;
      };
    };

    return {
      decision: data.decision,
      actionHash: data.action_hash ?? "",
      reason: data.reason,
      approval: data.approval
        ? {
            approvalId: data.approval.approval_id,
            actionHash: data.approval.action_hash,
            approverGroup: data.approval.approver_group,
            expiresAt: data.approval.expires_at,
          }
        : undefined,
    };
  }

  // -------------------------------------------------------------------------
  // getApproval()
  // -------------------------------------------------------------------------

  /**
   * GET /v1/approvals/:id
   *
   * Throws AegisGatewayError on non-2xx; propagates network errors as-is.
   */
  async getApproval(approvalId: string): Promise<ApprovalStatus> {
    const resp = await this.fetchWithTimeout(
      `${this.baseUrl}/v1/approvals/${approvalId}`,
      { method: "GET", headers: this.headers() }
    );

    if (!resp.ok) {
      throw new AegisGatewayError(resp.status, await this.readBodyExcerpt(resp));
    }

    const data = (await resp.json()) as {
      status: string;
      action_hash?: string;
      reason?: string;
      expires_at?: string;
    };

    return {
      status: data.status,
      actionHash: data.action_hash ?? "",
      reason: data.reason,
      expiresAt: data.expires_at,
    };
  }

  // -------------------------------------------------------------------------
  // consumeApproval()
  // -------------------------------------------------------------------------

  /**
   * POST /v1/approvals/:id/consume
   *
   * Atomically consumes an APPROVED approval so it cannot be reused (replay
   * defence). Throws AegisGatewayError on non-2xx (including 409 Already
   * Consumed); propagates network errors as-is.
   */
  async consumeApproval(approvalId: string): Promise<ConsumeResponse> {
    const resp = await this.fetchWithTimeout(
      `${this.baseUrl}/v1/approvals/${approvalId}/consume`,
      { method: "POST", headers: this.headers(), body: "" }
    );

    if (!resp.ok) {
      throw new AegisGatewayError(resp.status, await this.readBodyExcerpt(resp));
    }

    const data = (await resp.json()) as { action_hash?: string };
    return { actionHash: data.action_hash ?? "" };
  }

  // -------------------------------------------------------------------------
  // approve() / reject()
  // -------------------------------------------------------------------------

  /**
   * POST /v1/approvals/:id/approve
   *
   * Throws AegisGatewayError on non-2xx (e.g. 409 if already decided);
   * propagates network errors as-is.
   */
  async approve(
    approvalId: string,
    approverUserId: string,
    reason?: string
  ): Promise<ApprovalDecisionResponse> {
    return this.decideApproval("approve", approvalId, approverUserId, reason);
  }

  /**
   * POST /v1/approvals/:id/reject
   *
   * Throws AegisGatewayError on non-2xx (e.g. 409 if already decided);
   * propagates network errors as-is.
   */
  async reject(
    approvalId: string,
    approverUserId: string,
    reason?: string
  ): Promise<ApprovalDecisionResponse> {
    return this.decideApproval("reject", approvalId, approverUserId, reason);
  }

  private async decideApproval(
    decision: "approve" | "reject",
    approvalId: string,
    approverUserId: string,
    reason?: string
  ): Promise<ApprovalDecisionResponse> {
    const body = JSON.stringify({
      approver_user_id: approverUserId,
      reason: reason ?? null,
    });

    const resp = await this.fetchWithTimeout(
      `${this.baseUrl}/v1/approvals/${approvalId}/${decision}`,
      { method: "POST", headers: this.headers(), body }
    );

    if (!resp.ok) {
      throw new AegisGatewayError(resp.status, await this.readBodyExcerpt(resp));
    }

    const data = (await resp.json()) as { status: string; approval_id: string };
    return { status: data.status, approvalId: data.approval_id };
  }

  // -------------------------------------------------------------------------
  // listAlerts() / listIncidents() / getSocSummary()
  // -------------------------------------------------------------------------

  /** GET /v1/alerts — tenant-scoped SOC detection alerts. */
  async listAlerts(opts: ListAlertsOptions = {}): Promise<SocAlert[]> {
    const query = new URLSearchParams();
    if (opts.limit !== undefined) query.set("limit", String(opts.limit));
    if (opts.offset !== undefined) query.set("offset", String(opts.offset));
    if (opts.severity !== undefined) query.set("severity", opts.severity);
    if (opts.agentId !== undefined) query.set("agent_id", opts.agentId);

    const qs = query.toString();
    const resp = await this.fetchWithTimeout(
      `${this.baseUrl}/v1/alerts${qs ? `?${qs}` : ""}`,
      { method: "GET", headers: this.headers() }
    );

    if (!resp.ok) {
      throw new AegisGatewayError(resp.status, await this.readBodyExcerpt(resp));
    }

    const data = (await resp.json()) as Array<{
      id: string;
      tenant_id: string;
      rule: string;
      severity: string;
      agent_id: string;
      source_event_id: string;
      summary: string;
      created_at: string;
    }>;

    return data.map((a) => ({
      id: a.id,
      tenantId: a.tenant_id,
      rule: a.rule,
      severity: a.severity,
      agentId: a.agent_id,
      sourceEventId: a.source_event_id,
      summary: a.summary,
      createdAt: a.created_at,
    }));
  }

  /** GET /v1/incidents — tenant-scoped SOC correlation incidents. */
  async listIncidents(opts: ListIncidentsOptions = {}): Promise<SocIncident[]> {
    const query = new URLSearchParams();
    if (opts.limit !== undefined) query.set("limit", String(opts.limit));
    if (opts.offset !== undefined) query.set("offset", String(opts.offset));
    if (opts.status !== undefined) query.set("status", opts.status);
    if (opts.severity !== undefined) query.set("severity", opts.severity);
    if (opts.agentId !== undefined) query.set("agent_id", opts.agentId);

    const qs = query.toString();
    const resp = await this.fetchWithTimeout(
      `${this.baseUrl}/v1/incidents${qs ? `?${qs}` : ""}`,
      { method: "GET", headers: this.headers() }
    );

    if (!resp.ok) {
      throw new AegisGatewayError(resp.status, await this.readBodyExcerpt(resp));
    }

    const data = (await resp.json()) as Array<{
      id: string;
      tenant_id: string;
      kind: string;
      severity: string;
      agent_id: string;
      summary: string;
      source_event_ids: string;
      opened_at: string;
      status: string;
      closed_at?: string | null;
    }>;

    return data.map((i) => ({
      id: i.id,
      tenantId: i.tenant_id,
      kind: i.kind,
      severity: i.severity,
      agentId: i.agent_id,
      summary: i.summary,
      sourceEventIds: i.source_event_ids,
      openedAt: i.opened_at,
      status: i.status,
      closedAt: i.closed_at ?? undefined,
    }));
  }

  /** GET /v1/soc/summary — tenant-scoped aggregate SOC counts. */
  async getSocSummary(): Promise<SocSummary> {
    const resp = await this.fetchWithTimeout(`${this.baseUrl}/v1/soc/summary`, {
      method: "GET",
      headers: this.headers(),
    });

    if (!resp.ok) {
      throw new AegisGatewayError(resp.status, await this.readBodyExcerpt(resp));
    }

    const data = (await resp.json()) as {
      alerts_total: number;
      alerts_high: number;
      incidents_total: number;
      incidents_open: number;
      incidents_closed: number;
    };

    return {
      alertsTotal: data.alerts_total,
      alertsHigh: data.alerts_high,
      incidentsTotal: data.incidents_total,
      incidentsOpen: data.incidents_open,
      incidentsClosed: data.incidents_closed,
    };
  }
}
