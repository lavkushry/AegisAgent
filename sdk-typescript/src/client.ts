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
}
