import { fetchFromGateway, type FetchOptions } from "@/app/api";
import { resolveTimeToken } from "@/lib/format";
import { rowsToFrame } from "./frame";
import type {
  DataFrame,
  Datasource,
  DatasourceCapabilities,
  EntityKind,
  FieldDescriptor,
  QueryRequest,
  VerifyResult,
} from "./types";

const ENTITY_PATHS: Record<EntityKind, string> = {
  incident: "/v1/incidents",
  alert: "/v1/alerts",
  approval: "/v1/approvals",
  agent: "/v1/agents",
  mcp_server: "/v1/mcp/servers",
  receipt: "/v1/receipts",
  decision: "/v1/decisions",
  rule: "/v1/detection_rules",
};

// Minimal field catalogs for the Explore sidebar / autocomplete. Extended
// as the event-query datasource (POST /v1/soc/query) lands.
const ENTITY_FIELDS: Partial<Record<EntityKind, ReadonlyArray<FieldDescriptor>>> = {
  decision: [
    { name: "decision", type: "decision", facetable: true, examples: ["allow", "deny", "require_approval"] },
    { name: "source_trust", type: "trust", facetable: true, examples: ["untrusted_external", "trusted_internal_signed"] },
    { name: "tool", type: "string", facetable: true },
    { name: "agent_id", type: "string", facetable: true },
    { name: "action_hash", type: "hash", facetable: false },
    { name: "created_at", type: "time", facetable: false },
  ],
};

/**
 * Reads tenant-scoped entities from the gateway REST API and returns them
 * as DataFrames. Wraps the existing fetchFromGateway transport; it does not
 * support AQL aggregation (that is the event-query datasource).
 */
export class GatewayEntityDatasource implements Datasource {
  readonly id = "gateway-entity";
  readonly capabilities: DatasourceCapabilities = {
    query: false,
    stream: false,
    fields: true,
    verify: true,
  };

  constructor(private readonly opts: FetchOptions) {}

  async query(req: QueryRequest): Promise<DataFrame> {
    if (req.aggregate === "count_over_time") {
      return this.countOverTime(req);
    }
    const entity = req.entity ?? "decision";
    const limit = req.limit ?? 50;
    const params = new URLSearchParams({ limit: String(limit) });
    if (req.search) params.set("q", req.search);
    const path = `${ENTITY_PATHS[entity]}?${params.toString()}`;
    const rows = await fetchFromGateway<Array<Record<string, unknown>>>(this.opts, path);
    return rowsToFrame(Array.isArray(rows) ? rows : []);
  }

  /** Decision count bucketed over time -> a [time, number] DataFrame. */
  private async countOverTime(req: QueryRequest): Promise<DataFrame> {
    const params = new URLSearchParams({ interval: req.interval ?? "hour" });
    const from = resolveTimeToken(req.timeRange.from);
    const to = resolveTimeToken(req.timeRange.to);
    if (from) params.set("from", from);
    if (to) params.set("to", to);
    const points = await fetchFromGateway<Array<{ bucket: string; count: number }>>(
      this.opts,
      `/v1/decisions/timeseries?${params.toString()}`,
    );
    const rows = Array.isArray(points) ? points : [];
    return {
      fields: [
        { name: "bucket", type: "time", values: rows.map((p) => p.bucket) },
        { name: "count", type: "number", values: rows.map((p) => p.count) },
      ],
      length: rows.length,
      meta: { total: rows.length },
    };
  }

  async fields(entity: EntityKind): Promise<ReadonlyArray<FieldDescriptor>> {
    return ENTITY_FIELDS[entity] ?? [];
  }

  async verifyReceipt(receiptId: string): Promise<VerifyResult> {
    const data = await fetchFromGateway<Record<string, unknown>>(
      this.opts,
      `/v1/receipts/${receiptId}/verify`,
    );
    return normalizeVerify(data);
  }
}

/**
 * Normalize the gateway's loose verify response into a VerifyResult. The
 * gateway has shipped several shapes ({verified}, {status}, {error}); this
 * centralizes the interpretation that ExploreTab previously inlined.
 */
export function normalizeVerify(data: Record<string, unknown>): VerifyResult {
  const err = data.error;
  const ok =
    data.verified === true ||
    data.status === "verified" ||
    (err === undefined || err === null);
  const brokenRaw = data.broken_at_row ?? data.brokenAtRow;
  const brokenAtRow = typeof brokenRaw === "number" ? brokenRaw : undefined;
  const message = err
    ? `Tamper detected: ${String(err)}`
    : "Receipt cryptographic signature matches the hash chain.";
  const head = data.chain_head ?? data.chainHead;
  return {
    ok,
    brokenAtRow,
    message,
    chainHead: typeof head === "string" ? head : undefined,
  };
}
