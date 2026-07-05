import { fetchFromGateway, type FetchOptions } from "../app/api";
import { fieldsForEntity } from "./fieldCatalog";
import { normalizeVerification } from "./receiptVerification";
import { resolveTimeToken } from "../lib/format";
import { objectToSingleRowFrame, rowsToFrame } from "./frame";
import type {
  DataFrame,
  Datasource,
  DatasourceCapabilities,
  EntityKind,
  GatewaySnapshot,
  QueryRequest,
  VerifyResult,
} from "./types";

const ENTITY_PATHS: Record<Exclude<EntityKind, "ase">, string> = {
  incident: "/v1/incidents",
  alert: "/v1/alerts",
  approval: "/v1/approvals",
  agent: "/v1/agents",
  mcp_server: "/v1/mcp/servers",
  receipt: "/v1/receipts",
  decision: "/v1/decisions",
  rule: "/v1/detection_rules",
};

const SNAPSHOT_PATHS: Record<GatewaySnapshot, string> = {
  "tenant-stats": "/v1/stats",
  "soc-summary": "/v1/soc/summary",
  "agent-scoreboard": "/v1/agents/risk-scoreboard",
};

function withSignal(opts: FetchOptions, signal?: AbortSignal): FetchOptions {
  return signal ? { ...opts, signal } : opts;
}

function normalizeMcpManifestHistory(
  response: Array<Record<string, unknown>> | { snapshots?: Array<Record<string, unknown>> } | null | undefined,
): Array<Record<string, unknown>> {
  if (Array.isArray(response)) return response;
  if (response && Array.isArray(response.snapshots)) return response.snapshots;
  return [];
}

/**
 * Reads tenant-scoped entities from the gateway REST API and returns them
 * as DataFrames. Wraps the existing fetchFromGateway transport; it does not
 * support AQL aggregation (that is the event-query datasource).
 */
export class GatewayEntityDatasource implements Datasource {
  readonly id = "gateway-entity";
  readonly capabilities: DatasourceCapabilities = {
    query: true,
    stream: false,
    fields: true,
    verify: true,
  };

  constructor(private readonly opts: FetchOptions) {}

  async query(req: QueryRequest): Promise<DataFrame> {
    if (req.snapshot) {
      return this.querySnapshot(req);
    }
    if (req.rulesCatalog) {
      return this.queryRulesCatalog(req);
    }
    if (req.entityId && req.subResource && req.subResource !== "detail") {
      return this.querySubResource(req);
    }
    if (req.entityId) {
      return this.queryEntityDetail(req);
    }

    const entity = req.entity ?? "decision";
    if (entity === "ase") {
      throw new Error("Entity 'ase' requires the soc-query datasource");
    }
    if (req.aggregate === "count_over_time") {
      if (entity !== "decision") {
        throw new Error("Aggregate 'count_over_time' is only supported for the 'decision' entity");
      }
      return this.countOverTime(req);
    }
    const entityPath = ENTITY_PATHS[entity];
    const limit = req.limit ?? 50;
    const params = new URLSearchParams({ limit: String(limit) });
    if (req.search) params.set("q", req.search);
    if (req.cursor) params.set("cursor", req.cursor);
    const path = `${entityPath}?${params.toString()}`;
    const rows = await fetchFromGateway<Array<Record<string, unknown>>>(withSignal(this.opts, req.signal), path);
    return rowsToFrame(Array.isArray(rows) ? rows : []);
  }

  private async querySnapshot(req: QueryRequest): Promise<DataFrame> {
    const snapshot = req.snapshot!;
    const path = SNAPSHOT_PATHS[snapshot];
    const data = await fetchFromGateway<Record<string, unknown> | Array<Record<string, unknown>>>(
      withSignal(this.opts, req.signal),
      path,
    );
    if (snapshot === "agent-scoreboard") {
      return rowsToFrame(Array.isArray(data) ? data : []);
    }
    const obj = data && typeof data === "object" && !Array.isArray(data) ? data : {};
    return objectToSingleRowFrame(obj);
  }

  private async queryRulesCatalog(req: QueryRequest): Promise<DataFrame> {
    const path = req.rulesCatalog === "soc" ? "/v1/soc/rules" : "/v1/detection_rules";
    const rows = await fetchFromGateway<Array<Record<string, unknown>>>(
      withSignal(this.opts, req.signal),
      path,
    );
    return rowsToFrame(Array.isArray(rows) ? rows : []);
  }

  private async queryEntityDetail(req: QueryRequest): Promise<DataFrame> {
    const entity = req.entity ?? "incident";
    if (entity === "ase") {
      throw new Error("Entity 'ase' requires the soc-query datasource");
    }
    const entityPath = ENTITY_PATHS[entity];
    const encodedId = encodeURIComponent(req.entityId!);
    const data = await fetchFromGateway<Record<string, unknown>>(
      withSignal(this.opts, req.signal),
      `${entityPath}/${encodedId}`,
    );
    return objectToSingleRowFrame(data && typeof data === "object" ? data : {});
  }

  private async querySubResource(req: QueryRequest): Promise<DataFrame> {
    const entity = req.entity ?? "incident";
    const encodedId = encodeURIComponent(req.entityId!);
    const subResource = req.subResource!;

    if (subResource === "graph") {
      if (entity !== "incident") {
        throw new Error("Sub-resource 'graph' is only supported for the 'incident' entity");
      }
      const graph = await fetchFromGateway<Record<string, unknown>>(
        withSignal(this.opts, req.signal),
        `/v1/graph/incident/${encodedId}`,
      );
      return objectToSingleRowFrame(graph && typeof graph === "object" ? graph : { nodes: [] });
    }

    if (subResource === "narrate") {
      if (entity !== "incident") {
        throw new Error("Sub-resource 'narrate' is only supported for the 'incident' entity");
      }
      const narration = await fetchFromGateway<Record<string, unknown>>(
        withSignal(this.opts, req.signal),
        `/v1/incidents/${encodedId}/narrate`,
      );
      return objectToSingleRowFrame(narration && typeof narration === "object" ? narration : {});
    }

    if (subResource === "manifest-history") {
      if (entity !== "mcp_server") {
        throw new Error("Sub-resource 'manifest-history' is only supported for the 'mcp_server' entity");
      }
      const response = await fetchFromGateway<
        Array<Record<string, unknown>> | { snapshots?: Array<Record<string, unknown>> }
      >(withSignal(this.opts, req.signal), `/v1/mcp/servers/${encodedId}/manifest-history`);
      return rowsToFrame(normalizeMcpManifestHistory(response));
    }

    throw new Error(`Unsupported sub-resource '${subResource}'`);
  }

  /** Decision count bucketed over time -> a [time, number] DataFrame. */
  private async countOverTime(req: QueryRequest): Promise<DataFrame> {
    const params = new URLSearchParams({ interval: req.interval ?? "hour" });
    const from = resolveTimeToken(req.timeRange.from);
    const to = resolveTimeToken(req.timeRange.to);
    if (from) params.set("from", from);
    if (to) params.set("to", to);
    const points = await fetchFromGateway<Array<{ bucket: string; count: number }>>(
      withSignal(this.opts, req.signal),
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

  async fields(entity: EntityKind) {
    return fieldsForEntity(entity);
  }

  async verifyReceipt(receiptId: string, signal?: AbortSignal): Promise<VerifyResult> {
    const data = await fetchFromGateway<Record<string, unknown>>(
      withSignal(this.opts, signal),
      `/v1/receipts/${encodeURIComponent(receiptId)}/verify`,
    );
    return normalizeVerification(data);
  }
}
