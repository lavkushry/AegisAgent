import {
  fetchFromGateway,
  type FetchOptions,
} from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";
import { objectToSingleRowFrame, rowsToFrame } from "./frame";
import { fieldsForEntity } from "./fieldCatalog";
import type {
  DataFrame,
  Datasource,
  DatasourceCapabilities,
  EntityKind,
  GatewaySnapshot,
  QueryRequest,
} from "./types";

export const DEFAULT_DATASOURCE_ID = "gateway-entity";

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

const SNAPSHOT_PATHS: Record<
  Exclude<GatewaySnapshot, "trust-breakdown">,
  string
> = {
  "tenant-stats": "/v1/stats",
  "soc-summary": "/v1/soc/summary",
  "agent-scoreboard": "/v1/agents/risk-scoreboard",
};

const UNTRUSTED = new Set(["untrusted_external", "malicious_suspected"]);

function untrustedSourceCount(breakdown: unknown): number {
  if (!Array.isArray(breakdown)) return 0;
  return breakdown.reduce<number>((sum, row) => {
    if (!row || typeof row !== "object") return sum;
    const trustLevel = String(
      (row as Record<string, unknown>).trust_level ?? "",
    );
    const count = Number((row as Record<string, unknown>).count ?? 0);
    return UNTRUSTED.has(trustLevel) ? sum + count : sum;
  }, 0);
}

function trustBreakdownRows(
  breakdown: unknown,
): Array<Record<string, unknown>> {
  if (!Array.isArray(breakdown)) return [];
  return breakdown
    .filter((row) => row && typeof row === "object")
    .map((row) => {
      const record = row as Record<string, unknown>;
      return {
        trust_level: record.trust_level ?? "unknown",
        count: record.count ?? 0,
      };
    });
}

function withSignal(opts: FetchOptions, signal?: AbortSignal): FetchOptions {
  return signal ? { ...opts, signal } : opts;
}

/**
 * Tenant-scoped gateway REST → DataFrame. Snapshots + entity lists.
 * Aggregates / ASE require soc-query (Phase C).
 */
export class GatewayEntityDatasource implements Datasource {
  readonly id = DEFAULT_DATASOURCE_ID;
  readonly capabilities: DatasourceCapabilities = {
    query: true,
    stream: false,
    fields: true,
    verify: false,
  };

  private readonly opts: FetchOptions;

  constructor(opts: FetchOptions) {
    this.opts = opts;
  }

  async query(req: QueryRequest): Promise<DataFrame> {
    if (req.snapshot) {
      return this.querySnapshot(req);
    }
    if (req.entityId) {
      const entity = req.entity ?? "incident";
      if (entity === "ase") {
        throw new Error("Entity 'ase' requires the soc-query datasource");
      }
      const data = await fetchFromGateway<Record<string, unknown>>(
        withSignal(this.opts, req.signal),
        `${ENTITY_PATHS[entity]}/${encodeURIComponent(req.entityId)}`,
      );
      return objectToSingleRowFrame(
        data && typeof data === "object" ? data : {},
      );
    }

    const entity = req.entity ?? "decision";
    if (entity === "ase") {
      throw new Error("Entity 'ase' requires the soc-query datasource");
    }
    if (req.aggregate) {
      throw new Error(
        `Aggregate '${req.aggregate}' requires the soc-query datasource`,
      );
    }
    const limit = req.limit ?? 50;
    const params = new URLSearchParams({ limit: String(limit) });
    if (req.search) params.set("q", req.search);
    if (req.cursor) params.set("cursor", req.cursor);
    const raw = await fetchFromGateway<unknown>(
      withSignal(this.opts, req.signal),
      `${ENTITY_PATHS[entity]}?${params.toString()}`,
    );
    return rowsToFrame(asRecordArray(raw));
  }

  fields(entity: EntityKind) {
    return Promise.resolve(fieldsForEntity(entity));
  }

  private async querySnapshot(req: QueryRequest): Promise<DataFrame> {
    const snapshot = req.snapshot!;
    if (snapshot === "trust-breakdown") {
      const stats = await fetchFromGateway<Record<string, unknown>>(
        withSignal(this.opts, req.signal),
        SNAPSHOT_PATHS["tenant-stats"],
      );
      return rowsToFrame(trustBreakdownRows(stats?.trust_level_breakdown), [
        "trust_level",
        "count",
      ]);
    }

    const path =
      SNAPSHOT_PATHS[snapshot as Exclude<GatewaySnapshot, "trust-breakdown">];
    const data = await fetchFromGateway<
      Record<string, unknown> | Array<Record<string, unknown>>
    >(withSignal(this.opts, req.signal), path);

    if (snapshot === "agent-scoreboard") {
      return rowsToFrame(Array.isArray(data) ? data : asRecordArray(data));
    }
    const obj =
      data && typeof data === "object" && !Array.isArray(data) ? data : {};
    if (snapshot === "tenant-stats") {
      return objectToSingleRowFrame({
        ...obj,
        untrusted_source_count: untrustedSourceCount(
          obj.trust_level_breakdown,
        ),
      });
    }
    return objectToSingleRowFrame(obj);
  }
}
