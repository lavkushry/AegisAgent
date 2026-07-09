import {
  fetchFromGateway,
  type FetchOptions,
} from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";
import { rowsToFrame } from "./frame";
import type {
  DataFrame,
  Datasource,
  DatasourceCapabilities,
  EntityKind,
  QueryRequest,
} from "./types";
import { aqlToCompiledRequest } from "./aql/compile";

export const SOC_QUERY_DATASOURCE_ID = "soc-query";

type SocQueryBody = {
  version: 1;
  entity: string;
  filters: Record<string, string | undefined>;
  aggregate?: string;
  interval?: string;
  group_by?: string;
  limit?: number;
};

function entityName(entity: EntityKind | undefined): string {
  // Gateway v1 supports decision | ase for /v1/soc/query.
  if (entity === "ase") return "ase";
  return "decision";
}

function buildBody(req: QueryRequest): SocQueryBody {
  let filters: Record<string, string | undefined> = {
    from: req.timeRange.from,
    to: req.timeRange.to,
  };

  if (req.aql?.trim()) {
    const compiled = aqlToCompiledRequest(
      req.aql,
      req.entity === "ase" ? "ase" : "decision",
    );
    filters = {
      ...filters,
      ...Object.fromEntries(
        Object.entries(compiled.filters).map(([k, v]) => [
          k,
          v === undefined || v === null ? undefined : String(v),
        ]),
      ),
    };
    const body: SocQueryBody = {
      version: 1,
      entity: entityName(req.entity),
      filters,
      limit: req.limit,
    };
    if (compiled.aggregate) body.aggregate = compiled.aggregate;
    if (compiled.interval) body.interval = compiled.interval;
    if (compiled.groupBy) body.group_by = compiled.groupBy;
    return body;
  }

  const body: SocQueryBody = {
    version: 1,
    entity: entityName(req.entity),
    filters,
    limit: req.limit,
  };
  if (req.aggregate) body.aggregate = req.aggregate;
  if (req.interval) body.interval = req.interval;
  if (req.groupBy) body.group_by = req.groupBy;
  if (req.search) body.filters.q = req.search;
  return body;
}

function normalizeResponse(raw: unknown): DataFrame {
  if (Array.isArray(raw)) {
    return rowsToFrame(asRecordArray(raw), ["bucket", "count"]);
  }
  if (raw && typeof raw === "object") {
    const obj = raw as { rows?: unknown };
    if (Array.isArray(obj.rows)) {
      const rows = asRecordArray(obj.rows);
      if (rows.length > 0 && "bucket" in rows[0]) {
        return rowsToFrame(rows, ["bucket", "count"]);
      }
      return rowsToFrame(rows);
    }
  }
  return rowsToFrame([]);
}

/**
 * Structured SOC query datasource — POST /v1/soc/query.
 * Powers timeseries (count_over_time) and count_by panels.
 */
export class SocQueryDatasource implements Datasource {
  readonly id = SOC_QUERY_DATASOURCE_ID;
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
    const body = buildBody(req);
    // Strip undefined filter values so deny_unknown_fields doesn't choke on nulls.
    const filters: Record<string, string> = {};
    for (const [k, v] of Object.entries(body.filters)) {
      if (v !== undefined && v !== "") filters[k] = v;
    }
    const payload = { ...body, filters };
    const opts = req.signal
      ? { ...this.opts, signal: req.signal }
      : this.opts;
    const raw = await fetchFromGateway<unknown>(
      opts,
      "/v1/soc/query",
      "POST",
      payload,
    );
    return normalizeResponse(raw);
  }

  fields(entity: EntityKind) {
    void entity;
    return Promise.resolve([
      { name: "bucket", type: "time" as const, facetable: false },
      { name: "count", type: "number" as const, facetable: false },
    ]);
  }
}
