import { GatewayRequestError, fetchFromGateway, type FetchOptions } from "../app/api";
import { aqlToCompiledRequest, gatewayFiltersToLegacy, type LegacyParsedQuery } from "./aql/compile";
import { fieldsForEntity } from "./fieldCatalog";
import { rowsToFrame } from "./frame";
import { resolveTimeToken } from "../lib/format";
import type {
  DataFrame,
  Datasource,
  DatasourceCapabilities,
  EntityKind,
  Field,
  FieldDescriptor,
  QueryRequest,
} from "./types";

export const SOC_QUERY_DATASOURCE_ID = "soc-query";

function withSignal(opts: FetchOptions, signal?: AbortSignal): FetchOptions {
  return signal ? { ...opts, signal } : opts;
}

interface SocQueryResponse {
  rows?: Array<Record<string, unknown>>;
  fields?: ReadonlyArray<Field>;
  length?: number;
  meta?: DataFrame["meta"];
  field_descriptors?: ReadonlyArray<FieldDescriptor>;
}

function responseToFrame(response: SocQueryResponse | Array<Record<string, unknown>>): DataFrame {
  if (Array.isArray(response)) return rowsToFrame(response);
  if (Array.isArray(response.fields) && typeof response.length === "number") {
    return { fields: response.fields, length: response.length, meta: response.meta };
  }
  const frame = rowsToFrame(Array.isArray(response.rows) ? response.rows : []);
  return {
    ...frame,
    meta: {
      ...frame.meta,
      ...response.meta,
      fieldDescriptors: response.field_descriptors,
    },
  };
}

/** Structured SOC event query with a safe decisions fallback for older gateways. */
export class SocQueryDatasource implements Datasource {
  readonly id = SOC_QUERY_DATASOURCE_ID;
  readonly capabilities: DatasourceCapabilities = {
    query: true,
    stream: false,
    fields: true,
    verify: false,
  };

  constructor(private readonly opts: FetchOptions) {}

  async query(req: QueryRequest): Promise<DataFrame> {
    const entity = req.entity ?? "decision";
    const compiled = aqlToCompiledRequest(req.aql ?? req.search ?? "", entity);
    const gatewayFilters = {
      ...compiled.filters,
      from: compiled.filters.from ?? resolveTimeToken(req.timeRange.from),
      to: compiled.filters.to ?? resolveTimeToken(req.timeRange.to),
    };
    const aggregate = req.aggregate ?? compiled.aggregate;
    const body = {
      version: 1,
      entity,
      filters: Object.fromEntries(
        Object.entries(gatewayFilters).filter(([, value]) => value !== undefined && value !== ""),
      ),
      aggregate,
      interval: aggregate === "count_over_time" ? req.interval ?? compiled.interval ?? "hour" : undefined,
      group_by: aggregate === "count_by" ? req.groupBy ?? compiled.groupBy : undefined,
      limit: req.limit ?? 50,
      cursor: req.cursor,
    };

    try {
      const response = await fetchFromGateway<SocQueryResponse | Array<Record<string, unknown>>>(
        withSignal(this.opts, req.signal),
        "/v1/soc/query",
        "POST",
        body,
      );
      return responseToFrame(response);
    } catch (error: unknown) {
      if (
        !(error instanceof GatewayRequestError) ||
        ![404, 405, 501].includes(error.status) ||
        (req.entity !== undefined && req.entity !== "decision") ||
        req.aggregate
      ) {
        throw error;
      }
      return this.queryDecisionsFallback(req, gatewayFiltersToLegacy(compiled.filters));
    }
  }

  fields(entity: EntityKind = "ase"): Promise<ReadonlyArray<FieldDescriptor>> {
    return Promise.resolve(fieldsForEntity(entity));
  }

  private async queryDecisionsFallback(
    req: QueryRequest,
    filters: LegacyParsedQuery,
  ): Promise<DataFrame> {
    const params = new URLSearchParams({ limit: String(req.limit ?? 50) });
    if (filters.agentId) params.set("agent_id", filters.agentId);
    if (filters.decision) params.set("decision", filters.decision);
    if (filters.sourceTrust) params.set("source_trust", filters.sourceTrust);
    if (filters.skill) params.set("skill", filters.skill);
    if (filters.action) params.set("action", filters.action);
    if (filters.resource) params.set("resource", filters.resource);
    if (filters.runId) params.set("run_id", filters.runId);
    if (filters.traceId) params.set("trace_id", filters.traceId);
    if (filters.actionHash) params.set("action_hash", filters.actionHash);
    if (filters.receiptHash) params.set("receipt_hash", filters.receiptHash);
    if (filters.q) params.set("q", filters.q);
    const from = resolveTimeToken(req.timeRange.from);
    const to = resolveTimeToken(req.timeRange.to);
    if (from) params.set("from", from);
    if (to) params.set("to", to);
    const rows = await fetchFromGateway<Array<Record<string, unknown>>>(
      withSignal(this.opts, req.signal),
      `/v1/decisions?${params.toString()}`,
    );
    return rowsToFrame(Array.isArray(rows) ? rows : []);
  }
}
