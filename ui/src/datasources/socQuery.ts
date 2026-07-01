import { GatewayRequestError, fetchFromGateway, type FetchOptions } from "../app/api";
import { parseAql } from "./aql/parse";
import { rowsToFrame } from "./frame";
import type {
  DataFrame,
  Datasource,
  DatasourceCapabilities,
  Field,
  FieldDescriptor,
  QueryRequest,
} from "./types";

export const SOC_QUERY_DATASOURCE_ID = "soc-query";

const EVENT_FIELDS: ReadonlyArray<FieldDescriptor> = [
  { name: "timestamp", type: "time", facetable: false },
  { name: "event_type", type: "string", facetable: true },
  { name: "agent_id", type: "string", facetable: true },
  { name: "tool", type: "string", facetable: true },
  { name: "action", type: "string", facetable: true },
  { name: "decision", type: "decision", facetable: true, examples: ["allow", "deny", "require_approval"] },
  { name: "source_trust", type: "trust", facetable: true },
  { name: "action_hash", type: "hash", facetable: false },
  { name: "receipt_hash", type: "hash", facetable: false },
  { name: "run_id", type: "string", facetable: true },
  { name: "trace_id", type: "string", facetable: true },
];

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
    const filters = parseAql(req.aql ?? req.search ?? "");
    const gatewayFilters = {
      event_type: filters.eventType,
      severity: filters.severity,
      source_component: filters.sourceComponent,
      agent_id: filters.agentId,
      decision: filters.decision,
      source_trust: filters.sourceTrust,
      tool: filters.skill,
      action: filters.action,
      resource: filters.resource,
      run_id: filters.runId,
      trace_id: filters.traceId,
      action_hash: filters.actionHash,
      receipt_hash: filters.receiptHash,
      q: filters.q,
      from: req.timeRange.from,
      to: req.timeRange.to,
    };
    const body = {
      version: 1,
      entity: req.entity ?? "decision",
      filters: Object.fromEntries(
        Object.entries(gatewayFilters).filter(([, value]) => value !== undefined && value !== ""),
      ),
      aggregate: req.aggregate,
      interval: req.aggregate === "count_over_time" ? req.interval ?? "hour" : undefined,
      group_by: req.aggregate === "count_by" ? req.groupBy : undefined,
      limit: req.limit ?? 50,
      cursor: req.cursor,
    };

    try {
      const response = await fetchFromGateway<SocQueryResponse | Array<Record<string, unknown>>>(
        this.opts,
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
      return this.queryDecisionsFallback(req, filters);
    }
  }

  fields(): Promise<ReadonlyArray<FieldDescriptor>> {
    return Promise.resolve(EVENT_FIELDS);
  }

  private async queryDecisionsFallback(
    req: QueryRequest,
    filters: ReturnType<typeof parseAql>,
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
    if (req.timeRange.from) params.set("from", req.timeRange.from);
    if (req.timeRange.to) params.set("to", req.timeRange.to);
    const rows = await fetchFromGateway<Array<Record<string, unknown>>>(
      this.opts,
      `/v1/decisions?${params.toString()}`,
    );
    return rowsToFrame(Array.isArray(rows) ? rows : []);
  }
}
