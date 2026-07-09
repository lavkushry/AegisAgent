import { canonicalAqlField } from "./fields";
import { parseAql } from "./parse";
import {
  ALLOWED_COUNT_BY_FIELDS,
  ALLOWED_COUNT_OVER_TIME_INTERVALS,
  AqlCompileError,
  type AqlNode,
  type AqlQuery,
  type CompiledAqlRequest,
  type GatewayFilters,
  type ParseAqlOptions,
} from "./types";
import type { EntityKind, QueryRequest } from "../types";

function containsOr(node: AqlNode): boolean {
  if (node.kind === "bool") {
    if (node.op === "or") return true;
    return node.children.some(containsOr);
  }
  return false;
}

function collectAndTerms(node: AqlNode, terms: AqlNode[]): void {
  if (node.kind === "bool" && node.op === "and") {
    for (const child of node.children) collectAndTerms(child, terms);
    return;
  }
  terms.push(node);
}

function applyTerm(filters: GatewayFilters, node: AqlNode): void {
  if (node.kind === "text") {
    filters.q = filters.q ? `${filters.q} ${node.value}` : node.value;
    return;
  }
  if (node.kind !== "term") {
    throw new AqlCompileError("Only AND-combined filters can be executed against the gateway");
  }

  const field = canonicalAqlField(node.field);
  if (field === "@time") {
    if (node.op === "range") {
      filters.from = node.value;
      filters.to = node.to;
      return;
    }
    throw new AqlCompileError("@time requires a range: @time:[from TO to]");
  }

  const key = field as keyof GatewayFilters;
  if (!(key in GATEWAY_SCALAR_FIELDS)) {
    throw new AqlCompileError(`Unsupported gateway field '${node.field}'`);
  }
  if (node.op === "range") {
    throw new AqlCompileError(`Field '${node.field}' does not support range syntax`);
  }
  if (filters[key]) {
    throw new AqlCompileError(`Duplicate filter for '${node.field}'`);
  }
  (filters as Record<string, string | undefined>)[key] = node.value;
}

const GATEWAY_SCALAR_FIELDS: Readonly<Record<keyof GatewayFilters, true>> = {
  event_type: true,
  severity: true,
  source_component: true,
  agent_id: true,
  decision: true,
  source_trust: true,
  tool: true,
  action: true,
  resource: true,
  run_id: true,
  trace_id: true,
  action_hash: true,
  receipt_hash: true,
  from: true,
  to: true,
  q: true,
};

export function compileAqlToGatewayFilters(query: AqlQuery, entity: EntityKind): GatewayFilters {
  if (containsOr(query.filter)) {
    throw new AqlCompileError(
      "OR filters are parsed for URL sharing but cannot execute until the gateway accepts boolean AST",
    );
  }

  const terms: AqlNode[] = [];
  collectAndTerms(query.filter, terms);
  const filters: GatewayFilters = {};
  for (const term of terms) {
    applyTerm(filters, term);
  }

  if (query.aggregate?.by && !ALLOWED_COUNT_BY_FIELDS.includes(query.aggregate.by)) {
    throw new AqlCompileError(`Unsupported group_by field '${query.aggregate.by}'`);
  }
  if (
    query.aggregate?.interval &&
    !ALLOWED_COUNT_OVER_TIME_INTERVALS.includes(query.aggregate.interval)
  ) {
    throw new AqlCompileError(`Unsupported interval '${query.aggregate.interval}'`);
  }

  void entity;
  return filters;
}

export function aqlToCompiledRequest(
  input: string,
  entity: EntityKind,
  options: Omit<ParseAqlOptions, "entity"> = {},
): CompiledAqlRequest {
  const query = parseAql(input, { ...options, entity });
  const filters = compileAqlToGatewayFilters(query, entity);
  const compiled: CompiledAqlRequest = { filters };
  if (query.aggregate?.func === "count_over_time") {
    return {
      ...compiled,
      aggregate: "count_over_time",
      interval: query.aggregate.interval ?? "hour",
    };
  }
  if (query.aggregate?.func === "count") {
    if (query.aggregate.by) {
      return {
        ...compiled,
        aggregate: "count_by",
        groupBy: query.aggregate.by as QueryRequest["groupBy"],
      };
    }
    return { ...compiled, aggregate: "count" };
  }
  return compiled;
}

/** @deprecated Use compileAqlToGatewayFilters after parseAql. */
export interface LegacyParsedQuery {
  eventType?: string;
  severity?: string;
  sourceComponent?: string;
  agentId?: string;
  decision?: string;
  sourceTrust?: string;
  skill?: string;
  action?: string;
  resource?: string;
  runId?: string;
  traceId?: string;
  actionHash?: string;
  receiptHash?: string;
  q?: string;
}

export function gatewayFiltersToLegacy(filters: GatewayFilters): LegacyParsedQuery {
  return {
    eventType: filters.event_type,
    severity: filters.severity,
    sourceComponent: filters.source_component,
    agentId: filters.agent_id,
    decision: filters.decision,
    sourceTrust: filters.source_trust,
    skill: filters.tool,
    action: filters.action,
    resource: filters.resource,
    runId: filters.run_id,
    traceId: filters.trace_id,
    actionHash: filters.action_hash,
    receiptHash: filters.receipt_hash,
    q: filters.q,
  };
}

export function compileAqlString(input: string, entity: EntityKind = "decision"): LegacyParsedQuery {
  const { filters } = aqlToCompiledRequest(input, entity);
  return gatewayFiltersToLegacy(filters);
}