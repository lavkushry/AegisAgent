import {
  fetchFromGateway,
  type FetchOptions,
} from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";
import {
  aqlToCompiledRequest,
  compileAqlString,
} from "@/datasources/aql/compile";
import type { GatewayFilters } from "@/datasources/aql/types";
import { AqlCompileError, AqlParseError } from "@/datasources/aql/types";

export interface DecisionRecord {
  id: string;
  decision?: string;
  tool?: string;
  skill?: string;
  agent_id?: string;
  source_trust?: string;
  root_trust_level?: string;
  created_at?: string;
  ts?: string;
  reason?: string;
  action_hash?: string;
  receipt_id?: string;
  run_id?: string;
  composite_risk_score?: number;
}

export interface DecisionFilters {
  limit?: number;
  agentId?: string;
  decision?: string;
  sourceTrust?: string;
  skill?: string;
  action?: string;
  resource?: string;
  runId?: string;
  traceId?: string;
  actionHash?: string;
  from?: string;
  to?: string;
  q?: string;
}

/** Structured filters + free-text `q` → GET /v1/decisions (gateway parameterized). */
export async function searchDecisions(
  opts: FetchOptions,
  filters: DecisionFilters = {},
): Promise<DecisionRecord[]> {
  const params = new URLSearchParams();
  params.set("limit", String(filters.limit ?? 50));
  if (filters.agentId) params.set("agent_id", filters.agentId);
  if (filters.decision) params.set("decision", filters.decision);
  if (filters.sourceTrust) params.set("source_trust", filters.sourceTrust);
  if (filters.skill) params.set("skill", filters.skill);
  if (filters.action) params.set("action", filters.action);
  if (filters.resource) params.set("resource", filters.resource);
  if (filters.runId) params.set("run_id", filters.runId);
  if (filters.traceId) params.set("trace_id", filters.traceId);
  if (filters.actionHash) params.set("action_hash", filters.actionHash);
  if (filters.from) params.set("from", filters.from);
  if (filters.to) params.set("to", filters.to);
  if (filters.q) params.set("q", filters.q);
  const raw = await fetchFromGateway<unknown>(
    opts,
    `/v1/decisions?${params.toString()}`,
  );
  return asRecordArray(raw).map((row) => row as unknown as DecisionRecord);
}

export function gatewayFiltersToDecisionFilters(
  filters: GatewayFilters,
  limit = 50,
): DecisionFilters {
  return {
    limit,
    agentId: filters.agent_id,
    decision: filters.decision,
    sourceTrust: filters.source_trust,
    skill: filters.tool,
    action: filters.action,
    resource: filters.resource,
    runId: filters.run_id,
    traceId: filters.trace_id,
    actionHash: filters.action_hash,
    from: filters.from,
    to: filters.to,
    q: filters.q,
  };
}

/**
 * Full AQL → gateway decision filters (fail-closed on parse/compile errors).
 */
export function compileExploreAql(
  input: string,
  entity: "decision" | "ase" = "decision",
): DecisionFilters {
  const { filters } = aqlToCompiledRequest(input.trim() || "", entity);
  return gatewayFiltersToDecisionFilters(filters, 50);
}

/**
 * Validate AQL without throwing — for UI error banner.
 */
export function validateExploreAql(
  input: string,
  entity: "decision" | "ase" = "decision",
): string | null {
  try {
    if (!input.trim()) return null;
    aqlToCompiledRequest(input, entity);
    return null;
  } catch (err) {
    if (err instanceof AqlParseError || err instanceof AqlCompileError) {
      return err.message;
    }
    return err instanceof Error ? err.message : "Invalid AQL";
  }
}

/**
 * @deprecated Prefer compileExploreAql — kept for existing unit tests.
 * Minimal chip parser used before full AQL port.
 */
export function parseSimpleExploreQuery(input: string): DecisionFilters {
  try {
    return compileExploreAql(input, "decision");
  } catch {
    // Fallback: empty free-text only so Explore never hard-crashes on bad input
    // when callers used the old soft parser.
    return { limit: 50, q: input.trim() || undefined };
  }
}

export { compileAqlString };
