import { parseAql } from "@/datasources/aql/parse";
import { frameRows } from "../datasources/frame";
import type { DataFrame, EntityKind, QueryRequest } from "../datasources/types";

export type ExploreEntity = Extract<EntityKind, "decision" | "ase">;

export interface ExploreEventRecord extends Record<string, unknown> {
  id: string;
  decision?: string;
  tool?: string;
  skill?: string;
  event_type?: string;
  tool_call?: { name?: string; parameters?: Record<string, unknown> };
  agent_id?: string;
  root_trust_level?: string;
  source_trust?: string;
  created_at?: string;
  timestamp?: string;
  ts?: string;
  reason?: string;
  matched_policies?: string[];
  matched_policy_ids?: string[];
  run_id?: string;
  trace_id?: string;
  action_hash?: string;
  receipt_hash?: string;
  receipt_id?: string;
  composite_risk_score?: number;
}

/** @deprecated Use ExploreEventRecord */
export type DecisionRecord = ExploreEventRecord;

export function buildExploreRequest(
  entity: ExploreEntity,
  aql: string,
  range: string,
  signal?: AbortSignal,
): QueryRequest {
  return {
    entity,
    aql,
    timeRange: { from: `now-${range}`, to: "now" },
    variables: {},
    limit: 50,
    signal,
  };
}

export function buildExploreDecisionRequest(
  aql: string,
  range: string,
  signal?: AbortSignal,
): QueryRequest {
  return buildExploreRequest("decision", aql, range, signal);
}

export function appendAqlFilter(query: string, field: string, value: string): string {
  const trimmed = query.trim();
  const escaped = value.includes(" ") ? `"${value}"` : value;
  const clause = `${field}:${escaped}`;
  if (!trimmed) return clause;
  if (trimmed.toLowerCase().includes(clause.toLowerCase())) return trimmed;
  return `${trimmed} AND ${clause}`;
}

export function parsedAqlChips(input: string): Array<{ field: string; value: string }> {
  const parsed = parseAql(input);
  const chips: Array<{ field: string; value: string }> = [];
  const push = (field: string, value: string | undefined) => {
    if (value) chips.push({ field, value });
  };
  push("event_type", parsed.eventType);
  push("severity", parsed.severity);
  push("source_component", parsed.sourceComponent);
  push("agent_id", parsed.agentId);
  push("decision", parsed.decision);
  push("source_trust", parsed.sourceTrust);
  push("tool", parsed.skill);
  push("action", parsed.action);
  push("resource", parsed.resource);
  push("run_id", parsed.runId);
  push("trace_id", parsed.traceId);
  push("action_hash", parsed.actionHash);
  push("receipt_hash", parsed.receiptHash);
  if (parsed.q) chips.push({ field: "q", value: parsed.q });
  return chips;
}

export function exploreReceiptId(row: ExploreEventRecord): string | undefined {
  return typeof row.receipt_id === "string" && row.receipt_id ? row.receipt_id : undefined;
}

export function exploreEventTime(row: ExploreEventRecord): string | undefined {
  return row.timestamp || row.created_at || row.ts;
}

export function exploreResultCount(frame: DataFrame | undefined): number | undefined {
  if (!frame) return undefined;
  if (typeof frame.meta?.total === "number") return frame.meta.total;
  return frame.length;
}

function isExploreEventRecord(row: Record<string, unknown>): row is ExploreEventRecord {
  return typeof row.id === "string";
}

export function decisionRowsFromFrame(frame: DataFrame | undefined): ExploreEventRecord[] {
  return frame ? frameRows(frame).filter(isExploreEventRecord) : [];
}
