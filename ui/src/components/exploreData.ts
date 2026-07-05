import { frameRows } from "../datasources/frame";
import type { DataFrame, QueryRequest } from "../datasources/types";

export interface DecisionRecord extends Record<string, unknown> {
  id: string;
  decision?: string;
  tool?: string;
  skill?: string;
  tool_call?: { name?: string; parameters?: Record<string, unknown> };
  agent_id?: string;
  root_trust_level?: string;
  source_trust?: string;
  created_at?: string;
  ts?: string;
  reason?: string;
  matched_policies?: string[];
  matched_policy_ids?: string[];
  run_id?: string;
  action_hash?: string;
  composite_risk_score?: number;
}

export function buildExploreDecisionRequest(
  aql: string,
  range: string,
  signal?: AbortSignal,
): QueryRequest {
  return {
    entity: "decision",
    aql,
    timeRange: { from: `now-${range}`, to: "now" },
    variables: {},
    limit: 50,
    signal,
  };
}

function isDecisionRecord(row: Record<string, unknown>): row is DecisionRecord {
  return typeof row.id === "string";
}

export function decisionRowsFromFrame(frame: DataFrame | undefined): DecisionRecord[] {
  return frame ? frameRows(frame).filter(isDecisionRecord) : [];
}
