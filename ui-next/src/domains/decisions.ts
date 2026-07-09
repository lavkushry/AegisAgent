import {
  fetchFromGateway,
  type FetchOptions,
} from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";

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
  if (filters.q) params.set("q", filters.q);
  const raw = await fetchFromGateway<unknown>(
    opts,
    `/v1/decisions?${params.toString()}`,
  );
  return asRecordArray(raw).map((row) => row as unknown as DecisionRecord);
}

/**
 * Minimal AQL subset for Phase 2 Explore:
 *   decision:allow agent_id:abc trust:untrusted_external free text
 * Full AQL compiler ports later; this maps chips to gateway filters.
 */
export function parseSimpleExploreQuery(input: string): DecisionFilters {
  const filters: DecisionFilters = { limit: 50 };
  const tokens = input.trim().split(/\s+/).filter(Boolean);
  const free: string[] = [];

  for (const token of tokens) {
    const colon = token.indexOf(":");
    if (colon <= 0) {
      free.push(token);
      continue;
    }
    const key = token.slice(0, colon).toLowerCase();
    const value = token.slice(colon + 1);
    if (!value) {
      free.push(token);
      continue;
    }
    if (key === "decision") filters.decision = value;
    else if (key === "agent_id" || key === "agent") filters.agentId = value;
    else if (key === "trust" || key === "source_trust")
      filters.sourceTrust = value;
    else if (key === "skill" || key === "tool") filters.skill = value;
    else free.push(token);
  }

  if (free.length) filters.q = free.join(" ");
  return filters;
}
