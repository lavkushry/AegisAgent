import { fetchFromGateway, type FetchOptions } from "@/lib/http/client";

export interface TenantStats {
  total_decisions: number;
  decisions_allow: number;
  decisions_deny: number;
  decisions_require_approval: number;
  total_agents: number;
  total_receipts: number;
  trust_level_breakdown: unknown[];
}

export function getTenantStats(opts: FetchOptions): Promise<TenantStats> {
  return fetchFromGateway<TenantStats>(opts, "/v1/stats");
}
