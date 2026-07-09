export type RiskTrend = "rising" | "falling" | "stable";

export interface RiskMapRow {
  readonly agentId: string;
  readonly agentKey: string;
  readonly score: number;
  readonly decisionCount24h: number;
  readonly trend: RiskTrend;
}

function parseTrend(raw: unknown): RiskTrend {
  const t = String(raw ?? "stable").toLowerCase();
  if (t === "rising" || t === "falling" || t === "stable") return t;
  return "stable";
}

/** Normalize gateway risk-scoreboard rows for the agent-risk-map panel. */
export function rowsToRiskMap(
  rows: Array<Record<string, unknown>>,
  maxRows: number,
): RiskMapRow[] {
  const mapped: RiskMapRow[] = [];
  for (const row of rows) {
    const agentId = String(row.agent_id ?? row.id ?? "").trim();
    if (!agentId) continue;
    const scoreRaw = row.current_avg_risk_score ?? row.score ?? 0;
    const score =
      typeof scoreRaw === "number" ? scoreRaw : Number(scoreRaw);
    if (!Number.isFinite(score)) continue;
    const countRaw = row.decision_count_24h ?? row.count ?? 0;
    const decisionCount24h =
      typeof countRaw === "number" ? countRaw : Number(countRaw) || 0;
    const agentKey = String(
      row.agent_key ?? row.name ?? agentId,
    ).trim();
    mapped.push({
      agentId,
      agentKey: agentKey || agentId,
      score,
      decisionCount24h,
      trend: parseTrend(row.trend),
    });
  }
  return mapped
    .sort((a, b) => b.score - a.score)
    .slice(0, Math.max(1, maxRows));
}

/** 0–1 intensity relative to max score (floor so zeros stay visible). */
export function riskIntensity(score: number, maxScore: number): number {
  if (maxScore <= 0) return 0.08;
  return Math.min(1, Math.max(0.12, score / maxScore));
}
