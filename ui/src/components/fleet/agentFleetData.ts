import type { AgentRecord, AgentRiskRecord } from "@/app/api";

export const UNAVAILABLE = "—";

export type FleetRow = {
  id: string;
  agent_key: string;
  name: string;
  owner: string;
  environment: string;
  frameworkModel: string;
  risk_tier: string;
  status: string;
  advisoryRiskScore: string;
  advisoryTrend: string;
  lastSeen: string;
};

export function formatOwner(agent: AgentRecord): string {
  if (agent.owner_team && agent.owner_email) {
    return `${agent.owner_team} · ${agent.owner_email}`;
  }
  if (agent.owner_team) return agent.owner_team;
  if (agent.owner_email) return agent.owner_email;
  return UNAVAILABLE;
}

export function formatFrameworkModel(agent: AgentRecord): string {
  const framework = agent.framework?.trim();
  const model = [agent.model_provider, agent.model_name].filter(Boolean).join(" / ");
  if (framework && model) return `${framework} · ${model}`;
  if (framework) return framework;
  if (model) return model;
  return UNAVAILABLE;
}

export function formatLastSeen(lastSeen?: string | null): string {
  if (!lastSeen) return "Never seen";
  const date = new Date(lastSeen);
  if (Number.isNaN(date.getTime())) return UNAVAILABLE;
  return date.toLocaleString();
}

export function scoreboardEntryForAgent(
  agent: AgentRecord,
  scoreboard: AgentRiskRecord[],
): AgentRiskRecord | undefined {
  return scoreboard.find(
    (entry) => entry.agent_id === agent.id || entry.agent_key === agent.agent_key,
  );
}

export function formatAdvisoryRisk(entry?: AgentRiskRecord): { score: string; trend: string } {
  if (!entry) {
    return { score: UNAVAILABLE, trend: UNAVAILABLE };
  }
  const scoreValue = entry.current_avg_risk_score ?? entry.avg_risk_score;
  const score =
    typeof scoreValue === "number" && Number.isFinite(scoreValue)
      ? scoreValue.toFixed(2)
      : UNAVAILABLE;
  const trend = entry.trend?.trim() ? entry.trend : UNAVAILABLE;
  return { score, trend };
}

export function mergeFleetRows(
  agents: AgentRecord[],
  scoreboard: AgentRiskRecord[],
): FleetRow[] {
  return agents.map((agent) => {
    const risk = formatAdvisoryRisk(scoreboardEntryForAgent(agent, scoreboard));
    return {
      id: agent.id,
      agent_key: agent.agent_key,
      name: agent.name,
      owner: formatOwner(agent),
      environment: agent.environment || UNAVAILABLE,
      frameworkModel: formatFrameworkModel(agent),
      risk_tier: agent.risk_tier || "unknown",
      status: agent.status || "unknown",
      advisoryRiskScore: risk.score,
      advisoryTrend: risk.trend,
      lastSeen: formatLastSeen(agent.last_seen_at),
    };
  });
}