import { describe, expect, it } from "vitest";

import type { AgentRecord, AgentRiskRecord } from "@/app/api";
import {
  formatAdvisoryRisk,
  formatFrameworkModel,
  formatOwner,
  mergeFleetRows,
  UNAVAILABLE,
} from "./agentFleetData";

const agent: AgentRecord = {
  id: "agent-1",
  agent_key: "coding-agent",
  name: "Coding Agent",
  environment: "production",
  framework: "langchain",
  model_provider: "openai",
  model_name: "gpt-4",
  owner_team: "platform",
  owner_email: "ops@example.com",
  risk_tier: "high",
  status: "active",
  last_seen_at: "2026-07-01T12:00:00Z",
};

describe("agentFleetData", () => {
  it("formats owner and framework/model with unavailable fallbacks", () => {
    expect(formatOwner(agent)).toContain("platform");
    expect(formatFrameworkModel(agent)).toContain("langchain");
    expect(formatOwner({ ...agent, owner_team: null, owner_email: null })).toBe(UNAVAILABLE);
  });

  it("merges advisory scoreboard metrics onto fleet rows", () => {
    const scoreboard: AgentRiskRecord[] = [
      {
        agent_id: "agent-1",
        current_avg_risk_score: 0.82,
        trend: "rising",
      },
    ];
    const rows = mergeFleetRows([agent], scoreboard);
    expect(rows[0]).toMatchObject({
      agent_key: "coding-agent",
      advisoryRiskScore: "0.82",
      advisoryTrend: "rising",
    });
  });

  it("returns unavailable advisory metrics when scoreboard has no match", () => {
    expect(formatAdvisoryRisk(undefined)).toEqual({ score: UNAVAILABLE, trend: UNAVAILABLE });
  });
});