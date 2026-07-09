import { describe, expect, test } from "bun:test";
import AgentRiskMapPanel from "./AgentRiskMapPanel";
import {
  riskIntensity,
  rowsToRiskMap,
} from "./agentRiskMapModel";
import type { PanelDefinition } from "../types";

describe("AgentRiskMapPanel data path", () => {
  test("ranks scoreboard rows by score descending", () => {
    const rows = rowsToRiskMap(
      [
        {
          agent_id: "a2",
          agent_key: "low-agent",
          current_avg_risk_score: 12.5,
          decision_count_24h: 3,
          trend: "falling",
        },
        {
          agent_id: "a1",
          agent_key: "hot-agent",
          current_avg_risk_score: 81.2,
          decision_count_24h: 40,
          trend: "rising",
        },
        {
          agent_id: "a3",
          agent_key: "mid-agent",
          current_avg_risk_score: 40,
          decision_count_24h: 10,
          trend: "stable",
        },
      ],
      10,
    );
    expect(rows.map((r) => r.agentKey)).toEqual([
      "hot-agent",
      "mid-agent",
      "low-agent",
    ]);
    expect(rows[0].trend).toBe("rising");
    expect(rows[1].trend).toBe("stable");
  });

  test("respects maxRows and intensity bounds", () => {
    const rows = rowsToRiskMap(
      [
        {
          agent_id: "1",
          agent_key: "a",
          current_avg_risk_score: 90,
          decision_count_24h: 1,
          trend: "rising",
        },
        {
          agent_id: "2",
          agent_key: "b",
          current_avg_risk_score: 10,
          decision_count_24h: 1,
          trend: "stable",
        },
        {
          agent_id: "3",
          agent_key: "c",
          current_avg_risk_score: 50,
          decision_count_24h: 1,
          trend: "falling",
        },
      ],
      2,
    );
    expect(rows).toHaveLength(2);
    expect(rows[0].agentKey).toBe("a");
    expect(riskIntensity(90, 90)).toBe(1);
    expect(riskIntensity(0, 90)).toBeGreaterThan(0);
  });

  test("component is registered as agent-risk-map shape", () => {
    expect(typeof AgentRiskMapPanel).toBe("function");
    const def: PanelDefinition = {
      id: "risk-map",
      type: "agent-risk-map",
      title: "Agent risk map",
      datasourceId: "gateway-entity",
      snapshot: "agent-scoreboard",
      options: { maxRows: 8 },
    };
    void def;
  });
});
