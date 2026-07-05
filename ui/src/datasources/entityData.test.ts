import { describe, expect, it } from "vitest";

import { objectToSingleRowFrame, rowsToFrame } from "./frame";
import {
  agentScoreboardFromFrame,
  incidentGraphFromFrame,
  incidentNarrationFromFrame,
  socSummaryFromFrame,
  tenantStatsFromFrame,
} from "./entityData";

describe("entityData extractors", () => {
  it("reconstructs tenant stats and SOC summary from single-row frames", () => {
    const stats = tenantStatsFromFrame(objectToSingleRowFrame({
      total_decisions: 10,
      receipt_chain_verified: true,
    }));
    const summary = socSummaryFromFrame(objectToSingleRowFrame({
      approvals_pending: 2,
      incidents_open: 1,
    }));

    expect(stats.total_decisions).toBe(10);
    expect(stats.receipt_chain_verified).toBe(true);
    expect(summary.approvals_pending).toBe(2);
    expect(summary.incidents_open).toBe(1);
  });

  it("extracts scoreboard rows and incident sub-resource objects", () => {
    const scoreboard = agentScoreboardFromFrame(rowsToFrame([
      { agent_id: "agent-1", avg_risk_score: 0.8, trend: "rising" },
    ]));
    const graph = incidentGraphFromFrame(objectToSingleRowFrame({
      nodes: [{ id: "receipt-1", group: "receipt" }],
    }));
    const narration = incidentNarrationFromFrame(objectToSingleRowFrame({
      narrative: "Compromise path traced to approval bypass.",
      summary: "Approval bypass",
    }));

    expect(scoreboard[0]?.agent_id).toBe("agent-1");
    expect(graph.nodes).toHaveLength(1);
    expect(narration.narrative).toContain("approval bypass");
    expect(narration.summary).toBe("Approval bypass");
  });
});