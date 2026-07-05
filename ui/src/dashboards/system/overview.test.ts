import { describe, expect, it } from "vitest";

import { overviewDashboard } from "./overview";

function panelById(id: string) {
  return overviewDashboard.layout
    .flatMap((row) => row.panels)
    .find((item) => item.panel.id === id)?.panel;
}

describe("overviewDashboard schema", () => {
  it("declares production vitals fed by gateway snapshots", () => {
    const panelIds = overviewDashboard.layout.flatMap((row) => row.panels.map((item) => item.panel.id));
    expect(panelIds).toEqual(
      expect.arrayContaining([
        "stat-protected-actions",
        "stat-blocked-actions",
        "stat-pending-approvals",
        "stat-open-incidents",
        "stat-active-detections",
        "stat-receipt-chain",
        "stat-untrusted-sources",
        "table-trust-distribution",
        "table-denies-by-agent",
        "feed-latest-incident",
        "feed-decisions",
        "feed-alerts",
      ]),
    );

    const protectedActions = panelById("stat-protected-actions");
    expect(protectedActions?.snapshot).toBe("tenant-stats");
    expect(protectedActions?.options).toMatchObject({ valueField: "total_decisions" });
    expect(protectedActions?.drilldowns?.length).toBeGreaterThan(0);

    const blockedActions = panelById("stat-blocked-actions");
    expect(blockedActions?.options).toMatchObject({ valueField: "decisions_deny" });
    expect(blockedActions?.drilldowns?.[0]?.target).toMatchObject({ kind: "explore" });
  });

  it("never treats receipt verification as healthy without an explicit verify result", () => {
    const receiptChain = panelById("stat-receipt-chain");
    expect(receiptChain?.options).toMatchObject({
      field: "receipt_verify_state",
      healthyValues: ["verified"],
    });
  });

  it("does not embed synthetic demo entities in panel queries", () => {
    for (const row of overviewDashboard.layout) {
      for (const { panel } of row.panels) {
        if (panel.id === "table-denies-by-agent") {
          expect(panel.query).toBe("decision:deny");
          continue;
        }
        expect(panel.search).toBeUndefined();
      }
    }
  });

  it("wires trust distribution and denial aggregates to gateway-backed datasources", () => {
    expect(panelById("table-trust-distribution")?.snapshot).toBe("trust-breakdown");
    expect(panelById("stat-untrusted-sources")?.options).toMatchObject({
      valueField: "untrusted_source_count",
    });
    expect(panelById("table-denies-by-agent")).toMatchObject({
      datasourceId: "soc-query",
      aggregate: "count_by",
      groupBy: "agent_id",
    });
  });
});