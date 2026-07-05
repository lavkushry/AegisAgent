import { describe, expect, it } from "vitest";

import { overviewDashboard } from "./overview";

describe("overviewDashboard schema", () => {
  it("declares production vitals fed by gateway snapshots", () => {
    const panelIds = overviewDashboard.layout.flatMap((row) => row.panels.map((item) => item.panel.id));
    expect(panelIds).toEqual(
      expect.arrayContaining([
        "stat-protected-actions",
        "stat-pending-approvals",
        "stat-open-incidents",
        "stat-receipt-chain",
        "feed-incidents",
        "feed-alerts",
      ]),
    );

    const protectedActions = overviewDashboard.layout
      .flatMap((row) => row.panels)
      .find((item) => item.panel.id === "stat-protected-actions")?.panel;
    expect(protectedActions?.snapshot).toBe("tenant-stats");
    expect(protectedActions?.options).toMatchObject({ valueField: "total_decisions" });
    expect(protectedActions?.drilldowns?.length).toBeGreaterThan(0);
  });

  it("does not embed synthetic demo entities in panel queries", () => {
    for (const row of overviewDashboard.layout) {
      for (const { panel } of row.panels) {
        expect(panel.query).toBeUndefined();
        expect(panel.search).toBeUndefined();
      }
    }
  });
});