import { describe, expect, it } from "vitest";

import { incidentsDashboard } from "./incidents";

describe("incidentsDashboard schema", () => {
  it("registers the incidents uid and investigation drilldown feed", () => {
    expect(incidentsDashboard.uid).toBe("incidents");
    const panelIds = incidentsDashboard.layout.flatMap((row) => row.panels.map((item) => item.panel.id));
    expect(panelIds).toEqual([
      "stat-open-incidents",
      "stat-open-alerts",
      "stat-pending-approvals",
      "feed-incidents",
    ]);
  });

  it("routes feed rows into the incidents investigation tab", () => {
    const feed = incidentsDashboard.layout
      .flatMap((row) => row.panels)
      .find((item) => item.panel.id === "feed-incidents")?.panel;

    expect(feed?.drilldowns?.[0]?.target).toMatchObject({
      kind: "incident",
      incidentIdField: "id",
    });
  });
});