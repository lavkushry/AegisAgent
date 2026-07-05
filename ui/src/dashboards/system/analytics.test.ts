import { describe, expect, it } from "vitest";

import { analyticsDashboard } from "./analytics";

function panelById(id: string) {
  return analyticsDashboard.layout
    .flatMap((row) => row.panels)
    .find((item) => item.panel.id === id)?.panel;
}

describe("analyticsDashboard schema", () => {
  it("declares gateway-backed operational metrics with drilldowns", () => {
    const panelIds = analyticsDashboard.layout.flatMap((row) => row.panels.map((item) => item.panel.id));
    expect(panelIds).toEqual(
      expect.arrayContaining([
        "stat-decisions-24h",
        "stat-deny-rate",
        "ts-all-decisions",
        "table-trust-mix",
        "table-risky-agents",
        "table-denied-tools",
        "table-detection-rules",
        "ts-ase-events",
        "table-mcp-servers",
      ]),
    );

    expect(panelById("stat-deny-rate")?.options).toMatchObject({
      valueField: "deny_rate_today",
      unit: "%",
    });
    expect(panelById("table-risky-agents")?.drilldowns?.length).toBeGreaterThan(0);
  });

  it("labels risky-agent analytics as advisory via note panel", () => {
    expect(panelById("note-risk-advisory")?.options).toMatchObject({ variant: "advisory" });
    expect(panelById("table-risky-agents")?.title).toMatch(/advisory/i);
  });

  it("documents unavailable REST metrics instead of fabricating values", () => {
    for (const id of ["note-mttd", "note-mttc", "note-approval-latency", "note-mcp-drift"]) {
      const panel = panelById(id);
      expect(panel?.type).toBe("note");
      expect(panel?.options).toMatchObject({ variant: "unavailable" });
    }
  });

  it("uses soc-query aggregates for bounded server-side grouping", () => {
    expect(panelById("table-denied-tools")).toMatchObject({
      datasourceId: "soc-query",
      aggregate: "count_by",
      groupBy: "tool",
      query: "decision:deny",
    });
    expect(panelById("ts-ase-events")).toMatchObject({
      entity: "ase",
      aggregate: "count_over_time",
    });
  });

  it("does not embed synthetic demo search filters", () => {
    for (const row of analyticsDashboard.layout) {
      for (const { panel } of row.panels) {
        if (panel.type === "note") continue;
        expect(panel.search).toBeUndefined();
      }
    }
  });
});