import { describe, expect, it } from "vitest";

import { runtimeDashboard } from "./runtime";

describe("runtimeDashboard schema", () => {
  it("is the system runtime timeline surface over ASE", () => {
    expect(runtimeDashboard.uid).toBe("runtime");
    expect(runtimeDashboard.title).toBe("Runtime Timeline");
    const asePanels = runtimeDashboard.layout
      .flatMap((row) => row.panels)
      .map((item) => item.panel)
      .filter((panel) => panel.entity === "ase");
    expect(asePanels.length).toBeGreaterThanOrEqual(2);
    expect(asePanels.some((p) => p.type === "timeseries")).toBe(true);
    expect(asePanels.some((p) => p.type === "feed")).toBe(true);
  });

  it("does not embed synthetic demo query strings", () => {
    for (const row of runtimeDashboard.layout) {
      for (const { panel } of row.panels) {
        expect(panel.query).toBeUndefined();
        expect(panel.search).toBeUndefined();
      }
    }
  });
});
