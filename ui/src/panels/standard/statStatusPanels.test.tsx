import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import { objectToSingleRowFrame } from "@/datasources/frame";
import StatPanel from "./StatPanel";
import StatusPanel from "./StatusPanel";
import type { PanelDefinition } from "../types";

describe("overview stat and status panels", () => {
  it("reads snapshot counters from single-row frames", () => {
    const frame = objectToSingleRowFrame({ total_decisions: 42, approvals_pending: 2 });
    const definition: PanelDefinition = {
      id: "stat-test",
      type: "stat",
      title: "Protected actions",
      datasourceId: "gateway-entity",
      options: { valueField: "total_decisions" },
    };
    const html = renderToStaticMarkup(
      <StatPanel definition={definition} data={frame} timeRange={{ from: "now-24h", to: "now" }} variables={{}} onDrilldown={() => {}} />,
    );
    expect(html).toContain("42");
  });

  it("maps explicit receipt verify states and defaults missing data to unknown", () => {
    const verified = objectToSingleRowFrame({ receipt_verify_state: "verified" });
    const broken = objectToSingleRowFrame({ receipt_verify_state: "broken" });
    const unknown = objectToSingleRowFrame({});
    const definition: PanelDefinition = {
      id: "status-test",
      type: "status",
      title: "Receipt chain",
      datasourceId: "gateway-entity",
      options: {
        field: "receipt_verify_state",
        healthyValues: ["verified"],
        failedValues: ["broken", "tampered", "failed"],
      },
    };
    const verifiedHtml = renderToStaticMarkup(
      <StatusPanel definition={definition} data={verified} timeRange={{ from: "now-24h", to: "now" }} variables={{}} onDrilldown={() => {}} />,
    );
    const brokenHtml = renderToStaticMarkup(
      <StatusPanel definition={definition} data={broken} timeRange={{ from: "now-24h", to: "now" }} variables={{}} onDrilldown={() => {}} />,
    );
    const unknownHtml = renderToStaticMarkup(
      <StatusPanel definition={definition} data={unknown} timeRange={{ from: "now-24h", to: "now" }} variables={{}} onDrilldown={() => {}} />,
    );
    expect(verifiedHtml.toLowerCase()).toContain("verified");
    expect(brokenHtml.toLowerCase()).toContain("broken");
    expect(unknownHtml.toLowerCase()).toContain("unknown");
  });
});