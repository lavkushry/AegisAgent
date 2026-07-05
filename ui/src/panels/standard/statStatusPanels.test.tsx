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

  it("maps receipt_chain_verified booleans to explicit status labels", () => {
    const verified = objectToSingleRowFrame({ receipt_chain_verified: true });
    const unverified = objectToSingleRowFrame({ receipt_chain_verified: false });
    const definition: PanelDefinition = {
      id: "status-test",
      type: "status",
      title: "Receipt chain",
      datasourceId: "gateway-entity",
      options: { field: "receipt_chain_verified", healthyValues: ["true", "verified"] },
    };
    const verifiedHtml = renderToStaticMarkup(
      <StatusPanel definition={definition} data={verified} timeRange={{ from: "now-24h", to: "now" }} variables={{}} onDrilldown={() => {}} />,
    );
    const unverifiedHtml = renderToStaticMarkup(
      <StatusPanel definition={definition} data={unverified} timeRange={{ from: "now-24h", to: "now" }} variables={{}} onDrilldown={() => {}} />,
    );
    expect(verifiedHtml.toLowerCase()).toContain("verified");
    expect(unverifiedHtml.toLowerCase()).toContain("unverified");
  });
});