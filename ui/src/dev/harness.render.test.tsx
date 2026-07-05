import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import StatPanel from "@/panels/standard/StatPanel";
import TablePanel from "@/panels/standard/TablePanel";
import ProvableTimeline from "@/panels/differentiators/ProvableTimeline";
import ReceiptIntegrity from "@/panels/differentiators/ReceiptIntegrity";
import { HARNESS_SCENARIOS, HARNESS_TIME_RANGE } from "./scenarios";

vi.mock("@/datasources/registry", () => ({
  useDatasources: () =>
    new Map([
      [
        "receipt",
        {
          id: "receipt",
          capabilities: { query: true, stream: false, fields: true, verify: true },
          verifyReceipt: vi.fn(),
          verifyRange: vi.fn(),
          exportEvidencePack: vi.fn(),
        },
      ],
    ]),
}));

const noop = () => {};

describe("harness panel smoke renders", () => {
  it("renders representative stat, table, and integrity scenarios", () => {
    const stat = HARNESS_SCENARIOS.find((s) => s.id === "stat-success");
    const table = HARNESS_SCENARIOS.find((s) => s.id === "table-success");
    const receipt = HARNESS_SCENARIOS.find((s) => s.id === "receipt-success");
    const timeline = HARNESS_SCENARIOS.find((s) => s.id === "timeline-unknown");

    expect(stat?.definition && stat.frame).toBeTruthy();
    const statHtml = renderToStaticMarkup(
      <StatPanel
        definition={stat!.definition!}
        data={stat!.frame!}
        timeRange={HARNESS_TIME_RANGE}
        variables={{}}
        onDrilldown={noop}
      />,
    );
    expect(statHtml).toContain("128");

    const tableHtml = renderToStaticMarkup(
      <TablePanel
        definition={table!.definition!}
        data={table!.frame!}
        timeRange={HARNESS_TIME_RANGE}
        variables={{}}
        onDrilldown={noop}
      />,
    );
    expect(tableHtml).toContain("agent-harness-a");

    const receiptHtml = renderToStaticMarkup(
      <ReceiptIntegrity
        definition={receipt!.definition!}
        data={receipt!.frame!}
        timeRange={HARNESS_TIME_RANGE}
        variables={{}}
        onDrilldown={noop}
      />,
    );
    expect(receiptHtml).toContain("Chain not yet verified");
    expect(receiptHtml).not.toContain("text-green-400");

    const timelineHtml = renderToStaticMarkup(
      <ProvableTimeline
        definition={timeline!.definition!}
        data={timeline!.frame!}
        timeRange={HARNESS_TIME_RANGE}
        variables={{}}
        onDrilldown={noop}
      />,
    );
    expect(timelineHtml).toContain("Chain not yet verified");
    expect(timelineHtml).not.toContain("Tamper-free");
  });
});