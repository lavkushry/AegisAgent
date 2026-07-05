import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import { rowsToFrame } from "@/datasources/frame";
import ProvableTimeline from "./ProvableTimeline";
import type { PanelDefinition } from "../types";

vi.mock("@/datasources/registry", () => ({
  useDatasources: () =>
    new Map([
      [
        "receipt",
        {
          id: "receipt",
          capabilities: { query: true, stream: false, fields: true, verify: true },
          verifyRange: vi.fn(),
        },
      ],
    ]),
}));

const definition: PanelDefinition = {
  id: "timeline-test",
  type: "provable-timeline",
  title: "Provable decision timeline",
  datasourceId: "gateway-entity",
  entity: "decision",
  options: {
    labelField: "tool",
    timeField: "timestamp",
    receiptHashField: "receipt_hash",
    prevHashField: "prev_receipt_hash",
  },
};

const events = [
  {
    id: "decision-1",
    timestamp: "2026-06-28T10:00:00Z",
    tool: "github.create_issue",
    agent_id: "agent-a",
    decision: "allow",
    receipt_hash: "receipt-hash-1",
    prev_receipt_hash: "",
  },
  {
    id: "decision-2",
    timestamp: "2026-06-28T11:00:00Z",
    tool: "github.merge_pr",
    agent_id: "agent-a",
    decision: "deny",
    receipt_hash: "receipt-hash-2",
    prev_receipt_hash: "receipt-hash-1",
  },
];

describe("ProvableTimeline panel", () => {
  it("shows fail-closed chain status and ordered linkage without synthetic success badges", () => {
    const html = renderToStaticMarkup(
      <ProvableTimeline
        definition={definition}
        data={rowsToFrame(events)}
        timeRange={{ from: "now-24h", to: "now" }}
        variables={{}}
        onDrilldown={() => {}}
      />,
    );

    expect(html).toContain("Chain not yet verified");
    expect(html).toContain("Verify chain");
    expect(html).toContain("github.create_issue");
    expect(html).toContain("github.merge_pr");
    expect(html).toContain("genesis");
    expect(html).toContain("receipt-hash-1");
    expect(html).toContain("receipt-hash-2");
    expect(html).not.toContain("Tamper-free");
    expect(html).not.toContain("text-green-400");
  });
});