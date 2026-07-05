import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import { rowsToFrame } from "@/datasources/frame";
import ReceiptIntegrity from "./ReceiptIntegrity";
import type { PanelDefinition } from "../types";

vi.mock("@/datasources/registry", () => ({
  useDatasources: () =>
    new Map([
      [
        "receipt",
        {
          id: "receipt",
          capabilities: { query: true, stream: false, fields: true, verify: true },
          query: vi.fn(),
          verifyReceipt: vi.fn(),
          verifyRange: vi.fn(),
          exportEvidencePack: vi.fn(),
        },
      ],
    ]),
}));

const definition: PanelDefinition = {
  id: "receipt-test",
  type: "receipt-integrity",
  title: "Per-tenant hash chain",
  datasourceId: "receipt",
  entity: "receipt",
  limit: 50,
};

const receipts = [
  {
    id: "receipt-1",
    ts: "2026-06-28T10:00:00Z",
    agent_id: "agent-a",
    decision: "allow",
    source_trust: "trusted_internal_signed",
    action_hash: "action-hash-1",
    prev_receipt_hash: "",
    receipt_hash: "receipt-hash-1",
  },
];

describe("ReceiptIntegrity panel", () => {
  it("shows fail-closed chain status and verification controls without synthetic link badges", () => {
    const frame = {
      ...rowsToFrame(receipts),
      meta: { cursor: "cursor-1", total: 1 },
    };
    const html = renderToStaticMarkup(
      <ReceiptIntegrity
        definition={definition}
        data={frame}
        timeRange={{ from: "now-24h", to: "now" }}
        variables={{}}
        onDrilldown={() => {}}
      />,
    );

    expect(html).toContain("Chain not yet verified");
    expect(html).toContain("Verify range");
    expect(html).toContain("Verify receipt");
    expect(html).toContain("Load more receipts");
    expect(html).toContain("agent-a");
    expect(html).not.toContain("link:");
    expect(html).not.toContain("text-green-400");
  });
});