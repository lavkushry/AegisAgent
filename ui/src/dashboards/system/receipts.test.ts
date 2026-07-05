import { describe, expect, it } from "vitest";

import { RECEIPT_DATASOURCE_ID } from "@/datasources/receipt";
import { receiptsDashboard } from "./receipts";

describe("receiptsDashboard schema", () => {
  it("embeds the receipt-integrity panel on the receipt datasource", () => {
    const panel = receiptsDashboard.layout
      .flatMap((row) => row.panels)
      .find((item) => item.panel.id === "receipt-integrity-log")?.panel;

    expect(panel).toMatchObject({
      type: "receipt-integrity",
      datasourceId: RECEIPT_DATASOURCE_ID,
      entity: "receipt",
      limit: 50,
      options: {
        timeField: "ts",
        prevHashField: "prev_receipt_hash",
      },
    });
  });

  it("does not embed synthetic demo entities in panel queries", () => {
    for (const row of receiptsDashboard.layout) {
      for (const { panel } of row.panels) {
        expect(panel.query).toBeUndefined();
        expect(panel.search).toBeUndefined();
      }
    }
  });
});