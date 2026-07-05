import { RECEIPT_DATASOURCE_ID } from "@/datasources/receipt";
import type { DashboardSchema } from "../schema";

/**
 * Receipts Log — the dedicated Receipt Integrity viewer for chain browse,
 * range verify, cursor pagination, and compliance evidence export.
 */
export const receiptsDashboard: DashboardSchema = {
  uid: "receipts",
  title: "Receipts Log",
  schemaVersion: 1,
  variables: [],
  time: { defaultRange: { from: "now-24h", to: "now" }, refreshSec: 5 },
  layout: [
    {
      id: "chain",
      title: "Cryptographic receipt chain",
      panels: [
        {
          panel: {
            id: "receipt-integrity-log",
            type: "receipt-integrity",
            title: "Per-tenant hash chain",
            datasourceId: RECEIPT_DATASOURCE_ID,
            entity: "receipt",
            limit: 50,
            options: {
              timeField: "ts",
              prevHashField: "prev_receipt_hash",
            },
          },
          w: 12,
          h: 6,
        },
      ],
    },
  ],
};