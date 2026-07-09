import { DEFAULT_DATASOURCE_ID } from "@/datasources/registry";
import type { DashboardSchema } from "../schema";

/**
 * Integrity board — receipt hash-chain surface (read-only system template).
 * Live verify/export controls remain on the Integrity feature page.
 */
export const integrityDashboard: DashboardSchema = {
  uid: "integrity",
  title: "Integrity",
  schemaVersion: 1,
  variables: [],
  time: { defaultRange: { from: "now-24h", to: "now" }, refreshSec: 30 },
  layout: [
    {
      id: "intro",
      panels: [
        {
          panel: {
            id: "note-integrity",
            type: "note",
            title: "Receipt chain",
            datasourceId: DEFAULT_DATASOURCE_ID,
            options: {
              body: "Verifiable hash-chained action receipts. Use the Integrity page controls to verify range or export evidence packs. This board is a copyable template for tenant dashboards.",
            },
          },
          w: 12,
          h: 1,
        },
      ],
    },
    {
      id: "receipts",
      title: "Recent receipts",
      panels: [
        {
          panel: {
            id: "table-receipts",
            type: "table",
            title: "Receipt log",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "receipt",
            limit: 25,
            options: {
              columns: [
                "id",
                "decision",
                "agent_id",
                "source_trust",
                "receipt_hash",
                "prev_receipt_hash",
                "ts",
              ],
              maxRows: 25,
            },
            drilldowns: [
              {
                label: "Open Integrity",
                target: { kind: "verify-receipt", receiptIdField: "id" },
              },
            ],
          },
          w: 12,
          h: 5,
        },
      ],
    },
  ],
};
