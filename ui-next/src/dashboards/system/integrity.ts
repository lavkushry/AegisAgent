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
              body: "Verifiable hash-chained action receipts. Verify chain / per-row Verify below; export evidence packs on the Integrity page. This board is a copyable template for tenant dashboards.",
            },
          },
          w: 12,
          h: 1,
        },
      ],
    },
    {
      id: "timeline",
      title: "Provable timeline",
      panels: [
        {
          panel: {
            id: "timeline-receipts",
            type: "provable-timeline",
            title: "Hash-chained receipts",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "receipt",
            limit: 25,
            options: {
              maxRows: 25,
              showRangeVerify: true,
            },
            drilldowns: [
              {
                label: "Open Integrity",
                target: { kind: "verify-receipt", receiptIdField: "id" },
              },
            ],
          },
          w: 12,
          h: 6,
        },
      ],
    },
  ],
};
