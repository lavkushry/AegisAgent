import { DEFAULT_DATASOURCE_ID } from "@/datasources/registry";
import type { DashboardSchema } from "../schema";

/**
 * Integrity board — receipt hash-chain surface (system template).
 * receipt-integrity: chain summary + verify-range + evidence exports.
 * provable-timeline: per-row verify of the linked receipt list.
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
              body: "Verifiable hash-chained action receipts (aegis-jcs-1). Verify range and export evidence packs above; walk the timeline below for per-link Verify.",
            },
          },
          w: 12,
          h: 1,
        },
      ],
    },
    {
      id: "controls",
      title: "Chain integrity",
      panels: [
        {
          panel: {
            id: "integrity-controls",
            type: "receipt-integrity",
            title: "Verify & export",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "receipt",
            limit: 50,
            options: {
              showExports: true,
              showRangeVerify: true,
            },
          },
          w: 12,
          h: 3,
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
              // Range verify lives on the receipt-integrity panel above.
              showRangeVerify: false,
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
