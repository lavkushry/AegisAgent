import { DEFAULT_DATASOURCE_ID } from "@/datasources/registry";
import { RECEIPT_DATASOURCE_ID } from "@/datasources/receipt";
import type { DashboardSchema } from "../schema";

/**
 * The integrity dashboard — the three surfaces neither Grafana nor Kibana
 * can show, rendered through the panel framework: the Approval Queue, the
 * Provable Timeline, and the Receipt Integrity viewer.
 */
export const integrityDashboard: DashboardSchema = {
  uid: "integrity",
  title: "Integrity Console",
  schemaVersion: 1,
  variables: [],
  time: { defaultRange: { from: "now-24h", to: "now" }, refreshSec: 5 },
  layout: [
    {
      id: "approvals",
      title: "Approval queue",
      panels: [
        {
          panel: {
            id: "approval-queue",
            type: "approval-card",
            title: "Pending human-in-the-loop approvals",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "approval",
          },
          w: 12,
          h: 5,
        },
      ],
    },
    {
      id: "timeline",
      title: "Provable decision timeline",
      panels: [
        {
          panel: {
            id: "decision-timeline",
            type: "provable-timeline",
            title: "Recent decisions — verify the receipt chain",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "decision",
            options: { labelField: "tool", receiptHashField: "action_hash" },
            drilldowns: [
              { label: "Explore agent", target: { kind: "explore", aqlTemplate: "${agent_id}" } },
            ],
          },
          w: 12,
          h: 4,
        },
      ],
    },
    {
      id: "receipts",
      title: "Receipt integrity",
      panels: [
        {
          panel: {
            id: "receipt-chain",
            type: "receipt-integrity",
            title: "Per-tenant hash chain",
            datasourceId: RECEIPT_DATASOURCE_ID,
            entity: "receipt",
          },
          w: 12,
          h: 4,
        },
      ],
    },
  ],
};
