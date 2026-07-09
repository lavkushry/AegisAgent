import { DEFAULT_DATASOURCE_ID } from "@/datasources/registry";
import type { DashboardSchema } from "../schema";

/**
 * Detections board — triggered alerts template for the dashboard editor.
 */
export const detectionsDashboard: DashboardSchema = {
  uid: "detections",
  title: "Detections",
  schemaVersion: 1,
  variables: [],
  time: { defaultRange: { from: "now-24h", to: "now" }, refreshSec: 15 },
  layout: [
    {
      id: "vitals",
      panels: [
        {
          panel: {
            id: "stat-alerts",
            type: "stat",
            title: "Active detections",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "soc-summary",
            options: {
              valueField: "alerts_total",
              thresholds: [1, 5],
            },
          },
          w: 3,
          h: 1,
        },
        {
          panel: {
            id: "note-detections",
            type: "note",
            title: "Deterministic rules",
            datasourceId: DEFAULT_DATASOURCE_ID,
            options: {
              body: "Alerts fire from Cedar-aligned detection rules. Use the Detections page for severity filters; Rules for the catalogue.",
            },
          },
          w: 9,
          h: 1,
        },
      ],
    },
    {
      id: "alerts",
      title: "Triggered alerts",
      panels: [
        {
          panel: {
            id: "table-alerts",
            type: "table",
            title: "Alert feed",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "alert",
            limit: 50,
            options: {
              columns: [
                "severity",
                "rule",
                "summary",
                "agent_id",
                "created_at",
              ],
              maxRows: 50,
            },
            drilldowns: [
              {
                label: "Open detections",
                target: { kind: "dashboard", uid: "detections" },
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
