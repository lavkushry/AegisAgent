import { DEFAULT_DATASOURCE_ID } from "@/datasources/registry";
import type { DashboardSchema } from "../schema";

/**
 * Alerting board — delivery-health oriented template.
 * Webhook CRUD / reactivate remain on the Alerting feature page.
 */
export const alertingDashboard: DashboardSchema = {
  uid: "alerting",
  title: "Alerting",
  schemaVersion: 1,
  variables: [],
  time: { defaultRange: { from: "now-24h", to: "now" }, refreshSec: 30 },
  layout: [
    {
      id: "intro",
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
            drilldowns: [
              {
                label: "Detections",
                target: { kind: "dashboard", uid: "detections" },
              },
            ],
          },
          w: 3,
          h: 1,
        },
        {
          panel: {
            id: "note-alerting",
            type: "note",
            title: "Delivery circuit breaker",
            datasourceId: DEFAULT_DATASOURCE_ID,
            options: {
              body: "Webhook subscriptions can trip dead after consecutive delivery failures. Manage URLs, secrets, and reactivate on the Alerting page.",
            },
          },
          w: 9,
          h: 1,
        },
      ],
    },
    {
      id: "feed",
      title: "Recent alerts",
      panels: [
        {
          panel: {
            id: "table-alerts",
            type: "table",
            title: "Triggered alerts",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "alert",
            limit: 25,
            options: {
              columns: ["severity", "rule", "summary", "agent_id", "created_at"],
              maxRows: 25,
            },
            drilldowns: [
              {
                label: "Open detections",
                target: { kind: "dashboard", uid: "detections" },
              },
            ],
          },
          w: 12,
          h: 4,
        },
      ],
    },
  ],
};
