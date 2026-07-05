import { DEFAULT_DATASOURCE_ID } from "@/datasources/registry";
import type { DashboardSchema } from "../schema";

/**
 * Production incidents dashboard-as-code — open-case posture plus a recent
 * incident feed that drills into the provable investigation workflow tab.
 */
export const incidentsDashboard: DashboardSchema = {
  uid: "incidents",
  title: "Security Incidents",
  schemaVersion: 1,
  variables: [],
  time: { defaultRange: { from: "now-7d", to: "now" }, refreshSec: 10 },
  layout: [
    {
      id: "posture",
      title: "Incident posture",
      panels: [
        {
          panel: {
            id: "stat-open-incidents",
            type: "stat",
            title: "Open incidents",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "soc-summary",
            options: { valueField: "incidents_open", thresholds: [1, 3] },
          },
          w: 4,
          h: 1,
        },
        {
          panel: {
            id: "stat-open-alerts",
            type: "stat",
            title: "Open alerts",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "soc-summary",
            options: { valueField: "alerts_open", thresholds: [1, 5] },
            drilldowns: [
              { label: "View detections", target: { kind: "dashboard", uid: "detections" } },
            ],
          },
          w: 4,
          h: 1,
        },
        {
          panel: {
            id: "stat-pending-approvals",
            type: "stat",
            title: "Pending approvals",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "soc-summary",
            options: { valueField: "approvals_pending", thresholds: [1, 5] },
            drilldowns: [
              { label: "Open approvals", target: { kind: "dashboard", uid: "approvals" } },
            ],
          },
          w: 4,
          h: 1,
        },
      ],
    },
    {
      id: "cases",
      title: "Recent cases",
      panels: [
        {
          panel: {
            id: "feed-incidents",
            type: "feed",
            title: "Incident case feed",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "incident",
            limit: 20,
            options: {
              titleField: "kind",
              detailField: "summary",
              timeField: "opened_at",
              maxRows: 20,
            },
            drilldowns: [
              { label: "Investigate incident", target: { kind: "incident", incidentIdField: "id" } },
            ],
          },
          w: 12,
          h: 4,
        },
      ],
    },
  ],
};