import { DEFAULT_DATASOURCE_ID } from "@/datasources/registry";
import type { DashboardSchema } from "../schema";

/**
 * Incidents board — open cases template for the dashboard editor.
 */
export const incidentsDashboard: DashboardSchema = {
  uid: "incidents",
  title: "Incidents",
  schemaVersion: 1,
  variables: [],
  time: { defaultRange: { from: "now-7d", to: "now" }, refreshSec: 20 },
  layout: [
    {
      id: "vitals",
      panels: [
        {
          panel: {
            id: "stat-open-incidents",
            type: "stat",
            title: "Open incidents",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "soc-summary",
            options: {
              valueField: "incidents_open",
              thresholds: [1, 3],
            },
          },
          w: 3,
          h: 1,
        },
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
            id: "note-incidents",
            type: "note",
            title: "Case management",
            datasourceId: DEFAULT_DATASOURCE_ID,
            options: {
              body: "Correlated SOC cases with evidence packs. Open the Incidents page for detail, narrative, and ZIP export.",
            },
          },
          w: 6,
          h: 1,
        },
      ],
    },
    {
      id: "cases",
      title: "Cases",
      panels: [
        {
          panel: {
            id: "table-incidents",
            type: "table",
            title: "Incident list",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "incident",
            limit: 50,
            options: {
              columns: [
                "id",
                "kind",
                "severity",
                "status",
                "summary",
                "agent_id",
                "opened_at",
              ],
              maxRows: 50,
            },
            drilldowns: [
              {
                label: "Open incidents",
                target: { kind: "incident", incidentIdField: "id" },
              },
            ],
          },
          w: 6,
          h: 5,
        },
        {
          panel: {
            id: "graph-latest-incident",
            type: "decision-graph",
            title: "Evidence graph (latest case)",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "incident",
            limit: 1,
            options: {
              scopeKind: "incident",
              scopeIdField: "id",
              maxNodes: 40,
            },
            drilldowns: [
              {
                label: "Open incidents",
                target: { kind: "incident", incidentIdField: "id" },
              },
            ],
          },
          w: 6,
          h: 5,
        },
      ],
    },
  ],
};
