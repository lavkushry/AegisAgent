import { DEFAULT_DATASOURCE_ID } from "@/datasources/registry";
import type { DashboardSchema } from "../schema";

/**
 * Rules board — detection rule catalogue template.
 * Live Rules page owns filtering and backtest simulator.
 */
export const rulesDashboard: DashboardSchema = {
  uid: "rules",
  title: "Rules",
  schemaVersion: 1,
  variables: [],
  time: { defaultRange: { from: "now-24h", to: "now" }, refreshSec: 60 },
  layout: [
    {
      id: "intro",
      panels: [
        {
          panel: {
            id: "note-rules",
            type: "note",
            title: "Deterministic catalogue",
            datasourceId: DEFAULT_DATASOURCE_ID,
            options: {
              body: "SOC and detection rules that fire alerts. Open the Rules page for full catalogue detail; Detections for triggered alerts.",
            },
          },
          w: 12,
          h: 1,
        },
      ],
    },
    {
      id: "catalog",
      title: "Rule catalogue",
      panels: [
        {
          panel: {
            id: "table-rules",
            type: "table",
            title: "Detection rules",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "rule",
            limit: 100,
            options: {
              columns: [
                "rule_key",
                "name",
                "severity",
                "enabled",
                "source",
              ],
              maxRows: 100,
            },
            drilldowns: [
              {
                label: "Open rules",
                target: { kind: "dashboard", uid: "rules" },
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
