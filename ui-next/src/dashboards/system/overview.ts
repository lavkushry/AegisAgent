import {
  DEFAULT_DATASOURCE_ID,
  SOC_QUERY_DATASOURCE_ID,
} from "@/datasources/registry";
import type { DashboardSchema } from "../schema";

/**
 * SOC Overview — schema-driven landing board.
 * Snapshots/lists via gateway-entity; decision volume via soc-query timeseries.
 */
export const overviewDashboard: DashboardSchema = {
  uid: "overview",
  title: "SOC Overview",
  schemaVersion: 1,
  variables: [],
  time: { defaultRange: { from: "now-24h", to: "now" }, refreshSec: 10 },
  layout: [
    {
      id: "vitals",
      title: "Tenant posture",
      panels: [
        {
          panel: {
            id: "stat-protected-actions",
            type: "stat",
            title: "Protected actions",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "tenant-stats",
            options: { valueField: "total_decisions" },
            drilldowns: [
              {
                label: "Explore decisions",
                target: { kind: "explore", aqlTemplate: "decision:*" },
              },
            ],
          },
          w: 2,
          h: 1,
        },
        {
          panel: {
            id: "stat-blocked-actions",
            type: "stat",
            title: "Blocked actions",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "tenant-stats",
            options: {
              valueField: "decisions_deny",
              thresholds: [1, 5],
            },
            drilldowns: [
              {
                label: "Explore denials",
                target: { kind: "explore", aqlTemplate: "decision:deny" },
              },
            ],
          },
          w: 2,
          h: 1,
        },
        {
          panel: {
            id: "stat-pending-approvals",
            type: "stat",
            title: "Pending approvals",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "soc-summary",
            options: {
              valueField: "approvals_pending",
              thresholds: [1, 5],
            },
            drilldowns: [
              {
                label: "Open approvals",
                target: { kind: "dashboard", uid: "approvals" },
              },
            ],
          },
          w: 2,
          h: 1,
        },
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
            drilldowns: [
              {
                label: "View incidents",
                target: { kind: "dashboard", uid: "incidents" },
              },
            ],
          },
          w: 2,
          h: 1,
        },
        {
          panel: {
            id: "stat-active-detections",
            type: "stat",
            title: "Active detections",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "soc-summary",
            options: {
              valueField: "alerts_total",
              thresholds: [1, 3],
            },
            drilldowns: [
              {
                label: "View detections",
                target: { kind: "dashboard", uid: "detections" },
              },
            ],
          },
          w: 2,
          h: 1,
        },
        {
          panel: {
            id: "stat-untrusted-sources",
            type: "stat",
            title: "Untrusted sources",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "tenant-stats",
            options: {
              valueField: "untrusted_source_count",
              thresholds: [1, 5],
            },
            drilldowns: [
              {
                label: "Explore untrusted",
                target: {
                  kind: "explore",
                  aqlTemplate: "source_trust:untrusted_external",
                },
              },
            ],
          },
          w: 2,
          h: 1,
        },
      ],
    },
    {
      id: "volume",
      title: "Decision volume",
      panels: [
        {
          panel: {
            id: "ts-decisions",
            type: "timeseries",
            title: "Decisions over time",
            datasourceId: SOC_QUERY_DATASOURCE_ID,
            entity: "decision",
            aggregate: "count_over_time",
            interval: "hour",
            options: {
              timeField: "bucket",
              valueField: "count",
            },
            drilldowns: [
              {
                label: "Explore decisions",
                target: { kind: "explore", aqlTemplate: "decision:*" },
              },
            ],
          },
          w: 12,
          h: 3,
        },
      ],
    },
    {
      id: "facets",
      title: "Decision mix",
      panels: [
        {
          panel: {
            id: "hm-decision",
            type: "heatmap",
            title: "By decision",
            datasourceId: SOC_QUERY_DATASOURCE_ID,
            entity: "decision",
            aggregate: "count_by",
            groupBy: "decision",
            limit: 8,
            options: {
              categoryField: "value",
              valueField: "count",
            },
            drilldowns: [
              {
                label: "Explore denials",
                target: { kind: "explore", aqlTemplate: "decision:deny" },
              },
            ],
          },
          w: 6,
          h: 3,
        },
        {
          panel: {
            id: "hm-trust",
            type: "heatmap",
            title: "By source trust",
            datasourceId: SOC_QUERY_DATASOURCE_ID,
            entity: "decision",
            aggregate: "count_by",
            groupBy: "source_trust",
            limit: 8,
            options: {
              categoryField: "value",
              valueField: "count",
            },
            drilldowns: [
              {
                label: "Explore untrusted",
                target: {
                  kind: "explore",
                  aqlTemplate: "source_trust:untrusted_external",
                },
              },
            ],
          },
          w: 6,
          h: 3,
        },
      ],
    },
    {
      id: "risk",
      title: "Top risk",
      panels: [
        {
          panel: {
            id: "risk-map-top",
            type: "agent-risk-map",
            title: "Riskiest agents (24h, advisory)",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "agent-scoreboard",
            options: { maxRows: 5 },
            drilldowns: [
              {
                label: "Open agent",
                target: { kind: "agent", agentIdField: "agent_id" },
              },
            ],
          },
          w: 12,
          h: 3,
        },
      ],
    },
    {
      id: "feeds",
      title: "Live signals",
      panels: [
        {
          panel: {
            id: "feed-decisions",
            type: "feed",
            title: "Live authorization feed",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "decision",
            limit: 8,
            options: {
              titleField: "decision",
              detailField: "tool",
              timeField: "created_at",
              maxRows: 8,
            },
          },
          w: 6,
          h: 3,
        },
        {
          panel: {
            id: "feed-alerts",
            type: "feed",
            title: "Recent policy alerts",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "alert",
            limit: 5,
            options: {
              titleField: "rule",
              detailField: "summary",
              timeField: "created_at",
              maxRows: 5,
            },
          },
          w: 6,
          h: 3,
        },
      ],
    },
    {
      id: "recent",
      title: "Recent decisions",
      panels: [
        {
          panel: {
            id: "table-decisions",
            type: "table",
            title: "Latest authorization decisions",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "decision",
            limit: 10,
            options: {
              columns: [
                "decision",
                "tool",
                "agent_id",
                "source_trust",
                "action_hash",
                "created_at",
              ],
              maxRows: 10,
            },
          },
          w: 12,
          h: 4,
        },
      ],
    },
  ],
};
