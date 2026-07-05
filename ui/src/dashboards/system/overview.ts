import { DEFAULT_DATASOURCE_ID } from "@/datasources/registry";
import { SOC_QUERY_DATASOURCE_ID } from "@/datasources/socQuery";
import type { DashboardSchema } from "../schema";

/**
 * Production SOC Overview — the default landing dashboard. All panels read
 * through gateway datasources; no synthetic fallback values.
 */
export const overviewDashboard: DashboardSchema = {
  uid: "overview",
  title: "SOC Overview",
  schemaVersion: 1,
  variables: [],
  time: { defaultRange: { from: "now-24h", to: "now" }, refreshSec: 5 },
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
              { label: "Explore decisions", target: { kind: "explore", aqlTemplate: "decision:*" } },
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
            options: { valueField: "decisions_deny", thresholds: [1, 5] },
            drilldowns: [
              { label: "Explore denials", target: { kind: "explore", aqlTemplate: "decision:deny" } },
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
            options: { valueField: "approvals_pending", thresholds: [1, 5] },
            drilldowns: [
              { label: "Open approvals", target: { kind: "dashboard", uid: "approvals" } },
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
            options: { valueField: "incidents_open", thresholds: [1, 3] },
            drilldowns: [
              { label: "View incidents", target: { kind: "dashboard", uid: "incidents" } },
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
            options: { valueField: "alerts_total", thresholds: [1, 3] },
            drilldowns: [
              { label: "View detections", target: { kind: "dashboard", uid: "detections" } },
            ],
          },
          w: 2,
          h: 1,
        },
        {
          panel: {
            id: "stat-receipt-chain",
            type: "status",
            title: "Receipt chain",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "tenant-stats",
            options: {
              field: "receipt_verify_state",
              healthyValues: ["verified"],
              failedValues: ["broken", "tampered", "failed"],
            },
            drilldowns: [
              { label: "Receipt integrity", target: { kind: "dashboard", uid: "integrity" } },
            ],
          },
          w: 2,
          h: 1,
        },
      ],
    },
    {
      id: "trust",
      title: "Trust provenance (advisory)",
      panels: [
        {
          panel: {
            id: "stat-untrusted-sources",
            type: "stat",
            title: "Untrusted source decisions",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "tenant-stats",
            options: { valueField: "untrusted_source_count", thresholds: [1, 5] },
            drilldowns: [
              {
                label: "Explore untrusted",
                target: { kind: "explore", aqlTemplate: "source_trust:untrusted_external" },
              },
            ],
          },
          w: 3,
          h: 1,
        },
        {
          panel: {
            id: "table-trust-distribution",
            type: "table",
            title: "Trust level distribution",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "trust-breakdown",
            options: {
              columns: ["trust_level", "count"],
              maxRows: 6,
            },
            drilldowns: [
              {
                label: "Explore trust level",
                target: { kind: "explore", aqlTemplate: "source_trust:${trust_level}" },
              },
            ],
          },
          w: 9,
          h: 2,
        },
      ],
    },
    {
      id: "volume",
      title: "Decision volume and agent posture",
      panels: [
        {
          panel: {
            id: "ts-decisions",
            type: "timeseries",
            title: "Decision rate over 24 hours",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "decision",
            aggregate: "count_over_time",
            interval: "hour",
            drilldowns: [
              { label: "Explore decisions", target: { kind: "explore", aqlTemplate: "decision:*" } },
            ],
          },
          w: 8,
          h: 3,
        },
        {
          panel: {
            id: "table-risky-agents",
            type: "table",
            title: "Top risky agents (advisory)",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "agent-scoreboard",
            options: {
              columns: ["agent_id", "current_avg_risk_score", "trend"],
              maxRows: 5,
            },
            drilldowns: [
              { label: "Explore agent", target: { kind: "explore", aqlTemplate: "agent_id:${agent_id}" } },
              { label: "Agents fleet", target: { kind: "dashboard", uid: "agents" } },
            ],
          },
          w: 4,
          h: 3,
        },
      ],
    },
    {
      id: "denials",
      title: "Denials and latest incident",
      panels: [
        {
          panel: {
            id: "table-denies-by-agent",
            type: "table",
            title: "Denies by agent (24h)",
            datasourceId: SOC_QUERY_DATASOURCE_ID,
            entity: "decision",
            query: "decision:deny",
            aggregate: "count_by",
            groupBy: "agent_id",
            limit: 8,
            options: {
              columns: ["agent_id", "count"],
              maxRows: 8,
            },
            drilldowns: [
              { label: "Explore agent denials", target: { kind: "explore", aqlTemplate: "agent_id:${agent_id} decision:deny" } },
            ],
          },
          w: 6,
          h: 3,
        },
        {
          panel: {
            id: "feed-latest-incident",
            type: "feed",
            title: "Latest incident",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "incident",
            limit: 1,
            options: {
              titleField: "kind",
              detailField: "summary",
              timeField: "opened_at",
              maxRows: 1,
            },
            drilldowns: [
              { label: "Open incident", target: { kind: "incident", incidentIdField: "id" } },
              { label: "All incidents", target: { kind: "dashboard", uid: "incidents" } },
            ],
          },
          w: 6,
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
            drilldowns: [
              { label: "Explore agent", target: { kind: "explore", aqlTemplate: "agent_id:${agent_id}" } },
            ],
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
            drilldowns: [
              { label: "View detections", target: { kind: "dashboard", uid: "detections" } },
              { label: "Explore agent", target: { kind: "explore", aqlTemplate: "agent_id:${agent_id}" } },
            ],
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
              columns: ["decision", "tool", "agent_id", "source_trust", "action_hash", "created_at"],
              maxRows: 10,
            },
            drilldowns: [
              { label: "Explore agent", target: { kind: "explore", aqlTemplate: "agent_id:${agent_id}" } },
            ],
          },
          w: 12,
          h: 4,
        },
      ],
    },
  ],
};