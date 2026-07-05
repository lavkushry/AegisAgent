import { DEFAULT_DATASOURCE_ID } from "@/datasources/registry";
import type { DashboardSchema } from "../schema";

/**
 * Production SOC Overview — the default landing dashboard. All panels read
 * through GatewayEntityDatasource; no synthetic fallback values.
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
          w: 3,
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
          w: 3,
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
          w: 3,
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
              field: "receipt_chain_verified",
              healthyValues: ["true", "verified"],
              failedValues: ["broken", "tampered", "failed"],
            },
            drilldowns: [
              { label: "Receipt integrity", target: { kind: "dashboard", uid: "integrity" } },
            ],
          },
          w: 3,
          h: 1,
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
              columns: ["agent_id", "avg_risk_score", "trend"],
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
      id: "feeds",
      title: "Live signals",
      panels: [
        {
          panel: {
            id: "feed-incidents",
            type: "feed",
            title: "Recent security incidents",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "incident",
            limit: 5,
            options: {
              titleField: "kind",
              detailField: "summary",
              timeField: "opened_at",
              maxRows: 5,
            },
            drilldowns: [
              { label: "Open incident", target: { kind: "incident", incidentIdField: "id" } },
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