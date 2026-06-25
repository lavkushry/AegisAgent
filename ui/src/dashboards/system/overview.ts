import { DEFAULT_DATASOURCE_ID } from "@/datasources/registry";
import type { DashboardSchema } from "../schema";

/**
 * Curated SOC Overview dashboard, rendered through the panel framework as a
 * proof of the datasource -> PanelRuntime -> panel pipeline. Expanded into
 * the primary Overview surface as more panel types land.
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
      title: "Fleet vital signs",
      panels: [
        {
          panel: {
            id: "stat-incidents",
            type: "stat",
            title: "Open incidents",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "incident",
            options: { thresholds: [1, 5] },
          },
          w: 3,
          h: 1,
        },
        {
          panel: {
            id: "stat-approvals",
            type: "stat",
            title: "Pending approvals",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "approval",
            options: { thresholds: [3, 10] },
          },
          w: 3,
          h: 1,
        },
        {
          panel: {
            id: "stat-agents",
            type: "stat",
            title: "Agents in fleet",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "agent",
          },
          w: 3,
          h: 1,
        },
        {
          panel: {
            id: "stat-mcp",
            type: "stat",
            title: "MCP servers",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "mcp_server",
          },
          w: 3,
          h: 1,
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
            options: {
              columns: ["decision", "tool", "agent_id", "source_trust", "action_hash", "created_at"],
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
