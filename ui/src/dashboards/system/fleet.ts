import { DEFAULT_DATASOURCE_ID } from "@/datasources/registry";
import type { DashboardSchema } from "../schema";

/**
 * The Fleet dashboard — agent inventory as dashboards-as-code. Replaces the
 * bespoke AgentsTab; freeze/restore Active Response lives in the agent-table
 * panel (role-gated; the gateway enforces server-side).
 */
export const fleetDashboard: DashboardSchema = {
  uid: "fleet",
  title: "Agents Fleet",
  schemaVersion: 1,
  variables: [],
  time: { defaultRange: { from: "now-24h", to: "now" }, refreshSec: 5 },
  layout: [
    {
      id: "fleet-vitals",
      panels: [
        {
          panel: {
            id: "stat-agents-total",
            type: "stat",
            title: "Registered agents",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "agent",
          },
          w: 3,
          h: 1,
        },
        {
          panel: {
            id: "stat-mcp-total",
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
      id: "fleet-inventory",
      title: "Fleet inventory",
      panels: [
        {
          panel: {
            id: "agent-inventory",
            type: "agent-table",
            title: "Agents — status, risk, and Active Response",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "agent",
          },
          w: 12,
          h: 5,
        },
      ],
    },
  ],
};
