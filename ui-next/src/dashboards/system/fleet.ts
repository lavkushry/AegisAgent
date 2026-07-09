import { DEFAULT_DATASOURCE_ID } from "@/datasources/registry";
import type { DashboardSchema } from "../schema";

/**
 * Fleet board — agent inventory template for the dashboard editor.
 * Freeze/unfreeze and detail remain on the Agents feature pages.
 */
export const fleetDashboard: DashboardSchema = {
  uid: "fleet",
  title: "Agent fleet",
  schemaVersion: 1,
  variables: [],
  time: { defaultRange: { from: "now-24h", to: "now" }, refreshSec: 15 },
  layout: [
    {
      id: "intro",
      panels: [
        {
          panel: {
            id: "note-fleet",
            type: "note",
            title: "Active response",
            datasourceId: DEFAULT_DATASOURCE_ID,
            options: {
              body: "Agent workforce inventory. Use Agents for freeze / unfreeze / revoke controls and per-agent detail. Copy this board to customize columns for your tenant.",
            },
          },
          w: 12,
          h: 1,
        },
      ],
    },
    {
      id: "inventory",
      title: "Registered agents",
      panels: [
        {
          panel: {
            id: "table-agents",
            type: "table",
            title: "Fleet roster",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "agent",
            limit: 50,
            options: {
              columns: [
                "agent_key",
                "name",
                "status",
                "risk_tier",
                "environment",
                "last_seen_at",
              ],
              maxRows: 50,
            },
            drilldowns: [
              {
                label: "Open fleet",
                target: { kind: "agent", agentIdField: "id" },
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
