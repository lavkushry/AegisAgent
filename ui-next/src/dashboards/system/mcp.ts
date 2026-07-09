import { DEFAULT_DATASOURCE_ID } from "@/datasources/registry";
import type { DashboardSchema } from "../schema";

/**
 * MCP registry board — server inventory template for the dashboard editor.
 * Quarantine / tools / manifest history remain on the MCP feature page.
 */
export const mcpDashboard: DashboardSchema = {
  uid: "mcp",
  title: "MCP registry",
  schemaVersion: 1,
  variables: [],
  time: { defaultRange: { from: "now-24h", to: "now" }, refreshSec: 30 },
  layout: [
    {
      id: "intro",
      panels: [
        {
          panel: {
            id: "note-mcp",
            type: "note",
            title: "Manifest integrity",
            datasourceId: DEFAULT_DATASOURCE_ID,
            options: {
              body: "Registered MCP servers with pinned manifest hashes. Use the MCP page to inspect tools, history, and quarantine / restore.",
            },
          },
          w: 12,
          h: 1,
        },
      ],
    },
    {
      id: "servers",
      title: "Servers",
      panels: [
        {
          panel: {
            id: "table-mcp-servers",
            type: "table",
            title: "MCP servers",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "mcp_server",
            limit: 50,
            options: {
              columns: [
                "server_key",
                "name",
                "status",
                "trust_level",
                "transport",
                "manifest_hash",
              ],
              maxRows: 50,
            },
            drilldowns: [
              {
                label: "Open MCP",
                target: { kind: "dashboard", uid: "mcp" },
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
