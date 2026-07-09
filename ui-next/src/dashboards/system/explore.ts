import { DEFAULT_DATASOURCE_ID } from "@/datasources/registry";
import type { DashboardSchema } from "../schema";

/**
 * Explore board — decision-search oriented template.
 * Full AQL editor lives on the Explore feature page.
 */
export const exploreDashboard: DashboardSchema = {
  uid: "explore",
  title: "Explore",
  schemaVersion: 1,
  variables: [],
  time: { defaultRange: { from: "now-24h", to: "now" }, refreshSec: 20 },
  layout: [
    {
      id: "intro",
      panels: [
        {
          panel: {
            id: "note-explore",
            type: "note",
            title: "AQL search",
            datasourceId: DEFAULT_DATASOURCE_ID,
            options: {
              body: "Decision search uses AND-only AQL (OR is fail-closed). Open Explore for the live query bar; copy this board for a fixed decision table layout.",
            },
          },
          w: 12,
          h: 1,
        },
      ],
    },
    {
      id: "results",
      title: "Recent decisions",
      panels: [
        {
          panel: {
            id: "table-decisions",
            type: "table",
            title: "Decision stream",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "decision",
            limit: 50,
            options: {
              columns: [
                "decision",
                "tool",
                "action",
                "agent_id",
                "source_trust",
                "action_hash",
                "ts",
              ],
              maxRows: 50,
            },
            drilldowns: [
              {
                label: "Open Explore",
                target: {
                  kind: "explore",
                  aqlTemplate: "decision:*",
                },
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
