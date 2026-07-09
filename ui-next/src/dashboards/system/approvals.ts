import { DEFAULT_DATASOURCE_ID } from "@/datasources/registry";
import type { DashboardSchema } from "../schema";

/**
 * Approvals board — pending HITL queue template.
 * Approve / reject / edit remain on the Approvals feature page.
 */
export const approvalsDashboard: DashboardSchema = {
  uid: "approvals",
  title: "Approvals",
  schemaVersion: 1,
  variables: [],
  time: { defaultRange: { from: "now-24h", to: "now" }, refreshSec: 10 },
  layout: [
    {
      id: "queue",
      title: "Pending queue",
      panels: [
        {
          panel: {
            id: "stat-pending",
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
          w: 3,
          h: 1,
        },
        {
          panel: {
            id: "note-approval-integrity",
            type: "note",
            title: "Approval integrity",
            datasourceId: DEFAULT_DATASOURCE_ID,
            options: {
              body: "Each approval binds to a frozen action_hash (aegis-jcs-1). Edits re-hash and re-evaluate. Use the Approvals page with an Operator ID to act.",
            },
          },
          w: 9,
          h: 1,
        },
      ],
    },
    {
      id: "list",
      title: "Queue rows",
      panels: [
        {
          panel: {
            id: "table-approvals",
            type: "table",
            title: "Pending approvals",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "approval",
            limit: 50,
            options: {
              columns: [
                "approval_id",
                "agent_id",
                "tool_name",
                "source_trust",
                "status",
                "action_hash",
              ],
              maxRows: 50,
            },
            drilldowns: [
              {
                label: "Open approvals",
                target: { kind: "dashboard", uid: "approvals" },
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
