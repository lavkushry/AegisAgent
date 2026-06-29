import { DEFAULT_DATASOURCE_ID } from "@/datasources/registry";
import type { DashboardSchema } from "../schema";

export const approvalsDashboard: DashboardSchema = {
  uid: "approvals",
  title: "Approval Queue",
  schemaVersion: 1,
  variables: [],
  time: { defaultRange: { from: "now-24h", to: "now" }, refreshSec: 5 },
  layout: [
    {
      id: "approval-queue",
      title: "Human-in-the-loop action authorization",
      panels: [
        {
          panel: {
            id: "pending-approvals",
            type: "approval-card",
            title: "Frozen actions awaiting review",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "approval",
          },
          w: 12,
          h: 7,
        },
      ],
    },
  ],
};
