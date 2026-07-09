import type { DashboardSchema } from "../schema";
import {
  approvalsDashboard,
  fleetDashboard,
  incidentsDashboard,
  integrityDashboard,
  overviewDashboard,
} from "../system";
import type { PanelType } from "@/panels/types";

/** UIDs reserved for version-controlled system dashboards — tenants cannot claim them. */
export const RESERVED_SYSTEM_UIDS = [
  "overview",
  "dashboards",
  "integrity",
  "explore",
  "incidents",
  "detections",
  "rules",
  "alerting",
  "approvals",
  "agents",
  "mcp",
  "receipts",
  "analytics",
  "settings",
  "fleet",
  "runtime",
] as const;

export const ALLOWED_PANEL_TYPES: readonly PanelType[] = [
  "stat",
  "timeseries",
  "table",
  "agent-table",
  "heatmap",
  "status",
  "feed",
  "note",
  "provable-timeline",
  "approval-card",
  "receipt-integrity",
  "agent-risk-map",
  "decision-graph",
];

export const ALLOWED_DATASOURCE_IDS = [
  "gateway-entity",
  "soc-query",
  "receipt",
] as const;

export const ALLOWED_ENTITIES = [
  "ase",
  "incident",
  "alert",
  "approval",
  "agent",
  "mcp_server",
  "receipt",
  "decision",
  "rule",
] as const;

export const ALLOWED_SNAPSHOTS = [
  "tenant-stats",
  "soc-summary",
  "agent-scoreboard",
  "trust-breakdown",
] as const;

export const ALLOWED_AGGREGATES = ["count_over_time", "count_by"] as const;

export const ALLOWED_GROUP_BY = [
  "agent_id",
  "decision",
  "source_trust",
  "tool",
  "action",
] as const;

export const ALLOWED_DRILLDOWN_KINDS = [
  "explore",
  "dashboard",
  "incident",
  "receipt",
  "verify-receipt",
  "agent",
] as const;

export interface SystemDashboardEntry {
  readonly uid: string;
  readonly title: string;
  readonly schema: DashboardSchema;
  readonly readOnly: true;
}

/** Built-in dashboards shipped as typed JSON — copy-only in the editor. */
export const SYSTEM_DASHBOARD_CATALOG: readonly SystemDashboardEntry[] = [
  {
    uid: overviewDashboard.uid,
    title: overviewDashboard.title,
    schema: overviewDashboard,
    readOnly: true,
  },
  {
    uid: integrityDashboard.uid,
    title: integrityDashboard.title,
    schema: integrityDashboard,
    readOnly: true,
  },
  {
    uid: fleetDashboard.uid,
    title: fleetDashboard.title,
    schema: fleetDashboard,
    readOnly: true,
  },
  {
    uid: approvalsDashboard.uid,
    title: approvalsDashboard.title,
    schema: approvalsDashboard,
    readOnly: true,
  },
  {
    uid: incidentsDashboard.uid,
    title: incidentsDashboard.title,
    schema: incidentsDashboard,
    readOnly: true,
  },
];

export function copySystemDashboardAsTenant(
  uid: string,
  newUid: string,
  newTitle?: string,
): DashboardSchema | null {
  const entry = SYSTEM_DASHBOARD_CATALOG.find((d) => d.uid === uid);
  if (!entry) return null;
  return {
    ...entry.schema,
    uid: newUid,
    title: newTitle ?? `${entry.title} (copy)`,
  };
}
