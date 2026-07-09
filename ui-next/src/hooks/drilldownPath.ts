import type { DrilldownLink } from "@/panels/types";

/**
 * Pure drilldown → SPA path mapping (testable without React Router).
 * Paths are relative to the `/dashboard` basename.
 */
export function resolveDrilldownPath(
  link: DrilldownLink,
  row?: Record<string, unknown>,
): string | null {
  const target = link.target;
  switch (target.kind) {
    case "explore": {
      const aql = interpolate(target.aqlTemplate, row);
      return `/explore?q=${encodeURIComponent(aql)}`;
    }
    case "incident":
      return "/incidents";
    case "dashboard":
      return dashboardUidPath(target.uid);
    case "agent": {
      const id = row?.[target.agentIdField];
      if (id != null && String(id).length > 0) {
        return `/agents/${encodeURIComponent(String(id))}`;
      }
      return "/agents";
    }
    case "receipt":
    case "verify-receipt":
      return "/integrity";
    default:
      return null;
  }
}

function dashboardUidPath(uid: string): string {
  switch (uid) {
    case "approvals":
      return "/approvals";
    case "integrity":
    case "receipts":
      return "/integrity";
    case "incidents":
      return "/incidents";
    case "detections":
      return "/detections";
    case "agents":
    case "fleet":
      return "/agents";
    case "mcp":
      return "/mcp";
    case "rules":
      return "/rules";
    case "alerting":
      return "/alerting";
    case "explore":
      return "/explore";
    case "dashboards":
      return "/dashboards";
    default:
      return "/";
  }
}

export function interpolate(
  template: string,
  row?: Record<string, unknown>,
): string {
  if (!row) return template;
  return template.replace(/\$\{(\w+)\}/g, (_, key: string) =>
    String(row[key] ?? ""),
  );
}
