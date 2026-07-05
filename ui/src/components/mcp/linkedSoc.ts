import type { AlertRecord, IncidentRecord } from "@/app/api";

export function alertsForMcpServer(
  alerts: ReadonlyArray<AlertRecord>,
  serverKey: string,
): AlertRecord[] {
  const needle = serverKey.toLowerCase();
  return alerts.filter((alert) => {
    const rule = alert.rule?.toLowerCase() ?? "";
    const summary = alert.summary?.toLowerCase() ?? "";
    return (
      rule.includes("mcp_manifest") ||
      rule.includes("mcp") ||
      summary.includes(needle) ||
      summary.includes("manifest drift")
    );
  });
}

export function incidentsForMcpServer(
  incidents: ReadonlyArray<IncidentRecord>,
  serverKey: string,
): IncidentRecord[] {
  const needle = serverKey.toLowerCase();
  return incidents.filter((incident) => {
    const summary = incident.summary?.toLowerCase() ?? "";
    const kind = incident.kind?.toLowerCase() ?? "";
    return summary.includes(needle) || kind.includes("mcp");
  });
}