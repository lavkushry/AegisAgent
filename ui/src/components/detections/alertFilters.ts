import type { AlertRecord } from "@/app/api";

export function filterAlerts(
  alerts: AlertRecord[],
  search: string,
  severityFilter: string,
): AlertRecord[] {
  const q = search.trim().toLowerCase();
  const severity = severityFilter.toLowerCase();

  return alerts.filter((alert) => {
    const severityMatch = severity === "all" || alert.severity.toLowerCase() === severity;
    const searchMatch =
      !q ||
      alert.rule.toLowerCase().includes(q) ||
      alert.summary.toLowerCase().includes(q) ||
      alert.agent_id.toLowerCase().includes(q) ||
      alert.alert_id.toLowerCase().includes(q);
    return severityMatch && searchMatch;
  });
}