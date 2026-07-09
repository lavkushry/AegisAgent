import {
  fetchFromGateway,
  type FetchOptions,
} from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";
import { severityColorVar } from "@/domains/incidents";

export interface AlertRecord {
  id: string;
  alert_id?: string;
  rule?: string;
  severity?: string;
  summary?: string;
  agent_id?: string;
  created_at?: string;
  occurred_at?: string;
  source_event_id?: string;
}

export function listAlerts(
  opts: FetchOptions,
  limit = 50,
): Promise<AlertRecord[]> {
  return fetchFromGateway<unknown>(opts, `/v1/alerts?limit=${limit}`).then(
    (raw) => asRecordArray(raw).map((r) => r as unknown as AlertRecord),
  );
}

export { severityColorVar };

export function filterAlerts(
  rows: AlertRecord[],
  query: string,
  severity: string,
): AlertRecord[] {
  const q = query.trim().toLowerCase();
  return rows.filter((row) => {
    if (severity && String(row.severity ?? "").toLowerCase() !== severity) {
      return false;
    }
    if (!q) return true;
    const hay = [
      row.summary,
      row.rule,
      row.agent_id,
      row.alert_id,
      row.id,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    return hay.includes(q);
  });
}
