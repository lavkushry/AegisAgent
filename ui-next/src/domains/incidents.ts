import {
  downloadFromGateway,
  fetchFromGateway,
  type FetchOptions,
} from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";

export interface IncidentRecord {
  id: string;
  kind?: string;
  summary?: string;
  severity?: string;
  status?: string;
  agent_id?: string;
  opened_at?: string;
  closed_at?: string | null;
}

export function listIncidents(
  opts: FetchOptions,
  limit = 50,
): Promise<IncidentRecord[]> {
  return fetchFromGateway<unknown>(
    opts,
    `/v1/incidents?limit=${limit}`,
  ).then((raw) =>
    asRecordArray(raw).map((r) => r as unknown as IncidentRecord),
  );
}

export function getIncident(
  opts: FetchOptions,
  id: string,
): Promise<IncidentRecord> {
  return fetchFromGateway<IncidentRecord>(
    opts,
    `/v1/incidents/${encodeURIComponent(id)}`,
  );
}

/** Per-incident ZIP evidence pack (#1189). */
export function downloadIncidentEvidencePack(
  opts: FetchOptions,
  incidentId: string,
): Promise<Blob> {
  return downloadFromGateway(
    opts,
    `/v1/incidents/${encodeURIComponent(incidentId)}/evidence-pack`,
  );
}

export function severityColorVar(severity: string | undefined): string {
  switch (String(severity ?? "").toLowerCase()) {
    case "critical":
      return "--sev-critical";
    case "high":
      return "--sev-high";
    case "medium":
      return "--sev-medium";
    case "low":
      return "--sev-low";
    default:
      return "--sev-info";
  }
}
