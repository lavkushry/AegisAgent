import { fetchFromGateway, type FetchOptions } from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";

export interface QuarantineRecord {
  id: string;
  target_type: string;
  target_value: string;
  reason?: string | null;
  actor: string;
  status: string;
  incident_id?: string | null;
  created_at: string;
  released_at?: string | null;
  released_by?: string | null;
}

export interface CreateQuarantineInput {
  target_type: string;
  target_value: string;
  actor: string;
  reason?: string;
  incident_id?: string;
}

export const QUARANTINE_PAGE_SIZE = 50;

export function listQuarantine(
  opts: FetchOptions,
  limit = QUARANTINE_PAGE_SIZE,
  offset = 0,
): Promise<QuarantineRecord[]> {
  return fetchFromGateway<unknown>(
    opts,
    `/v1/quarantine?limit=${limit}&offset=${offset}`,
  ).then((raw) =>
    asRecordArray(raw).map((r) => r as unknown as QuarantineRecord),
  );
}

export function getQuarantine(
  opts: FetchOptions,
  id: string,
): Promise<QuarantineRecord> {
  return fetchFromGateway<QuarantineRecord>(
    opts,
    `/v1/quarantine/${encodeURIComponent(id)}`,
  );
}

export function createQuarantine(
  opts: FetchOptions,
  input: CreateQuarantineInput,
): Promise<QuarantineRecord> {
  const body: Record<string, unknown> = {
    target_type: input.target_type,
    target_value: input.target_value,
    actor: input.actor,
  };
  if (input.reason?.trim()) body.reason = input.reason.trim();
  if (input.incident_id?.trim()) body.incident_id = input.incident_id.trim();
  return fetchFromGateway<QuarantineRecord>(opts, "/v1/quarantine", "POST", body);
}

export function releaseQuarantine(
  opts: FetchOptions,
  id: string,
  releasedBy: string,
): Promise<QuarantineRecord> {
  return fetchFromGateway<QuarantineRecord>(
    opts,
    `/v1/quarantine/${encodeURIComponent(id)}/release`,
    "POST",
    { released_by: releasedBy },
  );
}

export const QUARANTINE_TARGET_TYPES = [
  "agent",
  "run",
  "workspace",
  "file",
  "mcp_server",
  "tool",
  "credential",
  "destination",
  "prompt_lineage",
] as const;

export function quarantineStatusColorVar(status: string): string {
  switch (String(status).toLowerCase()) {
    case "active":
      return "--decision-approval";
    case "released":
      return "--state-verified";
    case "deleted":
      return "--text-muted";
    default:
      return "--sev-info";
  }
}
