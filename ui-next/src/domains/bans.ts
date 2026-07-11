import { fetchFromGateway, type FetchOptions } from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";

export interface BanRecord {
  id: string;
  target_type: string;
  target_value: string;
  scope: string;
  reason?: string | null;
  actor: string;
  status: string;
  created_at: string;
  expires_at?: string | null;
  revoked_at?: string | null;
  revoked_by?: string | null;
}

export interface CreateBanInput {
  target_type: string;
  target_value: string;
  scope: string;
  actor: string;
  reason?: string;
  expires_at?: string;
}

export function listBans(opts: FetchOptions): Promise<BanRecord[]> {
  return fetchFromGateway<unknown>(opts, "/v1/bans").then((raw) =>
    asRecordArray(raw).map((r) => r as unknown as BanRecord),
  );
}

export function getBan(opts: FetchOptions, id: string): Promise<BanRecord> {
  return fetchFromGateway<BanRecord>(opts, `/v1/bans/${encodeURIComponent(id)}`);
}

export function createBan(
  opts: FetchOptions,
  input: CreateBanInput,
): Promise<BanRecord> {
  const body: Record<string, unknown> = {
    target_type: input.target_type,
    target_value: input.target_value,
    scope: input.scope,
    actor: input.actor,
  };
  if (input.reason?.trim()) body.reason = input.reason.trim();
  if (input.expires_at?.trim()) body.expires_at = input.expires_at.trim();
  return fetchFromGateway<BanRecord>(opts, "/v1/bans", "POST", body);
}

export function revokeBan(
  opts: FetchOptions,
  id: string,
  revokedBy: string,
): Promise<BanRecord> {
  return fetchFromGateway<BanRecord>(
    opts,
    `/v1/bans/${encodeURIComponent(id)}/revoke`,
    "POST",
    { revoked_by: revokedBy },
  );
}

export const BAN_SCOPES = ["run", "agent", "tenant", "organization"] as const;
export const BAN_TARGET_TYPES = [
  "agent",
  "run",
  "sandbox",
  "fingerprint",
  "destination",
  "tool",
] as const;

export function banStatusColorVar(status: string): string {
  switch (String(status).toLowerCase()) {
    case "active":
      return "--decision-deny";
    case "revoked":
      return "--text-muted";
    default:
      return "--sev-info";
  }
}
