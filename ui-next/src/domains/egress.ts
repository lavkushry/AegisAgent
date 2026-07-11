import { fetchFromGateway, type FetchOptions } from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";
import type { BanRecord } from "@/domains/bans";

export interface EgressEventRecord {
  id: string;
  event_id: string;
  event_type: string;
  severity?: string | null;
  agent_id?: string | null;
  run_id?: string | null;
  decision?: string | null;
  reason?: string | null;
  observed_at: string;
}

export interface BlockEgressInput {
  destination: string;
  actor: string;
  reason?: string;
  expires_at?: string;
}

/**
 * First page only (no `x-next-cursor` follow-up yet) — matches the
 * simplicity of the rest of the console's list pages; cursoring past the
 * first `limit` is a follow-up if egress volume needs it.
 */
export function listEgressEvents(
  opts: FetchOptions,
  limit = 100,
): Promise<EgressEventRecord[]> {
  return fetchFromGateway<unknown>(
    opts,
    `/v1/egress/events?limit=${limit}`,
  ).then((raw) => asRecordArray(raw).map((r) => r as unknown as EgressEventRecord));
}

export function blockEgress(
  opts: FetchOptions,
  input: BlockEgressInput,
): Promise<BanRecord> {
  const body: Record<string, unknown> = {
    destination: input.destination,
    actor: input.actor,
  };
  if (input.reason?.trim()) body.reason = input.reason.trim();
  if (input.expires_at?.trim()) body.expires_at = input.expires_at.trim();
  return fetchFromGateway<BanRecord>(opts, "/v1/egress/block", "POST", body);
}

export function unblockEgress(
  opts: FetchOptions,
  banId: string,
  revokedBy: string,
): Promise<BanRecord> {
  return fetchFromGateway<BanRecord>(opts, "/v1/egress/unblock", "POST", {
    ban_id: banId,
    revoked_by: revokedBy,
  });
}

export function egressDecisionColorVar(decision?: string | null): string {
  switch (String(decision ?? "").toLowerCase()) {
    case "deny":
    case "blocked":
      return "--decision-deny";
    case "allow":
    case "allowed":
      return "--state-verified";
    default:
      return "--sev-info";
  }
}
