import {
  fetchFromGateway,
  type FetchOptions,
} from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";

export interface McpServerRecord {
  id?: string;
  server_key: string;
  name?: string;
  owner_team?: string | null;
  transport?: string;
  trust_level?: string;
  endpoint?: string;
  version?: string | null;
  status?: string;
  manifest_hash?: string;
  last_discovery_at?: string | null;
  created_at?: string;
}

export interface McpToolRecord {
  tool_key: string;
  name?: string;
  description?: string | null;
  risk?: string;
  mutates_state?: boolean;
  approval_required?: boolean;
  status?: string;
}

export function listMcpServers(opts: FetchOptions): Promise<McpServerRecord[]> {
  return fetchFromGateway<unknown>(opts, "/v1/mcp/servers").then((raw) =>
    asRecordArray(raw).map((r) => r as unknown as McpServerRecord),
  );
}

export async function listMcpTools(
  opts: FetchOptions,
  serverKey: string,
): Promise<McpToolRecord[]> {
  const raw = await fetchFromGateway<unknown>(
    opts,
    `/v1/mcp/servers/${encodeURIComponent(serverKey)}/tools`,
  );
  if (Array.isArray(raw)) {
    return raw as McpToolRecord[];
  }
  if (
    typeof raw === "object" &&
    raw !== null &&
    Array.isArray((raw as { tools?: unknown }).tools)
  ) {
    return (raw as { tools: McpToolRecord[] }).tools;
  }
  return [];
}

export function quarantineMcpServer(
  opts: FetchOptions,
  serverKey: string,
  reason?: string,
) {
  const body = reason?.trim() ? { reason: reason.trim() } : undefined;
  return fetchFromGateway<McpServerRecord>(
    opts,
    `/v1/mcp/servers/${encodeURIComponent(serverKey)}/quarantine`,
    "POST",
    body,
  );
}

export function restoreMcpServer(
  opts: FetchOptions,
  serverKey: string,
  reason?: string,
) {
  const body = reason?.trim() ? { reason: reason.trim() } : undefined;
  return fetchFromGateway<McpServerRecord>(
    opts,
    `/v1/mcp/servers/${encodeURIComponent(serverKey)}/restore`,
    "POST",
    body,
  );
}
