import {
  fetchFromGateway,
  type FetchOptions,
} from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";

/** Tenant-owned dashboard schema record (#1634 /v1/soc/dashboards). */
export interface SocDashboardRecord {
  id: string;
  tenant_id: string;
  uid: string;
  title: string;
  schema_version: number;
  schema_json: string;
  created_at: string;
  updated_at: string;
}

function asDashboard(raw: Record<string, unknown>): SocDashboardRecord {
  return {
    id: String(raw.id ?? ""),
    tenant_id: String(raw.tenant_id ?? ""),
    uid: String(raw.uid ?? ""),
    title: String(raw.title ?? ""),
    schema_version: Number(raw.schema_version ?? 1),
    schema_json:
      typeof raw.schema_json === "string"
        ? raw.schema_json
        : JSON.stringify(raw.schema_json ?? {}),
    created_at: String(raw.created_at ?? ""),
    updated_at: String(raw.updated_at ?? ""),
  };
}

export function listSocDashboards(
  opts: FetchOptions,
): Promise<SocDashboardRecord[]> {
  return fetchFromGateway<unknown>(opts, "/v1/soc/dashboards").then((raw) =>
    asRecordArray(raw).map(asDashboard),
  );
}

export function getSocDashboard(
  opts: FetchOptions,
  uid: string,
): Promise<SocDashboardRecord> {
  return fetchFromGateway<Record<string, unknown>>(
    opts,
    `/v1/soc/dashboards/${encodeURIComponent(uid)}`,
  ).then(asDashboard);
}

/** Create persists the DashboardSchema body; gateway returns the record. */
export function createSocDashboard(
  opts: FetchOptions,
  schema: unknown,
): Promise<SocDashboardRecord> {
  return fetchFromGateway<Record<string, unknown>>(
    opts,
    "/v1/soc/dashboards",
    "POST",
    schema,
  ).then(asDashboard);
}

export function updateSocDashboard(
  opts: FetchOptions,
  uid: string,
  schema: unknown,
): Promise<SocDashboardRecord> {
  return fetchFromGateway<Record<string, unknown>>(
    opts,
    `/v1/soc/dashboards/${encodeURIComponent(uid)}`,
    "PUT",
    schema,
  ).then(asDashboard);
}

export function deleteSocDashboard(
  opts: FetchOptions,
  uid: string,
): Promise<Record<string, unknown>> {
  return fetchFromGateway(
    opts,
    `/v1/soc/dashboards/${encodeURIComponent(uid)}`,
    "DELETE",
  );
}
