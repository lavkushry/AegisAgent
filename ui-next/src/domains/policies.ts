import { fetchFromGateway, type FetchOptions } from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";

export interface PolicyRecord {
  id: string;
  policy_key: string;
  name: string;
  language: string;
  body: string;
  version: number;
  status: string;
  created_by?: string | null;
  created_at: string;
}

export interface PolicyAuditLogRecord {
  id: string;
  policy_id?: string | null;
  policy_key?: string | null;
  action: string;
  actor?: string | null;
  created_at: string;
}

export interface CreatePolicyInput {
  policy_key: string;
  name: string;
  body: string;
}

export interface UpdatePolicyInput {
  name?: string;
  body?: string;
  status?: string;
}

export function listPolicies(opts: FetchOptions): Promise<PolicyRecord[]> {
  return fetchFromGateway<unknown>(opts, "/v1/policies").then((raw) =>
    asRecordArray(raw).map((r) => r as unknown as PolicyRecord),
  );
}

export function createPolicy(
  opts: FetchOptions,
  input: CreatePolicyInput,
): Promise<PolicyRecord> {
  return fetchFromGateway<PolicyRecord>(opts, "/v1/policies", "POST", input);
}

export function updatePolicy(
  opts: FetchOptions,
  id: string,
  input: UpdatePolicyInput,
): Promise<PolicyRecord> {
  return fetchFromGateway<PolicyRecord>(
    opts,
    `/v1/policies/${encodeURIComponent(id)}`,
    "PUT",
    input,
  );
}

export function deletePolicy(opts: FetchOptions, id: string): Promise<unknown> {
  return fetchFromGateway(
    opts,
    `/v1/policies/${encodeURIComponent(id)}`,
    "DELETE",
  );
}

export function rollbackPolicy(
  opts: FetchOptions,
  id: string,
): Promise<PolicyRecord> {
  return fetchFromGateway<PolicyRecord>(
    opts,
    `/v1/policies/${encodeURIComponent(id)}/rollback`,
    "POST",
  );
}

export function listPolicyAuditLog(
  opts: FetchOptions,
): Promise<PolicyAuditLogRecord[]> {
  return fetchFromGateway<unknown>(opts, "/v1/policies/audit-log").then((raw) =>
    asRecordArray(raw).map((r) => r as unknown as PolicyAuditLogRecord),
  );
}

export function policyStatusColorVar(status: string): string {
  switch (String(status).toLowerCase()) {
    case "active":
      return "--state-verified";
    case "draft":
      return "--sev-info";
    case "archived":
    case "disabled":
      return "--text-muted";
    default:
      return "--sev-low";
  }
}
