import {
  fetchFromGateway,
  type FetchOptions,
} from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";

export interface AgentRecord {
  id: string;
  agent_key: string;
  name: string;
  environment: string;
  risk_tier: string;
  status: string;
  owner_team?: string | null;
  framework?: string | null;
  model_name?: string | null;
  last_seen_at?: string | null;
  frozen_reason?: string | null;
  force_approval?: boolean;
  created_at?: string;
}

export type AgentControlKind = "freeze" | "unfreeze" | "restore" | "revoke";

const TERMINAL = new Set(["revoked", "deleted"]);

export function listAgents(opts: FetchOptions): Promise<AgentRecord[]> {
  return fetchFromGateway<unknown>(opts, "/v1/agents").then((raw) =>
    asRecordArray(raw).map((r) => r as unknown as AgentRecord),
  );
}

export function getAgent(
  opts: FetchOptions,
  id: string,
): Promise<AgentRecord> {
  return fetchFromGateway<AgentRecord>(
    opts,
    `/v1/agents/${encodeURIComponent(id)}`,
  );
}

export interface AgentToolPermission {
  id?: string;
  tool_key: string;
  created_at?: string;
}

export async function listAgentPermissions(
  opts: FetchOptions,
  agentId: string,
): Promise<AgentToolPermission[]> {
  const raw = await fetchFromGateway<unknown>(
    opts,
    `/v1/agents/${encodeURIComponent(agentId)}/permissions`,
  );
  if (
    typeof raw === "object" &&
    raw !== null &&
    Array.isArray((raw as { permissions?: unknown }).permissions)
  ) {
    return (raw as { permissions: AgentToolPermission[] }).permissions;
  }
  return asRecordArray(raw).map((r) => r as unknown as AgentToolPermission);
}

export function freezeAgent(opts: FetchOptions, id: string, reason?: string) {
  const body = reason?.trim() ? { reason: reason.trim() } : undefined;
  return fetchFromGateway<AgentRecord>(
    opts,
    `/v1/agents/${encodeURIComponent(id)}/freeze`,
    "POST",
    body,
  );
}

export function unfreezeAgent(opts: FetchOptions, id: string, reason?: string) {
  const body = reason?.trim() ? { reason: reason.trim() } : undefined;
  return fetchFromGateway<AgentRecord>(
    opts,
    `/v1/agents/${encodeURIComponent(id)}/unfreeze`,
    "POST",
    body,
  );
}

export function restoreAgent(opts: FetchOptions, id: string, reason?: string) {
  const body = reason?.trim() ? { reason: reason.trim() } : undefined;
  return fetchFromGateway<AgentRecord>(
    opts,
    `/v1/agents/${encodeURIComponent(id)}/restore`,
    "POST",
    body,
  );
}

export function revokeAgent(opts: FetchOptions, id: string, reason?: string) {
  const body = reason?.trim() ? { reason: reason.trim() } : undefined;
  return fetchFromGateway<AgentRecord>(
    opts,
    `/v1/agents/${encodeURIComponent(id)}/revoke`,
    "POST",
    body,
  );
}

/** Client-side control gating (gateway still enforces). */
export function controlDisabledReason(
  kind: AgentControlKind,
  status: string,
): string | null {
  const normalized = String(status).toLowerCase();
  if (TERMINAL.has(normalized)) {
    return kind === "revoke"
      ? "Agent is already permanently revoked or deleted"
      : "Agent is revoked or deleted";
  }
  switch (kind) {
    case "freeze":
      if (normalized === "frozen") return "Agent is already frozen";
      if (normalized === "quarantined")
        return "Quarantined agents must be restored first";
      if (normalized !== "active")
        return `Cannot freeze agent in ${normalized} status`;
      return null;
    case "unfreeze":
      if (normalized !== "frozen")
        return "Only frozen agents can be restored via unfreeze";
      return null;
    case "restore":
      if (normalized !== "quarantined")
        return "Only quarantined agents can be restored";
      return null;
    case "revoke":
      return null;
    default:
      return "Unsupported control";
  }
}

export function statusColorVar(status: string): string {
  switch (String(status).toLowerCase()) {
    case "active":
      return "--state-verified";
    case "frozen":
      return "--sev-low";
    case "quarantined":
      return "--decision-approval";
    case "revoked":
    case "deleted":
      return "--decision-deny";
    default:
      return "--sev-info";
  }
}
