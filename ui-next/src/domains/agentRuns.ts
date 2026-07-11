import { fetchFromGateway, type FetchOptions } from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";

export interface AgentRunRecord {
  id: string;
  agent_id?: string | null;
  run_key: string;
  source_component: string;
  mode: string;
  status: string;
  started_at: string;
  finished_at?: string | null;
  root_trace_id?: string | null;
  root_trust_level?: string | null;
  policy_bundle_id?: string | null;
  claimed_by?: string | null;
}

export interface AuditEventRecord {
  id: string;
  event_type: string;
  agent_id?: string | null;
  run_id?: string | null;
  skill?: string | null;
  action?: string | null;
  resource?: string | null;
  decision_id?: string | null;
  created_at?: string;
}

export interface RuntimeEventRecord {
  id: string;
  event_id: string;
  event_type: string;
  severity?: string | null;
  agent_id?: string | null;
  run_id?: string | null;
  source_component: string;
  decision?: string | null;
  reason?: string | null;
  observed_at: string;
}

export type RunControlKind = "pause" | "resume" | "kill" | "quarantine";

export const AGENT_RUNS_PAGE_SIZE = 50;

export function listAgentRuns(
  opts: FetchOptions,
  limit = AGENT_RUNS_PAGE_SIZE,
  offset = 0,
): Promise<AgentRunRecord[]> {
  return fetchFromGateway<unknown>(
    opts,
    `/v1/agent-cage/runs?limit=${limit}&offset=${offset}`,
  ).then((raw) => asRecordArray(raw).map((r) => r as unknown as AgentRunRecord));
}

export function getAgentRun(
  opts: FetchOptions,
  id: string,
): Promise<AgentRunRecord> {
  return fetchFromGateway<AgentRunRecord>(
    opts,
    `/v1/agent-cage/runs/${encodeURIComponent(id)}`,
  );
}

export function controlAgentRun(
  opts: FetchOptions,
  id: string,
  kind: RunControlKind,
  actor: string,
  reason?: string,
): Promise<unknown> {
  const body: Record<string, unknown> = { actor };
  if (reason?.trim()) body.reason = reason.trim();
  return fetchFromGateway(
    opts,
    `/v1/agent-cage/runs/${encodeURIComponent(id)}/${kind}`,
    "POST",
    body,
  );
}

export function getRunTimeline(
  opts: FetchOptions,
  runId: string,
): Promise<AuditEventRecord[]> {
  return fetchFromGateway<unknown>(
    opts,
    `/v1/runs/${encodeURIComponent(runId)}/timeline`,
  ).then((raw) => asRecordArray(raw).map((r) => r as unknown as AuditEventRecord));
}

export function listRunEvents(
  opts: FetchOptions,
  runId: string,
): Promise<RuntimeEventRecord[]> {
  return fetchFromGateway<unknown>(
    opts,
    `/v1/runtime/runs/${encodeURIComponent(runId)}/events`,
  ).then((raw) =>
    asRecordArray(raw).map((r) => r as unknown as RuntimeEventRecord),
  );
}

/** Client-side control gating (gateway still enforces). */
export function runControlDisabledReason(
  kind: RunControlKind,
  status: string,
): string | null {
  const normalized = String(status).toLowerCase();
  const TERMINAL = new Set(["killed", "finished", "quarantined", "stalled"]);
  if (TERMINAL.has(normalized)) {
    return `Run is already ${normalized}`;
  }
  switch (kind) {
    case "pause":
      if (normalized === "paused") return "Run is already paused";
      return null;
    case "resume":
      if (normalized !== "paused") return "Only paused runs can be resumed";
      return null;
    case "kill":
    case "quarantine":
      return null;
    default:
      return "Unsupported control";
  }
}

export function runStatusColorVar(status: string): string {
  switch (String(status).toLowerCase()) {
    case "started":
    case "claimed":
    case "running":
      return "--state-verified";
    case "paused":
      return "--sev-low";
    case "quarantined":
      return "--decision-approval";
    case "killed":
    case "stalled":
      return "--decision-deny";
    case "finished":
      return "--text-muted";
    default:
      return "--sev-info";
  }
}
