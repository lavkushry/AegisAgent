import { fetchFromGateway, type FetchOptions } from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";

export interface ModelCallEventRecord {
  id: string;
  event_id: string;
  run_id?: string | null;
  trace_id?: string | null;
  provider: string;
  model: string;
  request_hash?: string | null;
  response_hash?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  token_counts_json?: string | null;
  status: string;
  redaction_status: string;
  received_at: string;
}

export function listModelCallsForRun(
  opts: FetchOptions,
  runId: string,
  limit = 100,
): Promise<ModelCallEventRecord[]> {
  return fetchFromGateway<unknown>(
    opts,
    `/v1/runtime/runs/${encodeURIComponent(runId)}/model-calls?limit=${limit}`,
  ).then((raw) =>
    asRecordArray(raw).map((r) => r as unknown as ModelCallEventRecord),
  );
}

export function modelCallStatusColorVar(status: string): string {
  switch (String(status).toLowerCase()) {
    case "success":
      return "--state-verified";
    case "error":
      return "--decision-deny";
    case "timeout":
    case "cancelled":
      return "--sev-low";
    default:
      return "--sev-info";
  }
}

export function parseTokenCounts(
  tokenCountsJson?: string | null,
): Record<string, number> | null {
  if (!tokenCountsJson) return null;
  try {
    const parsed: unknown = JSON.parse(tokenCountsJson);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
      return null;
    const out: Record<string, number> = {};
    for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof v === "number") out[k] = v;
    }
    return out;
  } catch {
    return null;
  }
}
