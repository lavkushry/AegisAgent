import { fetchFromGateway, type FetchOptions } from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";

export interface PromptEventRecord {
  id: string;
  event_id: string;
  run_id?: string | null;
  trace_id?: string | null;
  prompt_hash: string;
  redacted_prompt_preview?: string | null;
  role?: string | null;
  source_trust?: string | null;
  model_provider?: string | null;
  retention_policy?: string | null;
  redaction_status: string;
  created_at: string;
}

export function listPromptEventsForRun(
  opts: FetchOptions,
  runId: string,
  limit = 100,
): Promise<PromptEventRecord[]> {
  return fetchFromGateway<unknown>(
    opts,
    `/v1/runtime/runs/${encodeURIComponent(runId)}/prompt-events?limit=${limit}`,
  ).then((raw) => asRecordArray(raw).map((r) => r as unknown as PromptEventRecord));
}
