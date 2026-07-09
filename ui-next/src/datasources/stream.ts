import {
  fetchFromGateway,
  type FetchOptions,
} from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";
import type {
  DataFrame,
  Datasource,
  DatasourceCapabilities,
  StreamConnectionStatus,
  StreamEvent,
  StreamRequest,
  StreamSubscription,
  StreamTopic,
} from "./types";

export const STREAM_DATASOURCE_ID = "soc-stream";

const DEFAULT_TOPICS: ReadonlyArray<StreamTopic> = ["ase", "alert", "approval"];

const POLL_PATHS: Record<StreamTopic, string> = {
  ase: "/v1/decisions?limit=30",
  alert: "/v1/alerts?limit=30",
  approval: "/v1/approvals",
};

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const onAbort = () => {
      clearTimeout(timeout);
      resolve();
    };
    const timeout = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

function eventKey(topic: StreamTopic, row: Record<string, unknown>): string {
  for (const name of [
    "event_id",
    "id",
    "approval_id",
    "alert_id",
    "decision_id",
    "action_hash",
  ]) {
    const v = row[name];
    if (typeof v === "string" && v.trim()) return `${topic}:${v}`;
  }
  return `${topic}:${JSON.stringify(row)}`;
}

function eventTs(row: Record<string, unknown>): string {
  for (const name of ["ts", "created_at", "occurred_at", "opened_at"]) {
    const v = row[name];
    if (typeof v === "string" && v.trim()) return v;
  }
  return new Date().toISOString();
}

/**
 * Advisory SOC stream — polling fallback (SSE when gateway supports it later).
 * Invalidates panel queries via useSocStream.
 */
export class SocStreamDatasource implements Datasource {
  readonly id = STREAM_DATASOURCE_ID;
  readonly capabilities: DatasourceCapabilities = {
    query: false,
    stream: true,
    fields: false,
    verify: false,
  };

  private readonly opts: FetchOptions;
  private readonly pollIntervalMs: number;

  constructor(opts: FetchOptions, pollIntervalMs = 5_000) {
    this.opts = opts;
    this.pollIntervalMs = pollIntervalMs;
  }

  query(): Promise<DataFrame> {
    return Promise.resolve({ fields: [], length: 0, meta: { total: 0 } });
  }

  subscribe(
    sub: StreamRequest,
    onEvent: (event: StreamEvent) => void,
    onStatus?: (status: StreamConnectionStatus) => void,
  ): StreamSubscription {
    const controller = new AbortController();
    let closed = false;
    const seen = new Set<string>();
    const topics =
      sub.topics.length > 0 ? sub.topics : [...DEFAULT_TOPICS];

    const pollOnce = async () => {
      for (const topic of topics) {
        if (closed) return;
        try {
          const raw = await fetchFromGateway<unknown>(
            { ...this.opts, signal: controller.signal },
            POLL_PATHS[topic],
          );
          for (const row of asRecordArray(raw)) {
            const key = eventKey(topic, row);
            if (seen.has(key)) continue;
            seen.add(key);
            onEvent({
              topic,
              payload: row,
              ts: eventTs(row),
            });
          }
        } catch {
          if (closed || controller.signal.aborted) return;
        }
      }
    };

    const run = async () => {
      onStatus?.("connecting");
      onStatus?.("polling");
      while (!closed) {
        await pollOnce();
        await sleep(this.pollIntervalMs, controller.signal);
      }
    };

    void run();

    return {
      close: () => {
        closed = true;
        controller.abort();
        onStatus?.("closed");
      },
    };
  }
}
