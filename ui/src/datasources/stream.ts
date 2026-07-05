import { buildGatewayHeaders, fetchFromGateway, type FetchOptions } from "../app/api";
import type {
  DataFrame,
  Datasource,
  DatasourceCapabilities,
  StreamEvent,
  StreamRequest,
  StreamSubscription,
  StreamTopic,
} from "./types";

export const STREAM_DATASOURCE_ID = "soc-stream";

export type StreamConnectionStatus = "connecting" | "live" | "polling" | "closed";

export interface StreamDatasourceOptions {
  readonly initialRetryMs?: number;
  readonly maxRetryMs?: number;
  readonly pollIntervalMs?: number;
}

const DEFAULT_STREAM_TOPICS: ReadonlyArray<StreamTopic> = ["ase", "alert", "approval"];
const STREAM_UNSUPPORTED_STATUSES = new Set([404, 405, 501]);
const POLL_PATHS: Record<StreamTopic, string> = {
  ase: "/v1/decisions?limit=50",
  alert: "/v1/alerts?limit=50",
  approval: "/v1/approvals",
};

class StreamHttpError extends Error {
  constructor(readonly status: number) {
    super(`Stream HTTP ${status}`);
    this.name = "StreamHttpError";
  }
}

function withSignal(opts: FetchOptions, signal?: AbortSignal): FetchOptions {
  return signal ? { ...opts, signal } : opts;
}

function isAbortError(error: unknown): boolean {
  return (
    (typeof DOMException !== "undefined" && error instanceof DOMException && error.name === "AbortError") ||
    (error instanceof Error && error.name === "AbortError")
  );
}

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

function subscriptionTopics(sub: StreamRequest): ReadonlyArray<StreamTopic> {
  return sub.topics.length > 0 ? sub.topics : DEFAULT_STREAM_TOPICS;
}

function stringField(row: Record<string, unknown>, names: ReadonlyArray<string>): string | undefined {
  for (const name of names) {
    const value = row[name];
    if (typeof value === "string" && value.trim()) return value;
  }
  return undefined;
}

function polledEventTimestamp(row: Record<string, unknown>): string {
  return stringField(row, ["ts", "created_at", "occurred_at", "opened_at", "updated_at"]) ?? new Date().toISOString();
}

function polledEventKey(topic: StreamTopic, row: Record<string, unknown>): string {
  const stableId = stringField(row, [
    "event_id",
    "id",
    "approval_id",
    "alert_id",
    "decision_id",
    "receipt_hash",
    "action_hash",
  ]);
  if (stableId) return `${topic}:${stableId}`;
  return `${topic}:${JSON.stringify(row)}`;
}

function parseEventBlock(block: string): StreamEvent | null {
  let eventName = "";
  const dataLines: string[] = [];
  for (const line of block.split(/\r?\n/)) {
    if (line.startsWith("event:")) eventName = line.slice(6).trim();
    if (line.startsWith("data:")) dataLines.push(line.slice(5).trimStart());
  }
  if (dataLines.length === 0) return null;
  try {
    const payload = JSON.parse(dataLines.join("\n")) as Record<string, unknown>;
    const topic = (eventName || payload.topic) as StreamTopic;
    if (!["ase", "alert", "approval"].includes(topic)) return null;
    return {
      topic,
      payload: payload.payload ?? payload,
      ts: typeof payload.ts === "string" ? payload.ts : new Date().toISOString(),
    };
  } catch {
    return null;
  }
}

/** Header-authenticated SSE transport with reconnect/backoff and polling status fallback. */
export class SocStreamDatasource implements Datasource {
  readonly id = STREAM_DATASOURCE_ID;
  readonly capabilities: DatasourceCapabilities = {
    query: false,
    stream: true,
    fields: false,
    verify: false,
  };

  constructor(
    private readonly opts: FetchOptions,
    private readonly config: StreamDatasourceOptions = {},
  ) {}

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
    const seenPollingRows = new Set<string>();
    const pollIntervalMs = this.config.pollIntervalMs ?? 5_000;
    const initialRetryMs = this.config.initialRetryMs ?? 1_000;
    const maxRetryMs = this.config.maxRetryMs ?? 30_000;

    const pollOnce = async () => {
      for (const topic of subscriptionTopics(sub)) {
        if (closed) return;
        try {
          const rows = await fetchFromGateway<Array<Record<string, unknown>>>(
            withSignal(this.opts, controller.signal),
            POLL_PATHS[topic],
          );
          if (!Array.isArray(rows)) continue;
          for (const row of rows) {
            const key = polledEventKey(topic, row);
            if (seenPollingRows.has(key)) continue;
            seenPollingRows.add(key);
            onEvent({
              topic,
              payload: row,
              ts: polledEventTimestamp(row),
            });
          }
        } catch (error: unknown) {
          if (closed || isAbortError(error)) return;
        }
      }
    };

    const runPollingFallback = async () => {
      onStatus?.("polling");
      while (!closed) {
        await pollOnce();
        await sleep(pollIntervalMs, controller.signal);
      }
    };

    const connect = async () => {
      let backoffMs = initialRetryMs;
      while (!closed) {
        onStatus?.("connecting");
        try {
          const url = new URL("/v1/soc/stream", `${this.opts.gatewayUrl.replace(/\/+$/, "")}/`);
          subscriptionTopics(sub).forEach((topic) => url.searchParams.append("topic", topic));
          const response = await fetch(url, {
            headers: { ...buildGatewayHeaders(this.opts), Accept: "text/event-stream" },
            signal: controller.signal,
          });
          if (!response.ok || !response.body) throw new StreamHttpError(response.status);
          onStatus?.("live");
          backoffMs = initialRetryMs;
          const reader = response.body.getReader();
          const decoder = new TextDecoder();
          let buffer = "";
          while (!closed) {
            const { done, value } = await reader.read();
            if (done) throw new Error("Stream ended");
            buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, "\n");
            let boundary = buffer.indexOf("\n\n");
            while (boundary >= 0) {
              const event = parseEventBlock(buffer.slice(0, boundary));
              buffer = buffer.slice(boundary + 2);
              if (event) onEvent(event);
              boundary = buffer.indexOf("\n\n");
            }
          }
        } catch (error: unknown) {
          if (closed || isAbortError(error)) break;
          if (error instanceof StreamHttpError && STREAM_UNSUPPORTED_STATUSES.has(error.status)) {
            await runPollingFallback();
            break;
          }
          onStatus?.("polling");
          await pollOnce();
        }
        await sleep(backoffMs, controller.signal);
        backoffMs = Math.min(backoffMs * 2, maxRetryMs);
      }
    };

    void connect();
    return {
      close() {
        closed = true;
        controller.abort();
        onStatus?.("closed");
      },
    };
  }
}

export { parseEventBlock };
