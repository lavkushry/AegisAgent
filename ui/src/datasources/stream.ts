import { buildGatewayHeaders, type FetchOptions } from "../app/api";
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

  constructor(private readonly opts: FetchOptions) {}

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

    const connect = async () => {
      let backoffMs = 1_000;
      while (!closed) {
        onStatus?.("connecting");
        try {
          const url = new URL("/v1/soc/stream", `${this.opts.gatewayUrl.replace(/\/+$/, "")}/`);
          sub.topics.forEach((topic) => url.searchParams.append("topic", topic));
          const response = await fetch(url, {
            headers: { ...buildGatewayHeaders(this.opts), Accept: "text/event-stream" },
            signal: controller.signal,
          });
          if (!response.ok || !response.body) throw new Error(`Stream HTTP ${response.status}`);
          onStatus?.("live");
          backoffMs = 1_000;
          const reader = response.body.getReader();
          const decoder = new TextDecoder();
          let buffer = "";
          while (!closed) {
            const { done, value } = await reader.read();
            if (done) break;
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
          if (closed || (error instanceof DOMException && error.name === "AbortError")) break;
          onStatus?.("polling");
        }
        await new Promise((resolve) => setTimeout(resolve, backoffMs));
        backoffMs = Math.min(backoffMs * 2, 30_000);
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
