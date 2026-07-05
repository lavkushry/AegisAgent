import { afterEach, describe, expect, it, vi } from "vitest";

import { parseEventBlock, SocStreamDatasource } from "./stream";

const options = {
  gatewayUrl: "http://gateway.test",
  bearerToken: "token",
  tenantId: "tenant-a",
};

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("SOC stream parsing", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("parses typed SSE events", () => {
    expect(
      parseEventBlock('event: approval\ndata: {"payload":{"id":"approval-1"},"ts":"2026-06-28T00:00:00Z"}'),
    ).toEqual({
      topic: "approval",
      payload: { id: "approval-1" },
      ts: "2026-06-28T00:00:00Z",
    });
  });

  it("ignores malformed and unknown events", () => {
    expect(parseEventBlock("event: unknown\ndata: {}" as string)).toBeNull();
    expect(parseEventBlock("event: alert\ndata: not-json" as string)).toBeNull();
  });

  it("falls back to real tenant-scoped polling when SSE is unsupported", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response("", { status: 404, statusText: "Not Found" }))
      .mockResolvedValueOnce(jsonResponse([
        { approval_id: "approval-1", created_at: "2026-07-05T07:30:00Z", status: "created" },
      ]));
    vi.stubGlobal("fetch", fetchMock);
    const onEvent = vi.fn();
    const onStatus = vi.fn();

    const subscription = new SocStreamDatasource(options, { pollIntervalMs: 5_000 }).subscribe(
      { topics: ["approval"], variables: {} },
      onEvent,
      onStatus,
    );

    await vi.waitFor(() => expect(onEvent).toHaveBeenCalledTimes(1));
    subscription.close();

    expect(onEvent).toHaveBeenCalledWith({
      topic: "approval",
      payload: { approval_id: "approval-1", created_at: "2026-07-05T07:30:00Z", status: "created" },
      ts: "2026-07-05T07:30:00Z",
    });
    expect(onStatus.mock.calls.map(([status]) => status)).toEqual(
      expect.arrayContaining(["connecting", "polling", "closed"]),
    );
    expect(String(fetchMock.mock.calls[0][0])).toBe("http://gateway.test/v1/soc/stream?topic=approval");
    expect(fetchMock.mock.calls[0][1]?.headers).toMatchObject({
      Accept: "text/event-stream",
      Authorization: "Bearer token",
      "X-Aegis-Tenant-ID": "tenant-a",
    });
    expect(fetchMock.mock.calls[1][0]).toBe("http://gateway.test/v1/approvals");
    expect(fetchMock.mock.calls[1][1]?.headers).toMatchObject({
      Accept: "application/json",
      Authorization: "Bearer token",
      "X-Aegis-Tenant-ID": "tenant-a",
    });
  });

  it("deduplicates replayed rows while polling", async () => {
    vi.useFakeTimers();
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response("", { status: 501, statusText: "Not Implemented" }))
      .mockResolvedValueOnce(jsonResponse([{ id: "approval-1", created_at: "2026-07-05T07:30:00Z" }]))
      .mockResolvedValueOnce(jsonResponse([
        { id: "approval-1", created_at: "2026-07-05T07:30:00Z" },
        { id: "approval-2", created_at: "2026-07-05T07:31:00Z" },
      ]));
    vi.stubGlobal("fetch", fetchMock);
    const onEvent = vi.fn();

    const subscription = new SocStreamDatasource(options, { pollIntervalMs: 1_000 }).subscribe(
      { topics: ["approval"], variables: {} },
      onEvent,
    );

    await vi.waitFor(() => expect(onEvent).toHaveBeenCalledTimes(1));
    await vi.advanceTimersByTimeAsync(1_000);
    await vi.waitFor(() => expect(onEvent).toHaveBeenCalledTimes(2));
    subscription.close();

    expect(onEvent.mock.calls.map(([event]) => event.payload.id)).toEqual(["approval-1", "approval-2"]);
  });
});
