import { afterEach, describe, expect, it, vi } from "vitest";

import { ReceiptDatasource } from "./receipt";

const options = {
  gatewayUrl: "http://127.0.0.1:8080",
  bearerToken: "secret-token",
  tenantId: "tenant-a",
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    statusText: status === 404 ? "Not Found" : undefined,
    headers: { "Content-Type": "application/json" },
  });
}

const receipts = [
  { id: "receipt-1", tenant_id: "tenant-a", ts: "2026-06-28T10:00:00Z", receipt_hash: "hash-1", prev_receipt_hash: "" },
  { id: "receipt-2", tenant_id: "tenant-a", ts: "2026-06-28T11:00:00Z", receipt_hash: "hash-2", prev_receipt_hash: "hash-1" },
];

describe("ReceiptDatasource", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("uses the gateway stored-range endpoint with the visible time bounds", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ verified: true }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await new ReceiptDatasource(options).verifyRange(receipts);

    expect(result.status).toBe("verified");
    expect(fetchMock.mock.calls[0][0]).toBe(
      "http://127.0.0.1:8080/v1/receipts/verify-range",
    );
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({
      from: "2026-06-28T10:00:00Z",
      to: "2026-06-28T11:00:00Z",
    });
  });

  it("surfaces X-Next-Cursor pagination from receipt list responses", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(receipts.slice(0, 1)), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "x-next-cursor": "cursor-99",
        },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const frame = await new ReceiptDatasource(options).query({
      entity: "receipt",
      timeRange: { from: "now-24h", to: "now" },
      variables: {},
      limit: 1,
    });

    expect(frame.length).toBe(1);
    expect(frame.meta?.cursor).toBe("cursor-99");
    expect(fetchMock.mock.calls[0][0]).toContain("/v1/receipts?limit=1");
  });

  it("forwards cursor tokens when requesting subsequent receipt pages", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(receipts));
    vi.stubGlobal("fetch", fetchMock);

    await new ReceiptDatasource(options).query({
      entity: "receipt",
      timeRange: { from: "now-24h", to: "now" },
      variables: {},
      cursor: "cursor-42",
    });

    expect(fetchMock.mock.calls[0][0]).toContain("cursor=cursor-42");
  });

  it("propagates query abort signals to receipt list reads", async () => {
    const controller = new AbortController();
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(receipts));
    vi.stubGlobal("fetch", fetchMock);

    await new ReceiptDatasource(options).query({
      entity: "receipt",
      timeRange: { from: "now-24h", to: "now" },
      variables: {},
      signal: controller.signal,
    });

    expect(fetchMock.mock.calls[0][1]?.signal).toBe(controller.signal);
  });

  it("falls back to caller-supplied chain verification when stored-range verification is unavailable", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({}, 404))
      .mockResolvedValueOnce(jsonResponse({ verified: true }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await new ReceiptDatasource(options).verifyRange(receipts);

    expect(result.status).toBe("verified");
    expect(fetchMock.mock.calls[1][0]).toBe(
      "http://127.0.0.1:8080/v1/receipts/verify-chain",
    );
    expect(JSON.parse(String(fetchMock.mock.calls[1][1]?.body))).toEqual({ receipts });
  });

  it("falls back to explicit per-receipt verification only when both range endpoints are unavailable", async () => {
    const controller = new AbortController();
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({}, 404))
      .mockResolvedValueOnce(jsonResponse({}, 404))
      .mockResolvedValueOnce(jsonResponse({ verified: true }))
      .mockResolvedValueOnce(jsonResponse({ verified: false, error: "hash mismatch" }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await new ReceiptDatasource(options).verifyRange(receipts, controller.signal);

    expect(result).toMatchObject({ status: "failed", ok: false, brokenAtRow: 2 });
    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect(fetchMock.mock.calls[2][0]).toBe(
      "http://127.0.0.1:8080/v1/receipts/receipt-1/verify",
    );
    expect(fetchMock.mock.calls[0][1]?.signal).toBe(controller.signal);
    expect(fetchMock.mock.calls[1][1]?.signal).toBe(controller.signal);
    expect(fetchMock.mock.calls[2][1]?.signal).toBe(controller.signal);
  });

  it("downloads authoritative evidence from the gateway compliance endpoint", async () => {
    const controller = new AbortController();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(new Blob(["zip"]), {
        status: 200,
        headers: { "Content-Type": "application/zip" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const blob = await new ReceiptDatasource(options).exportEvidencePack({}, controller.signal);

    expect(blob.type).toBe("application/zip");
    expect(fetchMock.mock.calls[0][0]).toBe(
      "http://127.0.0.1:8080/v1/compliance/evidence-pack",
    );
    expect(fetchMock.mock.calls[0][1]?.signal).toBe(controller.signal);
  });

  it("returns receipt integrity field descriptors from the shared catalog", async () => {
    await expect(new ReceiptDatasource(options).fields()).resolves.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "receipt_hash", type: "hash", facetable: false }),
        expect.objectContaining({ name: "prev_receipt_hash", type: "hash", facetable: false }),
        expect.objectContaining({ name: "agent_id", type: "string", facetable: true }),
      ]),
    );
  });
});
