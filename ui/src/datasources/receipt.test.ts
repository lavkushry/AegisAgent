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
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({}, 404))
      .mockResolvedValueOnce(jsonResponse({}, 404))
      .mockResolvedValueOnce(jsonResponse({ verified: true }))
      .mockResolvedValueOnce(jsonResponse({ verified: false, error: "hash mismatch" }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await new ReceiptDatasource(options).verifyRange(receipts);

    expect(result).toMatchObject({ status: "failed", ok: false, brokenAtRow: 2 });
    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect(fetchMock.mock.calls[2][0]).toBe(
      "http://127.0.0.1:8080/v1/receipts/receipt-1/verify",
    );
  });

  it("downloads authoritative evidence from the gateway compliance endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(new Blob(["zip"]), {
        status: 200,
        headers: { "Content-Type": "application/zip" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const blob = await new ReceiptDatasource(options).exportEvidencePack();

    expect(blob.type).toBe("application/zip");
    expect(fetchMock.mock.calls[0][0]).toBe(
      "http://127.0.0.1:8080/v1/compliance/evidence-pack",
    );
  });
});
