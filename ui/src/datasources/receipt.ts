import {
  GatewayRequestError,
  downloadFromGateway,
  fetchFromGateway,
  type FetchOptions,
} from "../app/api";
import { fieldsForEntity } from "./fieldCatalog";
import { rowsToFrame } from "./frame";
import { normalizeVerification } from "./receiptVerification";
import type {
  DataFrame,
  Datasource,
  DatasourceCapabilities,
  EvidenceExportRange,
  FieldDescriptor,
  QueryRequest,
  VerifyResult,
} from "./types";

export const RECEIPT_DATASOURCE_ID = "receipt";

function withSignal(opts: FetchOptions, signal?: AbortSignal): FetchOptions {
  return signal ? { ...opts, signal } : opts;
}

export class ReceiptDatasource implements Datasource {
  readonly id = RECEIPT_DATASOURCE_ID;
  readonly capabilities: DatasourceCapabilities = {
    query: true,
    stream: false,
    fields: true,
    verify: true,
  };

  constructor(private readonly opts: FetchOptions) {}

  async query(req: QueryRequest): Promise<DataFrame> {
    const params = new URLSearchParams({ limit: String(req.limit ?? 50) });
    if (req.cursor) params.set("cursor", req.cursor);
    const rows = await fetchFromGateway<Array<Record<string, unknown>>>(
      withSignal(this.opts, req.signal),
      `/v1/receipts?${params.toString()}`,
    );
    return rowsToFrame(Array.isArray(rows) ? rows : []);
  }

  fields(): Promise<ReadonlyArray<FieldDescriptor>> {
    return Promise.resolve(fieldsForEntity("receipt"));
  }

  async verifyReceipt(receiptId: string, signal?: AbortSignal): Promise<VerifyResult> {
    const data = await fetchFromGateway<Record<string, unknown>>(
      withSignal(this.opts, signal),
      `/v1/receipts/${encodeURIComponent(receiptId)}/verify`,
    );
    return normalizeVerification(data);
  }

  async verifyRange(receipts: ReadonlyArray<Record<string, unknown>>, signal?: AbortSignal): Promise<VerifyResult> {
    const timestamps = receipts
      .map((receipt) => receipt.ts ?? receipt.created_at)
      .filter((value): value is string => typeof value === "string" && !Number.isNaN(Date.parse(value)))
      .sort((left, right) => Date.parse(left) - Date.parse(right));
    const range = timestamps.length > 0
      ? { from: timestamps[0], to: timestamps[timestamps.length - 1] }
      : {};

    try {
      const data = await fetchFromGateway<Record<string, unknown>>(
        withSignal(this.opts, signal),
        "/v1/receipts/verify-range",
        "POST",
        range,
      );
      return normalizeVerification(data);
    } catch (error: unknown) {
      if (!(error instanceof GatewayRequestError) || ![404, 405, 501].includes(error.status)) {
        throw error;
      }
    }

    try {
      const data = await fetchFromGateway<Record<string, unknown>>(
        withSignal(this.opts, signal),
        "/v1/receipts/verify-chain",
        "POST",
        { receipts },
      );
      return normalizeVerification(data);
    } catch (error: unknown) {
      if (!(error instanceof GatewayRequestError) || ![404, 405, 501].includes(error.status)) {
        throw error;
      }
    }

    for (let index = 0; index < receipts.length; index += 1) {
      const receiptId = receipts[index].id;
      if (typeof receiptId !== "string" || !receiptId) {
        return {
          status: "unknown",
          ok: false,
          brokenAtRow: index + 1,
          message: `Receipt at row ${index + 1} has no ID for fallback verification.`,
        };
      }
      const result = await this.verifyReceipt(receiptId, signal);
      if (result.status !== "verified") {
        return { ...result, brokenAtRow: result.brokenAtRow ?? index + 1 };
      }
    }
    return {
      status: "verified",
      ok: true,
      message: `${receipts.length} receipts explicitly verified by the gateway.`,
    };
  }

  exportEvidencePack(range: EvidenceExportRange = {}, signal?: AbortSignal): Promise<Blob> {
    const params = new URLSearchParams();
    if (range.from) params.set("from", range.from);
    if (range.to) params.set("to", range.to);
    const query = params.size > 0 ? `?${params.toString()}` : "";
    return downloadFromGateway(withSignal(this.opts, signal), `/v1/compliance/evidence-pack${query}`);
  }
}
