import {
  GatewayRequestError,
  downloadFromGateway,
  fetchFromGateway,
  type FetchOptions,
} from "../app/api";
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

const RECEIPT_FIELDS: ReadonlyArray<FieldDescriptor> = [
  { name: "created_at", type: "time", facetable: false },
  { name: "tenant_id", type: "string", facetable: false },
  { name: "agent_id", type: "string", facetable: true },
  { name: "decision", type: "decision", facetable: true },
  { name: "source_trust", type: "trust", facetable: true },
  { name: "action_hash", type: "hash", facetable: false },
  { name: "prev_receipt_hash", type: "hash", facetable: false },
  { name: "receipt_hash", type: "hash", facetable: false },
];

export class ReceiptDatasource implements Datasource {
  readonly id = RECEIPT_DATASOURCE_ID;
  readonly capabilities: DatasourceCapabilities = {
    query: false,
    stream: false,
    fields: true,
    verify: true,
  };

  constructor(private readonly opts: FetchOptions) {}

  async query(req: QueryRequest): Promise<DataFrame> {
    const params = new URLSearchParams({ limit: String(req.limit ?? 50) });
    if (req.cursor) params.set("cursor", req.cursor);
    const rows = await fetchFromGateway<Array<Record<string, unknown>>>(
      this.opts,
      `/v1/receipts?${params.toString()}`,
    );
    return rowsToFrame(Array.isArray(rows) ? rows : []);
  }

  fields(): Promise<ReadonlyArray<FieldDescriptor>> {
    return Promise.resolve(RECEIPT_FIELDS);
  }

  async verifyReceipt(receiptId: string): Promise<VerifyResult> {
    const data = await fetchFromGateway<Record<string, unknown>>(
      this.opts,
      `/v1/receipts/${encodeURIComponent(receiptId)}/verify`,
    );
    return normalizeVerification(data);
  }

  async verifyRange(receipts: ReadonlyArray<Record<string, unknown>>): Promise<VerifyResult> {
    const timestamps = receipts
      .map((receipt) => receipt.ts ?? receipt.created_at)
      .filter((value): value is string => typeof value === "string" && !Number.isNaN(Date.parse(value)))
      .sort((left, right) => Date.parse(left) - Date.parse(right));
    const range = timestamps.length > 0
      ? { from: timestamps[0], to: timestamps[timestamps.length - 1] }
      : {};

    try {
      const data = await fetchFromGateway<Record<string, unknown>>(
        this.opts,
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
        this.opts,
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
      const result = await this.verifyReceipt(receiptId);
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

  exportEvidencePack(range: EvidenceExportRange = {}): Promise<Blob> {
    const params = new URLSearchParams();
    if (range.from) params.set("from", range.from);
    if (range.to) params.set("to", range.to);
    const query = params.size > 0 ? `?${params.toString()}` : "";
    return downloadFromGateway(this.opts, `/v1/compliance/evidence-pack${query}`);
  }
}
