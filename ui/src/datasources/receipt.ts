import { GatewayRequestError, fetchFromGateway, type FetchOptions } from "../app/api";
import { rowsToFrame } from "./frame";
import { normalizeVerification } from "./receiptVerification";
import type {
  DataFrame,
  Datasource,
  DatasourceCapabilities,
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

  async verifyRange(receiptIds: ReadonlyArray<string>): Promise<VerifyResult> {
    try {
      const data = await fetchFromGateway<Record<string, unknown>>(
        this.opts,
        "/v1/receipts/verify-range",
        "POST",
        { receipt_ids: receiptIds },
      );
      return normalizeVerification(data);
    } catch (error: unknown) {
      if (!(error instanceof GatewayRequestError) || ![404, 405, 501].includes(error.status)) {
        throw error;
      }
      for (let index = 0; index < receiptIds.length; index += 1) {
        const result = await this.verifyReceipt(receiptIds[index]);
        if (result.status !== "verified") {
          return { ...result, brokenAtRow: result.brokenAtRow ?? index + 1 };
        }
      }
      return {
        status: "verified",
        ok: true,
        message: `${receiptIds.length} receipts explicitly verified by the gateway.`,
      };
    }
  }
}
