/**
 * Datasource layer contracts. See
 * docs/AegisAgent_SOC_Console_HLD_LLD.md section 5.1.
 *
 * Every read in the console goes through a Datasource, so panels never
 * know about REST paths or response shapes — they receive a DataFrame.
 */

/** A point in (or span of) time. Relative tokens resolve at query build. */
export interface TimeRange {
  from: string; // ISO 8601 or relative token e.g. "now-24h"
  to: string; // ISO 8601 or "now"
}

/** Resolved variable bag passed into every query. */
export type VariableValues = Readonly<Record<string, string | string[]>>;

export type EntityKind =
  | "ase"
  | "incident"
  | "alert"
  | "approval"
  | "agent"
  | "mcp_server"
  | "receipt"
  | "decision"
  | "rule";

export type FieldType =
  | "time"
  | "number"
  | "string"
  | "trust"
  | "decision"
  | "hash"
  | "json";

export type FieldFormat =
  | "badge"
  | "hash"
  | "link"
  | "relative-time"
  | "bytes"
  | "raw";

/** What a query needs to run. Datasources translate this to a transport call. */
export interface QueryRequest {
  readonly aql?: string;
  readonly entity?: EntityKind;
  readonly timeRange: TimeRange;
  readonly variables: VariableValues;
  readonly limit?: number;
  readonly cursor?: string;
  readonly search?: string;
  /** Aggregate mode — when set, the datasource returns a bucketed series. */
  readonly aggregate?: "count" | "count_over_time" | "count_by";
  /** Bucket granularity for count_over_time ("minute" | "hour" | "day"). */
  readonly interval?: string;
  /** Allowlisted field used only with the count_by aggregate. */
  readonly groupBy?: "agent_id" | "decision" | "source_trust" | "tool" | "action";
  readonly signal?: AbortSignal;
}

export interface Field {
  readonly name: string;
  readonly type: FieldType;
  readonly values: ReadonlyArray<unknown>;
  readonly format?: FieldFormat;
}

/** Columnar result — panels read frames, not bespoke shapes. */
export interface DataFrame {
  readonly fields: ReadonlyArray<Field>;
  readonly length: number;
  readonly meta?: {
    total?: number;
    cursor?: string;
    executedMs?: number;
    fieldDescriptors?: ReadonlyArray<FieldDescriptor>;
  };
}

/** Field catalog for the Explore field sidebar + AQL autocomplete. */
export interface FieldDescriptor {
  readonly name: string;
  readonly type: FieldType;
  readonly facetable: boolean;
  readonly examples?: ReadonlyArray<string>;
}

export interface DatasourceCapabilities {
  readonly query: boolean;
  readonly stream: boolean;
  readonly fields: boolean;
  readonly verify: boolean;
}

export interface VerifyResult {
  readonly status: "verified" | "failed" | "unknown";
  readonly ok: boolean;
  readonly brokenAtRow?: number;
  readonly message: string;
  readonly chainHead?: string;
}

export interface EvidenceExportRange {
  readonly from?: string;
  readonly to?: string;
}

export type StreamTopic = "ase" | "alert" | "approval";

export interface StreamRequest {
  readonly topics: ReadonlyArray<StreamTopic>;
  readonly variables: VariableValues;
}

export interface StreamEvent {
  readonly topic: StreamTopic;
  readonly payload: unknown;
  readonly ts: string;
}

export interface StreamSubscription {
  close(): void;
}

/** The uniform datasource interface. */
export interface Datasource {
  readonly id: string;
  readonly capabilities: DatasourceCapabilities;
  query(req: QueryRequest): Promise<DataFrame>;
  fields?(entity: EntityKind): Promise<ReadonlyArray<FieldDescriptor>>;
  verifyReceipt?(receiptId: string, signal?: AbortSignal): Promise<VerifyResult>;
  verifyRange?(receipts: ReadonlyArray<Record<string, unknown>>, signal?: AbortSignal): Promise<VerifyResult>;
  exportEvidencePack?(range?: EvidenceExportRange, signal?: AbortSignal): Promise<Blob>;
  subscribe?(
    sub: StreamRequest,
    onEvent: (e: StreamEvent) => void,
  ): StreamSubscription;
}
