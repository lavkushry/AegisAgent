import type { VerifyResult } from "@/datasources/types";

export interface ProvableTimelineFieldOptions {
  timeField: string;
  labelField: string;
  agentField: string;
  decisionField: string;
  receiptIdField: string;
  receiptHashField: string;
  prevHashField: string;
}

export type RowVerifyState =
  | { status: "verified"; message?: string }
  | { status: "failed"; message?: string }
  | { status: "unknown"; message?: string };

export type ChainVerifyState =
  | { status: "idle" }
  | { status: "running" }
  | { status: "verified"; total: number; message: string }
  | { status: "failed"; brokenAt: number; message: string }
  | { status: "unknown"; message: string };

export function pickTimelineField(row: Record<string, unknown>, field: string): string {
  const value = row[field];
  return value === null || value === undefined ? "" : String(value);
}

export function pickTimelineTime(
  row: Record<string, unknown>,
  timeField: string,
): string {
  return (
    pickTimelineField(row, timeField)
    || pickTimelineField(row, "timestamp")
    || pickTimelineField(row, "ts")
    || pickTimelineField(row, "created_at")
  );
}

/** Normalize visible timeline rows into receipt-shaped payloads for range/chain verify. */
export function timelineRowsForVerify(
  rows: ReadonlyArray<Record<string, unknown>>,
  opts: ProvableTimelineFieldOptions,
): Array<Record<string, unknown>> {
  const mapped = rows.map((row) => {
    const receiptId =
      pickTimelineField(row, opts.receiptIdField)
      || pickTimelineField(row, "receipt_id")
      || pickTimelineField(row, "id");
    const receiptHash =
      pickTimelineField(row, opts.receiptHashField)
      || pickTimelineField(row, "receipt_hash");
    const prevHash =
      pickTimelineField(row, opts.prevHashField)
      || pickTimelineField(row, "prev_receipt_hash");
    const time = pickTimelineTime(row, opts.timeField);

    return {
      ...row,
      id: receiptId,
      receipt_id: receiptId,
      ts: time,
      created_at: time,
      receipt_hash: receiptHash,
      prev_receipt_hash: prevHash,
    };
  });

  return [...mapped].sort((left, right) => {
    const leftMs = Date.parse(pickTimelineTime(left, opts.timeField));
    const rightMs = Date.parse(pickTimelineTime(right, opts.timeField));
    if (Number.isNaN(leftMs) && Number.isNaN(rightMs)) return 0;
    if (Number.isNaN(leftMs)) return 1;
    if (Number.isNaN(rightMs)) return -1;
    return leftMs - rightMs;
  });
}

export function sortTimelineRows(
  rows: ReadonlyArray<Record<string, unknown>>,
  timeField: string,
): Array<Record<string, unknown>> {
  return [...rows].sort((left, right) => {
    const leftMs = Date.parse(pickTimelineTime(left, timeField));
    const rightMs = Date.parse(pickTimelineTime(right, timeField));
    if (Number.isNaN(leftMs) && Number.isNaN(rightMs)) return 0;
    if (Number.isNaN(leftMs)) return 1;
    if (Number.isNaN(rightMs)) return -1;
    return leftMs - rightMs;
  });
}

export function applyRangeVerificationResult(
  result: VerifyResult,
  rowCount: number,
): { chain: ChainVerifyState; rowStates: Record<number, RowVerifyState> } {
  if (result.status === "verified") {
    return {
      chain: {
        status: "verified",
        total: rowCount,
        message: result.message,
      },
      rowStates: Object.fromEntries(
        Array.from({ length: rowCount }, (_, index) => [
          index,
          { status: "verified" as const, message: result.message },
        ]),
      ),
    };
  }

  if (result.status === "unknown") {
    return {
      chain: { status: "unknown", message: result.message },
      rowStates: {},
    };
  }

  const brokenAt = result.brokenAtRow ?? 1;
  return {
    chain: {
      status: "failed",
      brokenAt,
      message: result.message,
    },
    rowStates: {
      [brokenAt - 1]: { status: "failed", message: result.message },
    },
  };
}