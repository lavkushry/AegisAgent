import { frameRows } from "./frame";
import type { DataFrame } from "./types";

export interface ReceiptRecord extends Record<string, unknown> {
  id: string;
  receipt_hash?: string;
  prev_receipt_hash?: string;
  agent_id?: string;
  run_id?: string;
  trace_id?: string;
  tool?: string;
  ts?: string;
  created_at?: string;
}

function isReceiptRecord(row: Record<string, unknown>): row is ReceiptRecord {
  return typeof row.id === "string";
}

export function receiptRowsFromFrame(frame: DataFrame | undefined): ReceiptRecord[] {
  return frame ? frameRows(frame).filter(isReceiptRecord) : [];
}