import type { DataFrame, Field, FieldFormat, FieldType } from "./types";

type Row = Record<string, unknown>;

const TIME_KEYS = new Set(["created_at", "ts", "time", "timestamp", "first_seen", "last_seen"]);

function inferType(key: string, sample: unknown): { type: FieldType; format?: FieldFormat } {
  const lower = key.toLowerCase();
  if (lower.includes("hash")) return { type: "hash", format: "hash" };
  if (lower === "decision") return { type: "decision", format: "badge" };
  if (lower.includes("trust")) return { type: "trust", format: "badge" };
  if (TIME_KEYS.has(lower)) return { type: "time", format: "relative-time" };
  if (typeof sample === "number") return { type: "number" };
  if (sample !== null && typeof sample === "object") return { type: "json", format: "raw" };
  return { type: "string" };
}

/**
 * Build a columnar DataFrame from row objects. Field types/formats are
 * inferred heuristically; an explicit field order can be supplied to keep
 * column ordering stable across pages.
 */
export function rowsToFrame(rows: ReadonlyArray<Row>, fieldOrder?: ReadonlyArray<string>): DataFrame {
  if (rows.length === 0) {
    const fields: Field[] = (fieldOrder ?? []).map((name) => ({
      name,
      type: "string" as FieldType,
      values: [],
    }));
    return { fields, length: 0, meta: { total: 0 } };
  }

  const keys = fieldOrder
    ? [...fieldOrder]
    : Array.from(rows.reduce((set, row) => {
        Object.keys(row).forEach((k) => set.add(k));
        return set;
      }, new Set<string>()));

  const fields: Field[] = keys.map((name) => {
    const sample = rows.find((r) => r[name] !== undefined && r[name] !== null)?.[name];
    const { type, format } = inferType(name, sample);
    return {
      name,
      type,
      format,
      values: rows.map((r) => r[name] ?? null),
    };
  });

  return { fields, length: rows.length, meta: { total: rows.length } };
}

/** Read a single cell from a frame by field name and row index. */
export function cell(frame: DataFrame, fieldName: string, rowIndex: number): unknown {
  const field = frame.fields.find((f) => f.name === fieldName);
  return field ? field.values[rowIndex] : undefined;
}

/** Reconstruct row objects from a frame (for table rendering). */
export function frameRows(frame: DataFrame): Array<Record<string, unknown>> {
  const rows: Array<Record<string, unknown>> = [];
  for (let i = 0; i < frame.length; i++) {
    const row: Record<string, unknown> = {};
    for (const field of frame.fields) {
      row[field.name] = field.values[i];
    }
    rows.push(row);
  }
  return rows;
}
