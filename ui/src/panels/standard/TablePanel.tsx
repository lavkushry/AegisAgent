import React from "react";
import type { Field } from "@/datasources/types";
import { frameRows } from "@/datasources/frame";
import { formatRelative } from "@/lib/format";
import DecisionBadge from "@/components/security/DecisionBadge";
import TrustBadge from "@/components/security/TrustBadge";
import HashChip from "@/components/security/HashChip";
import type { PanelProps } from "../types";

export interface TableOptions {
  /** Restrict/order columns by field name; defaults to all frame fields. */
  columns?: string[];
  maxRows?: number;
}

function renderCell(field: Field, value: unknown): React.ReactNode {
  if (value === null || value === undefined) {
    return <span className="text-[var(--text-muted)]">—</span>;
  }
  switch (field.type) {
    case "decision":
      return <DecisionBadge decision={String(value)} />;
    case "trust":
      return <TrustBadge trust={String(value)} />;
    case "hash":
      return <HashChip hash={String(value)} kind="receipt" />;
    case "time":
      return <span className="text-[var(--text-muted)]">{formatRelative(String(value))}</span>;
    case "json":
      return <span className="font-mono text-[var(--text-muted)]">{JSON.stringify(value)}</span>;
    default:
      return <span>{String(value)}</span>;
  }
}

/**
 * Tabular panel. A plain table for now; the high-row-count north star is
 * TanStack Table + virtualization (HLD/LLD section 6.3), swappable without
 * changing this component's PanelProps contract.
 */
export default function TablePanel(props: PanelProps<TableOptions>) {
  const { data, definition, onDrilldown } = props;
  const drilldown = definition.drilldowns?.[0];

  const columns = definition.options?.columns
    ? definition.options.columns
        .map((name) => data.fields.find((f) => f.name === name))
        .filter((f): f is Field => Boolean(f))
    : data.fields;

  const rows = frameRows(data);
  const max = definition.options?.maxRows ?? rows.length;
  const visibleRows = rows.slice(0, max);

  return (
    <div className="overflow-auto custom-scrollbar -mx-1">
      <table className="w-full text-xs">
        <thead>
          <tr className="text-left text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            {columns.map((f) => (
              <th key={f.name} className="font-semibold px-1 pb-2">
                {f.name}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {visibleRows.map((row, i) => (
            <tr
              key={String(row.id ?? i)}
              onClick={drilldown ? () => onDrilldown(drilldown, row) : undefined}
              className={`border-t border-[var(--border-default)] ${
                drilldown ? "cursor-pointer hover:bg-[var(--surface-elevated)]" : ""
              }`}
              style={{ height: "var(--row-height, 28px)" }}
            >
              {columns.map((f) => (
                <td key={f.name} className="px-1 align-middle">
                  {renderCell(f, row[f.name])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
