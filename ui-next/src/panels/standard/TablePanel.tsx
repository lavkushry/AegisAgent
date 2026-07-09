import type { ReactNode } from "react";
import type { Field } from "@/datasources/types";
import { frameRows } from "@/datasources/frame";
import { formatRelative } from "@/lib/format";
import { DecisionBadge } from "@/components/security/DecisionBadge";
import { TrustBadge } from "@/components/security/TrustBadge";
import { HashChip } from "@/components/security/HashChip";
import type { PanelProps } from "../types";

export interface TableOptions {
  columns?: string[];
  maxRows?: number;
}

function renderCell(field: Field, value: unknown): ReactNode {
  if (value === null || value === undefined) {
    return <span className="text-[var(--text-muted)]">—</span>;
  }
  switch (field.type) {
    case "decision":
      return <DecisionBadge decision={String(value)} />;
    case "trust":
      return <TrustBadge trust={String(value)} />;
    case "hash":
      return <HashChip hash={String(value)} kind="action" />;
    case "time":
      return (
        <span className="text-[var(--text-muted)]">
          {formatRelative(String(value))}
        </span>
      );
    case "json":
      return (
        <span className="font-mono text-[var(--text-muted)]">
          {JSON.stringify(value)}
        </span>
      );
    default:
      return <span>{String(value)}</span>;
  }
}

/** Simple table panel (virtualization deferred). */
export default function TablePanel(props: PanelProps<TableOptions>) {
  const { data, definition, onDrilldown } = props;
  const drilldown = definition.drilldowns?.[0];

  const columns = definition.options?.columns
    ? definition.options.columns
        .map((name) => data.fields.find((f) => f.name === name))
        .filter((f): f is Field => Boolean(f))
    : [...data.fields];

  const rows = frameRows(data);
  const max = definition.options?.maxRows ?? rows.length;
  const visibleRows = rows.slice(0, max);

  return (
    <div className="h-full overflow-auto">
      <table className="w-full border-collapse text-left text-[11px]">
        <thead className="sticky top-0 bg-[var(--surface-elevated)] text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
          <tr>
            {columns.map((field) => (
              <th key={field.name} className="px-2 py-1.5 font-medium">
                {field.name}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {visibleRows.map((row, index) => (
            <tr
              key={String(row.id ?? index)}
              className="cursor-pointer border-t border-[var(--border-default)] hover:bg-[var(--interactive-bg-hover)]"
              onClick={() => drilldown && onDrilldown(drilldown, row)}
            >
              {columns.map((field) => (
                <td key={field.name} className="px-2 py-1.5">
                  {renderCell(field, row[field.name])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
