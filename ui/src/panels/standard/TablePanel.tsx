import React, { useMemo } from "react";
import type { Field } from "@/datasources/types";
import { frameRows } from "@/datasources/frame";
import { formatRelative } from "@/lib/format";
import DecisionBadge from "@/components/security/DecisionBadge";
import TrustBadge from "@/components/security/TrustBadge";
import HashChip from "@/components/security/HashChip";
import VirtualTable, { type VirtualTableColumn } from "@/components/primitives/VirtualTable";
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
 * Tabular panel with TanStack Virtual windowing for 10k+ gateway pages (#1317).
 * Server-side filters/pagination stay in datasources; this only renders the
 * returned page efficiently.
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

  const tableColumns = useMemo<VirtualTableColumn<Record<string, unknown>>[]>(
    () =>
      columns.map((field) => ({
        key: field.name,
        header: field.name,
        cell: (row) => renderCell(field, row[field.name]),
      })),
    [columns],
  );

  return (
    <VirtualTable
      rows={visibleRows}
      columns={tableColumns}
      getRowKey={(row, index) => String(row.id ?? index)}
      onRowClick={
        drilldown
          ? (row) => {
              onDrilldown(drilldown, row);
            }
          : undefined
      }
    />
  );
}