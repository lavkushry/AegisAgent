"use client";

import React, { useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";

export const DEFAULT_ROW_HEIGHT = 28;
export const DEFAULT_VIRTUAL_OVERSCAN = 8;
export const DEFAULT_VIRTUAL_MAX_HEIGHT = 480;

export interface VirtualTableColumn<T> {
  key: string;
  header: React.ReactNode;
  headerClassName?: string;
  cellClassName?: string;
  cell: (row: T, index: number) => React.ReactNode;
}

export interface VirtualTableProps<T> {
  rows: readonly T[];
  columns: readonly VirtualTableColumn<T>[];
  getRowKey: (row: T, index: number) => string;
  rowHeight?: number;
  overscan?: number;
  maxHeight?: number | string;
  onRowClick?: (row: T, index: number) => void;
  rowClassName?: string | ((row: T, index: number) => string);
  tableClassName?: string;
  minWidth?: string;
  emptyState?: React.ReactNode;
}

/**
 * Windowed table body — only mounts visible rows (+ overscan) for 10k+ datasets.
 * Filtering/pagination remain upstream (gateway/API); this panel never scans all
 * rows client-side beyond what the datasource already returned.
 */
export function VirtualTable<T>({
  rows,
  columns,
  getRowKey,
  rowHeight = DEFAULT_ROW_HEIGHT,
  overscan = DEFAULT_VIRTUAL_OVERSCAN,
  maxHeight = DEFAULT_VIRTUAL_MAX_HEIGHT,
  onRowClick,
  rowClassName,
  tableClassName = "w-full text-xs",
  minWidth,
  emptyState,
}: VirtualTableProps<T>) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const viewportHeight = resolveViewportHeight(maxHeight);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => rowHeight,
    overscan,
    initialRect: { width: 800, height: viewportHeight },
  });

  const measuredRows = virtualizer.getVirtualItems();
  const virtualRows =
    measuredRows.length > 0
      ? measuredRows
      : fallbackVirtualItems(rows.length, rowHeight, viewportHeight, overscan);
  const colSpan = columns.length;
  const totalSize =
    measuredRows.length > 0 ? virtualizer.getTotalSize() : rows.length * rowHeight;
  const padTop = virtualRows.length > 0 ? virtualRows[0].start : 0;
  const padBottom =
    virtualRows.length > 0 ? totalSize - virtualRows[virtualRows.length - 1].end : 0;

  if (rows.length === 0) {
    return emptyState ?? null;
  }

  return (
    <div
      ref={scrollRef}
      className="overflow-auto custom-scrollbar -mx-1"
      style={{ maxHeight }}
      data-virtual-table
      data-row-count={rows.length}
    >
      <table className={tableClassName} style={minWidth ? { minWidth } : undefined}>
        <thead className="sticky top-0 z-10 bg-[var(--surface-panel)]">
          <tr className="text-left text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            {columns.map((column) => (
              <th
                key={column.key}
                className={`font-semibold px-1 pb-2 ${column.headerClassName ?? ""}`}
              >
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {padTop > 0 ? (
            <tr aria-hidden="true" style={{ height: padTop, border: 0 }}>
              <td colSpan={colSpan} style={{ padding: 0, border: 0 }} />
            </tr>
          ) : null}
          {virtualRows.map((virtualRow) => {
            const row = rows[virtualRow.index];
            const resolvedRowClass =
              typeof rowClassName === "function"
                ? rowClassName(row, virtualRow.index)
                : rowClassName ?? "";
            return (
              <tr
                key={getRowKey(row, virtualRow.index)}
                data-index={virtualRow.index}
                onClick={onRowClick ? () => onRowClick(row, virtualRow.index) : undefined}
                className={`border-t border-[var(--border-default)] ${resolvedRowClass} ${
                  onRowClick ? "cursor-pointer hover:bg-[var(--surface-elevated)]" : ""
                }`}
                style={{ height: rowHeight }}
              >
                {columns.map((column) => (
                  <td
                    key={column.key}
                    className={`px-1 align-middle ${column.cellClassName ?? ""}`}
                  >
                    {column.cell(row, virtualRow.index)}
                  </td>
                ))}
              </tr>
            );
          })}
          {padBottom > 0 ? (
            <tr aria-hidden="true" style={{ height: padBottom, border: 0 }}>
              <td colSpan={colSpan} style={{ padding: 0, border: 0 }} />
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  );
}

function resolveViewportHeight(maxHeight: number | string): number {
  if (typeof maxHeight === "number" && Number.isFinite(maxHeight)) {
    return maxHeight;
  }
  return DEFAULT_VIRTUAL_MAX_HEIGHT;
}

function fallbackVirtualItems(
  count: number,
  rowHeight: number,
  viewportHeight: number,
  overscan: number,
) {
  const visible = Math.ceil(viewportHeight / rowHeight) + overscan * 2;
  const limit = Math.min(count, Math.max(visible, 1));
  return Array.from({ length: limit }, (_, index) => ({
    index,
    start: index * rowHeight,
    size: rowHeight,
    key: index,
    end: (index + 1) * rowHeight,
  }));
}

export default VirtualTable;