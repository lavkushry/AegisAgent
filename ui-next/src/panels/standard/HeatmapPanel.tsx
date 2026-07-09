import { frameRows } from "@/datasources/frame";
import type { PanelProps } from "../types";

export interface HeatmapOptions {
  /** Category label field (default: value — gateway count_by shape). */
  categoryField?: string;
  /** Numeric intensity field (default: count). */
  valueField?: string;
  /** Max categories to render (default: 12). */
  maxCategories?: number;
}

type Cell = { label: string; value: number };

function toCells(
  rows: Array<Record<string, unknown>>,
  categoryField: string,
  valueField: string,
  maxCategories: number,
): Cell[] {
  const cells: Cell[] = [];
  for (const row of rows) {
    const rawLabel = row[categoryField];
    const rawValue = row[valueField];
    if (rawLabel === undefined || rawLabel === null) continue;
    const value =
      typeof rawValue === "number" ? rawValue : Number(rawValue);
    if (!Number.isFinite(value)) continue;
    const label = String(rawLabel).trim() || "(empty)";
    cells.push({ label, value });
  }
  return cells
    .sort((a, b) => b.value - a.value)
    .slice(0, Math.max(1, maxCategories));
}

/**
 * Intensity for a cell: 0–1 relative to max, with a floor so zeros stay visible.
 * Uses brand hue at varying opacity (no chart library).
 */
function intensity(value: number, max: number): number {
  if (max <= 0) return 0.08;
  return Math.min(1, Math.max(0.1, value / max));
}

/**
 * Pure SVG categorical heatmap for soc-query `count_by` frames
 * (`{ value, count }` rows). No ECharts dependency — same zero-dep stance as
 * TimeSeriesPanel. True 2D time×facet heatmaps can swap the Component later.
 */
export default function HeatmapPanel(props: PanelProps<HeatmapOptions>) {
  const categoryField =
    props.definition.options?.categoryField ?? "value";
  const valueField = props.definition.options?.valueField ?? "count";
  const maxCategories = props.definition.options?.maxCategories ?? 12;
  const rows = frameRows(props.data);
  const cells = toCells(rows, categoryField, valueField, maxCategories);

  if (cells.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-xs text-[var(--text-muted)]">
        No facet data
      </div>
    );
  }

  const max = Math.max(...cells.map((c) => c.value), 1);
  const total = cells.reduce((sum, c) => sum + c.value, 0);
  const cellW = 72;
  const cellH = 44;
  const gap = 6;
  const cols = Math.min(cells.length, 6);
  const rowsCount = Math.ceil(cells.length / cols);
  const width = cols * cellW + (cols - 1) * gap;
  const height = rowsCount * cellH + (rowsCount - 1) * gap;

  return (
    <div className="flex h-full flex-col gap-1">
      <div className="flex items-baseline justify-between text-[10px] text-[var(--text-muted)]">
        <span>
          max{" "}
          <span className="tabular-nums text-[var(--text-primary)]">{max}</span>
        </span>
        <span className="tabular-nums">
          n={" "}
          <span className="text-[var(--text-primary)]">{total}</span>
        </span>
      </div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-full min-h-[5rem] w-full"
        role="img"
        aria-label={`${props.definition.title}: ${cells.length} categories, total ${total}`}
      >
        {cells.map((cell, i) => {
          const col = i % cols;
          const row = Math.floor(i / cols);
          const x = col * (cellW + gap);
          const y = row * (cellH + gap);
          const alpha = intensity(cell.value, max);
          const short =
            cell.label.length > 10
              ? `${cell.label.slice(0, 9)}…`
              : cell.label;
          return (
            <g key={`${cell.label}-${i}`}>
              <rect
                x={x}
                y={y}
                width={cellW}
                height={cellH}
                rx={4}
                fill="var(--brand)"
                fillOpacity={alpha}
              />
              <title>
                {cell.label}: {cell.value}
              </title>
              <text
                x={x + cellW / 2}
                y={y + cellH / 2 - 5}
                textAnchor="middle"
                fill="var(--text-primary)"
                fontSize={9}
                fontFamily="ui-sans-serif, system-ui, sans-serif"
              >
                {short}
              </text>
              <text
                x={x + cellW / 2}
                y={y + cellH / 2 + 10}
                textAnchor="middle"
                fill="var(--text-primary)"
                fontSize={11}
                fontWeight={600}
                fontFamily="ui-monospace, monospace"
                className="tabular-nums"
              >
                {cell.value}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
