import { frameRows } from "@/datasources/frame";
import type { PanelProps } from "../types";

export interface TimeSeriesOptions {
  /** Field for the y-axis (default: count). */
  valueField?: string;
  /** Field for the x-axis (default: bucket). */
  timeField?: string;
  /** Stroke color CSS var or hex (default: brand). */
  color?: string;
}

type Point = { x: number; y: number; label: string };

function toPoints(
  rows: Array<Record<string, unknown>>,
  timeField: string,
  valueField: string,
): Point[] {
  const points: Point[] = [];
  for (const row of rows) {
    const rawT = row[timeField];
    const rawV = row[valueField];
    const t =
      typeof rawT === "number"
        ? rawT
        : rawT
          ? Date.parse(String(rawT))
          : Number.NaN;
    const v = typeof rawV === "number" ? rawV : Number(rawV);
    if (!Number.isFinite(t) || !Number.isFinite(v)) continue;
    points.push({
      x: t,
      y: v,
      label: typeof rawT === "string" ? rawT : new Date(t).toISOString(),
    });
  }
  return points.sort((a, b) => a.x - b.x);
}

/**
 * Lightweight SVG timeseries — no chart library dependency.
 * Expects a frame with bucket (time) + count (number) columns from soc-query.
 */
export default function TimeSeriesPanel(props: PanelProps<TimeSeriesOptions>) {
  const timeField = props.definition.options?.timeField ?? "bucket";
  const valueField = props.definition.options?.valueField ?? "count";
  const color =
    props.definition.options?.color ?? "var(--brand)";
  const rows = frameRows(props.data);
  const points = toPoints(rows, timeField, valueField);

  if (points.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-xs text-[var(--text-muted)]">
        No series data
      </div>
    );
  }

  const width = 320;
  const height = 120;
  const padX = 8;
  const padY = 12;
  const minX = points[0].x;
  const maxX = points[points.length - 1].x || minX + 1;
  const maxY = Math.max(...points.map((p) => p.y), 1);
  const spanX = maxX - minX || 1;

  const coords = points.map((p) => {
    const cx = padX + ((p.x - minX) / spanX) * (width - padX * 2);
    const cy =
      height - padY - (p.y / maxY) * (height - padY * 2);
    return { ...p, cx, cy };
  });

  const line = coords
    .map((p, i) => `${i === 0 ? "M" : "L"}${p.cx.toFixed(1)},${p.cy.toFixed(1)}`)
    .join(" ");
  const area =
    line +
    ` L${coords[coords.length - 1].cx.toFixed(1)},${(height - padY).toFixed(1)}` +
    ` L${coords[0].cx.toFixed(1)},${(height - padY).toFixed(1)} Z`;

  const last = points[points.length - 1];
  const firstLabel = new Date(points[0].x).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
  });
  const lastLabel = new Date(last.x).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
  });

  return (
    <div className="flex h-full flex-col gap-1">
      <div className="flex items-baseline justify-between text-[10px] text-[var(--text-muted)]">
        <span>
          max <span className="tabular-nums text-[var(--text-primary)]">{maxY}</span>
        </span>
        <span className="tabular-nums text-[var(--text-primary)]">
          last {last.y}
        </span>
      </div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-full min-h-[4.5rem] w-full"
        role="img"
        aria-label={`${props.definition.title}: ${points.length} points, last ${last.y}`}
      >
        <path d={area} fill={color} opacity={0.12} />
        <path
          d={line}
          fill="none"
          stroke={color}
          strokeWidth={2}
          strokeLinejoin="round"
          strokeLinecap="round"
        />
        {coords.map((p) => (
          <circle
            key={`${p.x}-${p.y}`}
            cx={p.cx}
            cy={p.cy}
            r={2.5}
            fill={color}
          >
            <title>
              {p.label}: {p.y}
            </title>
          </circle>
        ))}
      </svg>
      <div className="flex justify-between text-[10px] text-[var(--text-muted)]">
        <span>{firstLabel}</span>
        <span>{lastLabel}</span>
      </div>
    </div>
  );
}
