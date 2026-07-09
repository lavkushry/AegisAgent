import type { PanelProps } from "../types";

/** Placeholder until Recharts timeseries is wired. */
export default function TimeSeriesPlaceholder(_props: PanelProps) {
  return (
    <div className="flex h-full items-center justify-center text-xs text-[var(--text-muted)]">
      Time series chart — use Explore for detailed series (Phase C charts)
    </div>
  );
}
