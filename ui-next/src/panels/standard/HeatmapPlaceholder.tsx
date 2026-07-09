import type { PanelProps } from "../types";

/** Placeholder until ECharts heatmap lands. */
export default function HeatmapPlaceholder(_props: PanelProps) {
  return (
    <div className="flex h-full items-center justify-center text-xs text-[var(--text-muted)]">
      Heatmap unavailable in this build
    </div>
  );
}
