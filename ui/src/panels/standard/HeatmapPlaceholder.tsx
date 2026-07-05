import { Grid3X3 } from "lucide-react";

export default function HeatmapPlaceholder() {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 text-center text-[var(--text-muted)]">
      <Grid3X3 size={24} aria-hidden="true" />
      <p className="text-xs">Heatmap density panels are not enabled yet — use Analytics tables and timeseries.</p>
    </div>
  );
}
