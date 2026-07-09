import { useAppStore } from "@/app/store";
import type { StreamConnectionStatus } from "@/datasources/types";

const RANGES = [
  { id: "1h", label: "1h" },
  { id: "24h", label: "24h" },
  { id: "7d", label: "7d" },
  { id: "30d", label: "30d" },
] as const;

function streamLabel(status: StreamConnectionStatus): string {
  switch (status) {
    case "live":
      return "SSE live";
    case "polling":
      return "Polling";
    case "connecting":
      return "Connecting…";
    default:
      return "Stream off";
  }
}

function streamColor(status: StreamConnectionStatus): string {
  switch (status) {
    case "live":
      return "var(--state-verified)";
    case "polling":
      return "var(--state-pending)";
    case "connecting":
      return "var(--sev-low)";
    default:
      return "var(--text-muted)";
  }
}

/** Global Grafana-style controls: time range + live stream. */
export function ControlsBar() {
  const timeRange = useAppStore((s) => s.timeRange);
  const setTimeRange = useAppStore((s) => s.setTimeRange);
  const liveMode = useAppStore((s) => s.liveMode);
  const setLiveMode = useAppStore((s) => s.setLiveMode);
  const streamStatus = useAppStore((s) => s.streamStatus);
  const activeTenant = useAppStore((s) => s.activeTenant);

  return (
    <div className="flex flex-wrap items-center gap-3 border-b border-[var(--border-default)] bg-[var(--surface-panel)] px-4 py-2">
      <div className="font-mono text-[10px] text-[var(--text-muted)]">
        {activeTenant.trim() ? (
          <>
            tenant{" "}
            <span className="text-[var(--text-primary)]">{activeTenant}</span>
          </>
        ) : (
          "no tenant"
        )}
      </div>

      <div className="flex items-center gap-1" role="group" aria-label="Time range">
        {RANGES.map((r) => (
          <button
            key={r.id}
            type="button"
            onClick={() => setTimeRange(r.id)}
            className={[
              "rounded px-2 py-1 text-[11px] font-medium transition-colors",
              timeRange === r.id
                ? "bg-[var(--brand-subtle)] text-[var(--text-primary)] ring-1 ring-[var(--border-active)]"
                : "text-[var(--text-secondary)] hover:bg-[var(--interactive-bg-hover)]",
            ].join(" ")}
            aria-pressed={timeRange === r.id}
          >
            {r.label}
          </button>
        ))}
      </div>

      <button
        type="button"
        onClick={() => setLiveMode(!liveMode)}
        className={[
          "inline-flex items-center gap-1.5 rounded px-2.5 py-1 text-[11px] font-semibold transition-colors",
          liveMode
            ? "bg-[var(--brand-subtle)] text-[var(--text-primary)] ring-1 ring-[var(--border-active)]"
            : "border border-[var(--border-default)] text-[var(--text-secondary)]",
        ].join(" ")}
        aria-pressed={liveMode}
      >
        <span
          className="inline-block h-1.5 w-1.5 rounded-full"
          style={{
            background: liveMode
              ? streamColor(streamStatus)
              : "var(--text-muted)",
          }}
        />
        {liveMode ? "Live" : "Live off"}
      </button>

      {liveMode ? (
        <span
          className="text-[10px] font-medium uppercase tracking-wider"
          style={{ color: streamColor(streamStatus) }}
        >
          {streamLabel(streamStatus)}
        </span>
      ) : null}
    </div>
  );
}
