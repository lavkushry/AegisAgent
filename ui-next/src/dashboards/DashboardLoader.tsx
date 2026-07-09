import { PanelRuntime } from "@/panels/PanelRuntime";
import { useAppStore } from "@/app/store";
import type { DashboardSchema } from "./schema";

const ROW_UNIT_PX = 88;

type Props = {
  schema: DashboardSchema;
};

/** Renders DashboardSchema as a 12-column grid of PanelRuntime panels. */
export function DashboardLoader({ schema }: Props) {
  const selectedRange = useAppStore((s) => s.timeRange);
  const variables = useAppStore((s) => s.variables);
  const liveMode = useAppStore((s) => s.liveMode);
  const timeRange = selectedRange
    ? { from: `now-${selectedRange}`, to: "now" as const }
    : schema.time.defaultRange;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-sm font-bold uppercase tracking-wider">
          {schema.title}
        </h1>
        <p className="mt-1 text-[11px] text-[var(--text-muted)]">
          Schema-driven dashboard · {schema.uid}
          {liveMode ? " · live" : ""}
        </p>
      </div>
      {schema.layout.map((row) => (
        <div key={row.id} className="space-y-2">
          {row.title ? (
            <h2 className="text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
              {row.title}
            </h2>
          ) : null}
          <div className="grid grid-cols-12 gap-[var(--space-grid-gap,12px)]">
            {row.panels.map((item) => (
              <div
                key={item.panel.id}
                style={{
                  gridColumn: `span ${item.w} / span ${item.w}`,
                  height: item.h * ROW_UNIT_PX,
                }}
              >
                <PanelRuntime
                  definition={item.panel}
                  timeRange={timeRange}
                  variables={variables}
                  refreshSec={liveMode ? schema.time.refreshSec : undefined}
                />
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

export default DashboardLoader;
