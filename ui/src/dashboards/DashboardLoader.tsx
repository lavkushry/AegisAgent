"use client";

import React from "react";
import PanelRuntime from "@/panels/PanelRuntime";
import { useAppStore } from "@/app/store";
import type { DashboardSchema } from "./schema";

const ROW_UNIT_PX = 88;

type Props = {
  schema: DashboardSchema;
};

/**
 * Renders a DashboardSchema as a 12-column grid of PanelRuntime panels.
 * Composition only — it owns no data. Tabs and conditional display are
 * later additions (HLD/LLD section 7.3).
 */
export default function DashboardLoader({ schema }: Props) {
  const selectedRange = useAppStore((state) => state.timeRange);
  const variables = useAppStore((state) => state.variables);
  const liveMode = useAppStore((state) => state.liveMode);
  const timeRange = selectedRange
    ? { from: `now-${selectedRange}`, to: "now" }
    : schema.time.defaultRange;

  return (
    <div className="space-y-4">
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
                style={{ gridColumn: `span ${item.w} / span ${item.w}`, height: item.h * ROW_UNIT_PX }}
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
