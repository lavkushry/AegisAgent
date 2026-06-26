"use client";

import React from "react";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { useChartColors } from "@/hooks/useChartColors";
import type { PanelProps } from "../types";

export interface TimeSeriesOptions {
  timeField?: string;
  valueField?: string;
}

/** Shorten a DB bucket label for the axis: "2026-06-25 13:00:00" -> "13:00". */
function shortBucket(raw: string): string {
  const parts = raw.split(" ");
  return parts.length === 2 ? parts[1].slice(0, 5) : raw;
}

/**
 * Time-series line chart bound to a [time, number] DataFrame (e.g. the
 * decisions count_over_time aggregate). Recharts for v1; the north star is
 * uPlot, swappable behind this component without touching the panel contract.
 */
export default function TimeSeriesPanel({ data, definition }: PanelProps<TimeSeriesOptions>) {
  const chart = useChartColors();
  const opts = definition.options;

  const timeName = opts?.timeField ?? data.fields.find((f) => f.type === "time")?.name ?? "bucket";
  const valueName = opts?.valueField ?? data.fields.find((f) => f.type === "number")?.name ?? "count";
  const timeField = data.fields.find((f) => f.name === timeName);
  const valueField = data.fields.find((f) => f.name === valueName);

  const rows =
    timeField && valueField
      ? timeField.values.map((t, i) => ({
          t: shortBucket(String(t ?? "")),
          v: Number(valueField.values[i] ?? 0),
        }))
      : [];

  return (
    <div className="h-full w-full min-h-[160px]">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={rows} margin={{ top: 4, right: 8, bottom: 0, left: -16 }}>
          <CartesianGrid strokeDasharray="3 3" stroke={chart.border} />
          <XAxis dataKey="t" stroke={chart.textMuted} fontSize={10} />
          <YAxis stroke={chart.textMuted} fontSize={10} allowDecimals={false} />
          <Tooltip
            contentStyle={{ backgroundColor: chart.surfacePanel, borderColor: chart.border }}
            labelStyle={{ color: chart.textMuted }}
          />
          <Line type="monotone" dataKey="v" stroke={chart.brand} strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
