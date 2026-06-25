import React from "react";
import type { PanelProps } from "../types";

export interface StatOptions {
  /** Field to read the value from; defaults to the first numeric field. */
  valueField?: string;
  unit?: string;
  /** [warn, critical] thresholds that tint the number. */
  thresholds?: [number, number];
}

function resolveValue(props: PanelProps<StatOptions>): number | null {
  const { data, definition } = props;
  const field =
    data.fields.find((f) => f.name === definition.options?.valueField) ??
    data.fields.find((f) => f.type === "number");
  if (field && field.values.length > 0) {
    const last = field.values[field.values.length - 1];
    return typeof last === "number" ? last : Number(last) || 0;
  }
  // No value field: fall back to row count (e.g. "open incidents").
  return data.length;
}

function thresholdColor(value: number, thresholds?: [number, number]): string {
  if (!thresholds) return "var(--text-primary)";
  const [warn, critical] = thresholds;
  if (value >= critical) return "var(--sev-critical)";
  if (value >= warn) return "var(--sev-medium)";
  return "var(--text-primary)";
}

/** A single decision-relevant number with optional unit and threshold tint. */
export default function StatPanel(props: PanelProps<StatOptions>) {
  const value = resolveValue(props);
  const { unit, thresholds } = props.definition.options ?? {};
  const color = value === null ? "var(--text-muted)" : thresholdColor(value, thresholds);

  return (
    <div className="flex flex-col justify-center h-full">
      <span
        className="font-bold tabular-nums leading-none"
        style={{ color, fontSize: "var(--font-size-hero-stat, 2.25rem)" }}
      >
        {value === null ? "—" : value.toLocaleString()}
        {unit ? <span className="text-base text-[var(--text-muted)] ml-1">{unit}</span> : null}
      </span>
    </div>
  );
}
