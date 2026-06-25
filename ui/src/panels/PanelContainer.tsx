import React from "react";

type Props = {
  title: string;
  isLoading: boolean;
  error?: string;
  isEmpty: boolean;
  emptyLabel?: string;
  children: React.ReactNode;
};

/**
 * The panel frame: title plus the shared loading / error / empty states, so
 * individual panels only render their success body.
 */
export default function PanelContainer({
  title,
  isLoading,
  error,
  isEmpty,
  emptyLabel = "No data",
  children,
}: Props) {
  return (
    <section className="panel-card flex flex-col h-full">
      <h3 className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)] mb-3">
        {title}
      </h3>
      <div className="flex-1 min-h-0">
        {isLoading ? (
          <div className="h-full w-full animate-pulse rounded-md bg-[var(--surface-elevated)]/40" />
        ) : error ? (
          <p className="text-xs text-[var(--state-failed)] py-6 text-center">{error}</p>
        ) : isEmpty ? (
          <p className="text-xs text-[var(--text-muted)] py-6 text-center">{emptyLabel}</p>
        ) : (
          children
        )}
      </div>
    </section>
  );
}
