import React from "react";
import { EmptyState, ErrorState, LoadingSkeleton } from "@/components/primitives";

type Props = {
  title: string;
  isLoading: boolean;
  isRefreshing?: boolean;
  isStale?: boolean;
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
  isRefreshing,
  isStale,
  error,
  isEmpty,
  emptyLabel = "No data",
  children,
}: Props) {
  return (
    <section className="panel-card flex flex-col h-full">
      <header className="mb-3 flex items-center justify-between gap-2"><h3 className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">{title}</h3>{isRefreshing ? <span className="text-[10px] text-[var(--state-pending)]">Refreshing…</span> : isStale ? <span className="text-[10px] text-[var(--state-pending)]">Stale</span> : null}</header>
      <div className="flex-1 min-h-0">
        {isLoading ? (
          <LoadingSkeleton label={`Loading ${title}`} />
        ) : error ? (
          <ErrorState message={error} />
        ) : isEmpty ? (
          <EmptyState title={emptyLabel} />
        ) : (
          children
        )}
      </div>
    </section>
  );
}
