import type { ReactNode } from "react";
import {
  EmptyState,
  ErrorState,
  LoadingSkeleton,
} from "@/components/primitives/States";

type Props = {
  title: string;
  isLoading: boolean;
  isRefreshing?: boolean;
  isStale?: boolean;
  error?: string;
  isEmpty: boolean;
  emptyLabel?: string;
  children: ReactNode;
};

/** Panel frame: title + loading / error / empty states. */
export function PanelContainer({
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
    <section className="panel-card flex h-full flex-col">
      <header className="mb-3 flex items-center justify-between gap-2">
        <h3 className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
          {title}
        </h3>
        {isRefreshing ? (
          <span className="text-[10px] text-[var(--state-pending)]">
            Refreshing…
          </span>
        ) : isStale ? (
          <span className="text-[10px] text-[var(--state-pending)]">Stale</span>
        ) : null}
      </header>
      <div className="min-h-0 flex-1">
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

export default PanelContainer;
