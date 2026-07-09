export function LoadingSkeleton({ label }: { label?: string }) {
  return (
    <div
      className="flex h-full min-h-[3rem] items-center text-xs text-[var(--text-muted)]"
      role="status"
    >
      {label ?? "Loading…"}
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div
      className="rounded border border-[var(--sev-high)]/40 bg-[var(--surface-app)] px-2 py-2 text-xs text-[var(--sev-high)]"
      role="alert"
    >
      {message}
    </div>
  );
}

export function EmptyState({ title }: { title: string }) {
  return (
    <div className="flex h-full min-h-[3rem] items-center text-xs text-[var(--text-muted)]">
      {title}
    </div>
  );
}
