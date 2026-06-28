import { AlertTriangle, Inbox } from "lucide-react";

export function LoadingSkeleton({ label = "Loading" }: { label?: string }) {
  return <div className="h-full min-h-16 w-full animate-pulse rounded-md bg-[var(--surface-elevated)]/50" role="status" aria-label={label} />;
}

export function EmptyState({ title = "No data", detail }: { title?: string; detail?: string }) {
  return <div className="flex h-full min-h-16 flex-col items-center justify-center gap-1 text-center text-[var(--text-muted)]"><Inbox size={18} aria-hidden="true" /><strong className="text-xs">{title}</strong>{detail ? <p className="text-[11px]">{detail}</p> : null}</div>;
}

export function ErrorState({ message }: { message: string }) {
  return <div className="flex h-full min-h-16 items-center justify-center gap-2 text-center text-xs text-[var(--state-failed)]" role="alert"><AlertTriangle size={16} aria-hidden="true" /><span>{message}</span></div>;
}
