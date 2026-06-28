import type { ReactNode } from "react";

export function SectionHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return <header className="flex items-start justify-between gap-4"><div><h2 className="text-sm font-semibold text-[var(--text-primary)]">{title}</h2>{description ? <p className="mt-1 text-xs text-[var(--text-secondary)]">{description}</p> : null}</div>{actions}</header>;
}

export function StatCard({ label, value, detail }: { label: string; value: ReactNode; detail?: ReactNode }) {
  return <section className="panel-card"><h3 className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">{label}</h3><div className="mt-2 text-2xl font-bold text-[var(--text-primary)]">{value}</div>{detail ? <div className="mt-1 text-xs text-[var(--text-secondary)]">{detail}</div> : null}</section>;
}
