import { Link } from "react-router-dom";

export function PlaceholderPage({
  title,
  body,
}: {
  title: string;
  body: string;
}) {
  return (
    <div className="panel-card max-w-lg space-y-2">
      <h1 className="text-sm font-bold uppercase tracking-wider">{title}</h1>
      <p className="text-xs text-[var(--text-secondary)]">{body}</p>
      <p className="text-[11px] text-[var(--text-muted)]">
        Phase 1 scaffold — full port lands in Phase 2–3 of the Bun rewrite plan.
      </p>
      <Link className="text-xs text-[var(--brand)] underline" to="/">
        Back to Overview
      </Link>
    </div>
  );
}
