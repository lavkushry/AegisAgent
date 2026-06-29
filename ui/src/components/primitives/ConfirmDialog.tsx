"use client";

import { AlertTriangle } from "lucide-react";

export default function ConfirmDialog({ open, title, impact, target, reason, onReasonChange, confirmLabel = "Confirm", confirmDisabled = false, onConfirm, onCancel }: { open: boolean; title: string; impact: string; target: string; reason?: string; onReasonChange?: (value: string) => void; confirmLabel?: string; confirmDisabled?: boolean; onConfirm: () => void; onCancel: () => void }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onCancel()}>
      <section className="w-full max-w-md rounded-xl border border-[var(--border-default)] bg-[var(--surface-panel)] p-5 shadow-2xl" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title">
        <h2 id="confirm-title" className="flex items-center gap-2 font-semibold text-[var(--text-primary)]"><AlertTriangle size={18} className="text-[var(--state-pending)]" />{title}</h2>
        <p className="mt-3 text-sm text-[var(--text-secondary)]">{impact}</p>
        <p className="mt-2 rounded bg-[var(--surface-app)] p-2 font-mono text-xs text-[var(--text-primary)]">{target}</p>
        {onReasonChange ? <label className="mt-4 block text-xs text-[var(--text-secondary)]">Audit reason <span className="text-[var(--state-failed)]">(required)</span><textarea required value={reason ?? ""} onChange={(event) => onReasonChange(event.target.value)} className="mt-1 min-h-20 w-full rounded border border-[var(--border-default)] bg-[var(--surface-app)] p-2 text-[var(--text-primary)]" /></label> : null}
        <div className="mt-5 flex justify-end gap-2"><button type="button" onClick={onCancel} className="rounded border border-[var(--border-default)] px-3 py-2 text-xs">Cancel</button><button type="button" disabled={confirmDisabled} onClick={onConfirm} className="rounded bg-[var(--state-failed)] px-3 py-2 text-xs font-semibold text-white disabled:cursor-not-allowed disabled:opacity-50">{confirmLabel}</button></div>
      </section>
    </div>
  );
}
