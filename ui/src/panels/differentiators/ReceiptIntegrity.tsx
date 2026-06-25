"use client";

import React, { useState } from "react";
import { ShieldCheck, AlertTriangle, Loader2, Download, Check, X } from "lucide-react";
import { useDatasources } from "@/datasources/registry";
import { frameRows } from "@/datasources/frame";
import { formatTime, errorMessage } from "@/lib/format";
import HashChip from "@/components/security/HashChip";
import type { PanelProps } from "../types";

export interface ReceiptIntegrityOptions {
  receiptIdField?: string;
  receiptHashField?: string;
  prevHashField?: string;
  timeField?: string;
}

const DEFAULTS: Required<ReceiptIntegrityOptions> = {
  receiptIdField: "id",
  receiptHashField: "receipt_hash",
  prevHashField: "prev_hash",
  timeField: "created_at",
};

type RowState = { status: "ok" | "failed" | "running"; message?: string };
type Range =
  | { status: "idle" }
  | { status: "running"; checked: number; total: number }
  | { status: "ok"; total: number }
  | { status: "failed"; brokenAt: number; message: string };

/**
 * The Receipt Integrity viewer — browse the per-tenant hash chain, verify a
 * range, and visualize a break. A broken link is also a P1 detection
 * (receipt-chain-broken). Evidence-pack export for SOC 2 / EU AI Act Art. 14.
 */
export default function ReceiptIntegrity({ definition, data }: PanelProps<ReceiptIntegrityOptions>) {
  const datasources = useDatasources();
  const datasource = datasources.get(definition.datasourceId);
  const opts = { ...DEFAULTS, ...(definition.options ?? {}) };
  const [rowStates, setRowStates] = useState<Record<number, RowState>>({});
  const [range, setRange] = useState<Range>({ status: "idle" });

  const rows = frameRows(data);
  const pick = (row: Record<string, unknown>, field: string): string => {
    const v = row[field];
    return v === null || v === undefined ? "" : String(v);
  };

  const verifyRange = async () => {
    if (!datasource?.verifyReceipt) {
      setRange({ status: "failed", brokenAt: 0, message: "Datasource cannot verify receipts." });
      return;
    }
    setRange({ status: "running", checked: 0, total: rows.length });
    const next: Record<number, RowState> = {};
    for (let i = 0; i < rows.length; i++) {
      const id = pick(rows[i], opts.receiptIdField);
      try {
        const result = await datasource.verifyReceipt(id);
        next[i] = { status: result.ok ? "ok" : "failed", message: result.message };
        setRowStates({ ...next });
        if (!result.ok) {
          setRange({ status: "failed", brokenAt: i + 1, message: result.message });
          return;
        }
      } catch (err: unknown) {
        next[i] = { status: "failed", message: errorMessage(err) };
        setRowStates({ ...next });
        setRange({ status: "failed", brokenAt: i + 1, message: errorMessage(err) });
        return;
      }
      setRange({ status: "running", checked: i + 1, total: rows.length });
    }
    setRange({ status: "ok", total: rows.length });
  };

  const exportPack = () => {
    const pack = { exported_at: new Date().toISOString(), count: rows.length, receipts: rows };
    const blob = new Blob([JSON.stringify(pack, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aegis-evidence-pack-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between gap-3 pb-2 mb-2 border-b border-[var(--border-default)]">
        <RangeStatus range={range} />
        <div className="flex items-center gap-2">
          <button
            onClick={verifyRange}
            disabled={range.status === "running" || rows.length === 0}
            className="flex items-center gap-1.5 text-xs rounded-lg border px-3 py-1.5 cursor-pointer disabled:opacity-50"
            style={{ color: "var(--state-verified)", borderColor: "color-mix(in oklab, var(--state-verified) 40%, transparent)" }}
          >
            <ShieldCheck size={13} /> Verify range
          </button>
          <button
            onClick={exportPack}
            disabled={rows.length === 0}
            className="flex items-center gap-1.5 text-xs rounded-lg border border-[var(--border-default)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] px-3 py-1.5 cursor-pointer disabled:opacity-50"
          >
            <Download size={13} /> Export pack
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto custom-scrollbar space-y-1 pr-1">
        {rows.map((row, i) => {
          const state = rowStates[i];
          const broken = state?.status === "failed";
          return (
            <div
              key={String(row.id ?? i)}
              className="flex items-center gap-3 text-xs py-1.5 px-2 rounded border"
              style={{
                borderColor: broken ? "var(--state-failed)" : "transparent",
                backgroundColor: broken ? "color-mix(in oklab, var(--state-failed) 12%, transparent)" : "transparent",
              }}
            >
              <span className="w-6 text-[var(--text-muted)] font-mono shrink-0">{i + 1}</span>
              <span className="text-[var(--text-muted)] font-mono w-16 shrink-0">
                {formatTime(pick(row, opts.timeField))}
              </span>
              <HashChip hash={pick(row, opts.receiptHashField) || pick(row, opts.receiptIdField)} kind="receipt" />
              <span className="ml-auto shrink-0">
                {state?.status === "running" ? (
                  <Loader2 size={13} className="animate-spin text-[var(--state-pending)]" />
                ) : state?.status === "ok" ? (
                  <Check size={13} style={{ color: "var(--state-verified)" }} />
                ) : state?.status === "failed" ? (
                  <X size={13} style={{ color: "var(--state-failed)" }} />
                ) : null}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function RangeStatus({ range }: { range: Range }) {
  if (range.status === "running") {
    return (
      <span className="flex items-center gap-1.5 text-xs text-[var(--state-pending)]">
        <Loader2 size={13} className="animate-spin" /> Verifying {range.checked}/{range.total}
      </span>
    );
  }
  if (range.status === "ok") {
    return (
      <span className="flex items-center gap-1.5 text-xs" style={{ color: "var(--state-verified)" }}>
        <ShieldCheck size={13} /> Chain tamper-free ({range.total} receipts)
      </span>
    );
  }
  if (range.status === "failed") {
    return (
      <span className="flex items-center gap-1.5 text-xs" style={{ color: "var(--state-failed)" }}>
        <AlertTriangle size={13} /> Broken at receipt {range.brokenAt}
      </span>
    );
  }
  return <span className="text-xs text-[var(--text-muted)]">Chain not yet verified</span>;
}
