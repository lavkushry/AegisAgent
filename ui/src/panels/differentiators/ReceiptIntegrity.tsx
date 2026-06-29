"use client";

import React, { useState } from "react";
import { ShieldCheck, AlertTriangle, Loader2, Download, Check, X } from "lucide-react";
import { useDatasources } from "@/datasources/registry";
import { frameRows } from "@/datasources/frame";
import { formatTime, errorMessage } from "@/lib/format";
import HashChip from "@/components/security/HashChip";
import { ConfirmDialog, redactJson } from "@/components/primitives";
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

type RowState = { status: "verified" | "failed" | "unknown" | "running"; message?: string };
type Range =
  | { status: "idle" }
  | { status: "running"; checked: number; total: number }
  | { status: "ok"; total: number }
  | { status: "unknown"; message: string }
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
  const [exportConfirmOpen, setExportConfirmOpen] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  const rows = frameRows(data);
  const pick = (row: Record<string, unknown>, field: string): string => {
    const v = row[field];
    return v === null || v === undefined ? "" : String(v);
  };

  const verifyRange = async () => {
    if (!datasource?.verifyRange) {
      setRange({ status: "unknown", message: "Datasource cannot verify receipt ranges." });
      return;
    }
    setRange({ status: "running", checked: 0, total: rows.length });
    setRowStates(Object.fromEntries(rows.map((_, index) => [index, { status: "running" }])));
    try {
      const result = await datasource.verifyRange(rows);
      if (result.status === "verified") {
        setRowStates(Object.fromEntries(rows.map((_, index) => [index, { status: "verified", message: result.message }])));
        setRange({ status: "ok", total: rows.length });
        return;
      }
      if (result.status === "unknown") {
        setRowStates({});
        setRange({ status: "unknown", message: result.message });
        return;
      }
      const brokenAt = result.brokenAtRow ?? 1;
      setRowStates({ [brokenAt - 1]: { status: "failed", message: result.message } });
      setRange({ status: "failed", brokenAt, message: result.message });
    } catch (err: unknown) {
      setRowStates({});
      setRange({ status: "failed", brokenAt: 0, message: errorMessage(err) });
    }
  };

  const downloadBlob = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const exportGatewayPack = async () => {
    if (!datasource?.exportEvidencePack) return;
    setExportConfirmOpen(false);
    setIsExporting(true);
    setExportError(null);
    try {
      const blob = await datasource.exportEvidencePack();
      downloadBlob(blob, `aegis-evidence-pack-${Date.now()}.zip`);
    } catch (err: unknown) {
      setExportError(errorMessage(err));
    } finally {
      setIsExporting(false);
    }
  };

  const exportVisibleRows = () => {
    const pack = { exported_at: new Date().toISOString(), scope: "visible_rows_only", count: rows.length, receipts: redactJson(rows) };
    const blob = new Blob([JSON.stringify(pack, null, 2)], { type: "application/json" });
    downloadBlob(blob, `aegis-visible-receipts-local-${Date.now()}.json`);
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
            onClick={() => setExportConfirmOpen(true)}
            disabled={!datasource?.exportEvidencePack || isExporting}
            className="flex items-center gap-1.5 text-xs rounded-lg border border-[var(--border-default)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] px-3 py-1.5 cursor-pointer disabled:opacity-50"
            title={datasource?.exportEvidencePack ? "Gateway-authoritative compliance evidence ZIP" : "Gateway evidence export is unavailable"}
          >
            <Download size={13} /> {isExporting ? "Exporting…" : "Evidence pack (.zip)"}
          </button>
          <button
            onClick={exportVisibleRows}
            disabled={rows.length === 0}
            className="flex items-center gap-1.5 text-xs rounded-lg border border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-primary)] px-3 py-1.5 cursor-pointer disabled:opacity-50"
            title="Local JSON of currently loaded rows; not an authoritative compliance evidence pack"
          >
            <Download size={13} /> Visible rows (local)
          </button>
        </div>
      </div>
      {exportError ? <p className="mb-2 text-xs text-[var(--state-failed)]" role="alert">Evidence export failed: {exportError}</p> : null}

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
                ) : state?.status === "verified" ? (
                  <Check size={13} style={{ color: "var(--state-verified)" }} />
                ) : state?.status === "failed" ? (
                  <X size={13} style={{ color: "var(--state-failed)" }} />
                ) : state?.status === "unknown" ? (
                  <AlertTriangle size={13} style={{ color: "var(--state-pending)" }} />
                ) : null}
              </span>
            </div>
          );
        })}
      </div>
      <ConfirmDialog
        open={exportConfirmOpen}
        title="Export compliance evidence pack?"
        impact="The gateway will generate a tenant-scoped ZIP containing receipts, audit events, policies, incidents, and approval evidence. Handle it as sensitive audit material."
        target="Current tenant · gateway-authoritative export"
        confirmLabel="Export evidence pack"
        onConfirm={() => void exportGatewayPack()}
        onCancel={() => setExportConfirmOpen(false)}
      />
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
  if (range.status === "unknown") {
    return <span className="flex items-center gap-1.5 text-xs text-[var(--state-pending)]"><AlertTriangle size={13} /> Verification unknown: {range.message}</span>;
  }
  return <span className="text-xs text-[var(--text-muted)]">Chain not yet verified</span>;
}
