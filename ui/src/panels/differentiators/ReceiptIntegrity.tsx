"use client";

import React, { useEffect, useRef, useState } from "react";
import { useAppStore } from "@/app/store";
import { ShieldCheck, AlertTriangle, Loader2, Download, Check, X, ChevronDown } from "lucide-react";
import { useDatasources } from "@/datasources/registry";
import { frameRows } from "@/datasources/frame";
import { formatTime, errorMessage, resolveTimeToken } from "@/lib/format";
import HashChip from "@/components/security/HashChip";
import DecisionBadge from "@/components/security/DecisionBadge";
import TrustBadge from "@/components/security/TrustBadge";
import { ConfirmDialog, redactJson } from "@/components/primitives";
import type { PanelProps } from "../types";

export interface ReceiptIntegrityOptions {
  receiptIdField?: string;
  receiptHashField?: string;
  prevHashField?: string;
  timeField?: string;
  agentField?: string;
  decisionField?: string;
  trustField?: string;
  actionHashField?: string;
}

const DEFAULTS: Required<ReceiptIntegrityOptions> = {
  receiptIdField: "id",
  receiptHashField: "receipt_hash",
  prevHashField: "prev_receipt_hash",
  timeField: "ts",
  agentField: "agent_id",
  decisionField: "decision",
  trustField: "source_trust",
  actionHashField: "action_hash",
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
export default function ReceiptIntegrity({
  definition,
  data,
  timeRange,
}: PanelProps<ReceiptIntegrityOptions>) {
  const datasources = useDatasources();
  const datasource = datasources.get(definition.datasourceId);
  const opts = { ...DEFAULTS, ...(definition.options ?? {}) };
  const [rowStates, setRowStates] = useState<Record<number, RowState>>({});
  const [range, setRange] = useState<Range>({ status: "idle" });
  const [extraRows, setExtraRows] = useState<Array<Record<string, unknown>>>([]);
  const [tailCursor, setTailCursor] = useState<string | undefined>(undefined);
  const [loadingMore, setLoadingMore] = useState(false);
  const [loadMoreError, setLoadMoreError] = useState<string | null>(null);
  const [exportConfirmOpen, setExportConfirmOpen] = useState(false);
  const [exportReason, setExportReason] = useState("");
  const [isExporting, setIsExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const activeReceiptId = useAppStore((s) => s.activeReceiptId);
  const rowRefs = useRef<Record<string, HTMLDivElement | null>>({});

  const baseRows = frameRows(data);
  const rows = [...baseRows, ...extraRows];
  const nextCursor = tailCursor ?? data.meta?.cursor;

  useEffect(() => {
    setExtraRows([]);
    setTailCursor(undefined);
    setLoadMoreError(null);
    setRowStates({});
    setRange({ status: "idle" });
  }, [data.length, data.meta?.cursor, definition.id, timeRange.from, timeRange.to]);

  useEffect(() => {
    if (!activeReceiptId) return;
    const node = rowRefs.current[activeReceiptId];
    node?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [activeReceiptId, baseRows.length, extraRows.length]);

  const pick = (row: Record<string, unknown>, field: string): string => {
    const v = row[field];
    return v === null || v === undefined ? "" : String(v);
  };

  const pickTime = (row: Record<string, unknown>): string => {
    return pick(row, opts.timeField) || pick(row, "ts") || pick(row, "created_at");
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

  const verifyReceipt = async (index: number) => {
    if (!datasource?.verifyReceipt) {
      setRowStates((prev) => ({
        ...prev,
        [index]: { status: "unknown", message: "Datasource cannot verify receipts." },
      }));
      return;
    }
    const receiptId = pick(rows[index], opts.receiptIdField);
    if (!receiptId) {
      setRowStates((prev) => ({
        ...prev,
        [index]: { status: "unknown", message: "Receipt row has no ID." },
      }));
      return;
    }
    setRowStates((prev) => ({ ...prev, [index]: { status: "running" } }));
    try {
      const result = await datasource.verifyReceipt(receiptId);
      setRowStates((prev) => ({
        ...prev,
        [index]: { status: result.status, message: result.message },
      }));
    } catch (err: unknown) {
      setRowStates((prev) => ({
        ...prev,
        [index]: { status: "failed", message: errorMessage(err) },
      }));
    }
  };

  const loadMore = async () => {
    if (!datasource || !nextCursor) return;
    setLoadingMore(true);
    setLoadMoreError(null);
    try {
      const page = await datasource.query({
        entity: definition.entity ?? "receipt",
        timeRange,
        variables: {},
        cursor: nextCursor,
        limit: definition.limit ?? 50,
      });
      setExtraRows((prev) => [...prev, ...frameRows(page)]);
      setTailCursor(page.meta?.cursor);
    } catch (err: unknown) {
      setLoadMoreError(errorMessage(err));
    } finally {
      setLoadingMore(false);
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
    setExportReason("");
    setIsExporting(true);
    setExportError(null);
    try {
      const from = resolveTimeToken(timeRange.from);
      const to = resolveTimeToken(timeRange.to);
      const blob = await datasource.exportEvidencePack({ from, to });
      downloadBlob(blob, `aegis-evidence-pack-${Date.now()}.zip`);
    } catch (err: unknown) {
      setExportError(errorMessage(err));
    } finally {
      setIsExporting(false);
    }
  };

  const exportVisibleRows = () => {
    const pack = {
      exported_at: new Date().toISOString(),
      scope: "visible_rows_only",
      count: rows.length,
      receipts: redactJson(rows),
    };
    const blob = new Blob([JSON.stringify(pack, null, 2)], { type: "application/json" });
    downloadBlob(blob, `aegis-visible-receipts-local-${Date.now()}.json`);
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between gap-3 pb-2 mb-2 border-b border-[var(--border-default)]">
        <RangeStatus range={range} />
        <div className="flex items-center gap-2 flex-wrap justify-end">
          <button
            onClick={() => void verifyRange()}
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
      {loadMoreError ? <p className="mb-2 text-xs text-[var(--state-failed)]" role="alert">Load more failed: {loadMoreError}</p> : null}

      <div className="flex-1 overflow-auto custom-scrollbar space-y-1 pr-1">
        {rows.map((row, i) => {
          const state = rowStates[i];
          const broken = state?.status === "failed";
          const prevHash = pick(row, opts.prevHashField);
          const receiptHash = pick(row, opts.receiptHashField) || pick(row, opts.receiptIdField);
          const actionHash = pick(row, opts.actionHashField);
          const agentId = pick(row, opts.agentField);
          const decision = pick(row, opts.decisionField);
          const trust = pick(row, opts.trustField) || pick(row, "root_trust_level");
          const rowReceiptId = pick(row, opts.receiptIdField) || pick(row, "id");
          const focused = Boolean(activeReceiptId && rowReceiptId === activeReceiptId);
          return (
            <div
              key={String(row.id ?? `${receiptHash}-${i}`)}
              ref={(el) => {
                if (rowReceiptId) rowRefs.current[rowReceiptId] = el;
              }}
              className="flex flex-wrap items-center gap-2 text-xs py-2 px-2 rounded border"
              style={{
                borderColor: focused
                  ? "var(--border-active)"
                  : broken
                    ? "var(--state-failed)"
                    : "var(--border-default)",
                backgroundColor: focused
                  ? "color-mix(in oklab, var(--brand) 12%, transparent)"
                  : broken
                    ? "color-mix(in oklab, var(--state-failed) 12%, transparent)"
                    : "transparent",
              }}
            >
              <span className="w-6 text-[var(--text-muted)] font-mono shrink-0">{i + 1}</span>
              <span className="text-[var(--text-muted)] font-mono w-16 shrink-0">
                {formatTime(pickTime(row))}
              </span>
              {decision ? <DecisionBadge decision={decision} /> : null}
              {trust ? <TrustBadge trust={trust} /> : null}
              <span className="font-mono text-[var(--text-secondary)] truncate max-w-[8rem]" title={agentId}>
                {agentId || "—"}
              </span>
              {actionHash ? <HashChip hash={actionHash} kind="action" /> : null}
              <HashChip hash={prevHash || "genesis"} kind="receipt" />
              <span className="text-[var(--text-muted)]">→</span>
              <HashChip hash={receiptHash} kind="receipt" />
              <span className="ml-auto shrink-0 flex items-center gap-2">
                {state?.status === "running" ? (
                  <Loader2 size={13} className="animate-spin text-[var(--state-pending)]" />
                ) : state?.status === "verified" ? (
                  <span title={state.message}><Check size={13} style={{ color: "var(--state-verified)" }} /></span>
                ) : state?.status === "failed" ? (
                  <span title={state.message}><X size={13} style={{ color: "var(--state-failed)" }} /></span>
                ) : state?.status === "unknown" ? (
                  <span title={state.message}><AlertTriangle size={13} style={{ color: "var(--state-pending)" }} /></span>
                ) : null}
                <button
                  type="button"
                  onClick={() => void verifyReceipt(i)}
                  disabled={state?.status === "running"}
                  className="text-[10px] rounded border border-[var(--border-default)] px-2 py-0.5 text-[var(--text-secondary)] hover:text-[var(--text-primary)] cursor-pointer disabled:opacity-50"
                >
                  Verify receipt
                </button>
              </span>
            </div>
          );
        })}
      </div>

      {nextCursor ? (
        <div className="pt-2 border-t border-[var(--border-default)]">
          <button
            type="button"
            onClick={() => void loadMore()}
            disabled={loadingMore}
            className="flex w-full items-center justify-center gap-1.5 text-xs rounded-lg border border-[var(--border-default)] px-3 py-2 text-[var(--text-secondary)] hover:text-[var(--text-primary)] cursor-pointer disabled:opacity-50"
          >
            {loadingMore ? <Loader2 size={13} className="animate-spin" /> : <ChevronDown size={13} />}
            {loadingMore ? "Loading more receipts…" : "Load more receipts"}
          </button>
        </div>
      ) : null}

      <ConfirmDialog
        open={exportConfirmOpen}
        title="Export compliance evidence pack?"
        impact="The gateway will generate a tenant-scoped ZIP containing receipts, audit events, policies, incidents, and approval evidence. Handle it as sensitive audit material."
        target="Current tenant · gateway-authoritative export"
        reason={exportReason}
        onReasonChange={setExportReason}
        confirmLabel="Export evidence pack"
        confirmDisabled={!exportReason.trim() || isExporting}
        onConfirm={() => void exportGatewayPack()}
        onCancel={() => {
          setExportConfirmOpen(false);
          setExportReason("");
        }}
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