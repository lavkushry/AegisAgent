"use client";

import React, { useMemo, useState } from "react";
import { ShieldCheck, AlertTriangle, Loader2, Fingerprint, Check, X } from "lucide-react";
import { useDatasources } from "@/datasources/registry";
import { RECEIPT_DATASOURCE_ID } from "@/datasources/receipt";
import { frameRows } from "@/datasources/frame";
import { formatTime, errorMessage } from "@/lib/format";
import DecisionBadge from "@/components/security/DecisionBadge";
import HashChip from "@/components/security/HashChip";
import type { PanelProps } from "../types";
import {
  applyRangeVerificationResult,
  pickTimelineField,
  pickTimelineTime,
  sortTimelineRows,
  timelineRowsForVerify,
  type ChainVerifyState,
  type ProvableTimelineFieldOptions,
  type RowVerifyState,
} from "./provableTimelineState";

export interface ProvableTimelineOptions {
  timeField?: string;
  labelField?: string;
  agentField?: string;
  decisionField?: string;
  receiptIdField?: string;
  receiptHashField?: string;
  prevHashField?: string;
}

const DEFAULTS: ProvableTimelineFieldOptions = {
  timeField: "created_at",
  labelField: "decision",
  agentField: "agent_id",
  decisionField: "decision",
  receiptIdField: "receipt_id",
  receiptHashField: "receipt_hash",
  prevHashField: "prev_receipt_hash",
};

/**
 * The Provable Timeline — ordered events, each carrying its receipt, with a
 * one-click chain walk that proves the sequence is tamper-free or points at
 * the first broken link. The investigation differentiator.
 */
export default function ProvableTimeline({ definition, data, timeRange, onDrilldown }: PanelProps<ProvableTimelineOptions>) {
  const datasources = useDatasources();
  const receiptDatasource = datasources.get(RECEIPT_DATASOURCE_ID);
  const opts = { ...DEFAULTS, ...(definition.options ?? {}) };
  const [chain, setChain] = useState<ChainVerifyState>({ status: "idle" });
  const [rowStates, setRowStates] = useState<Record<number, RowVerifyState>>({});
  const [verifiedScopeKey, setVerifiedScopeKey] = useState<string | null>(null);

  const rows = useMemo(
    () => sortTimelineRows(frameRows(data), opts.timeField),
    [data, opts.timeField],
  );

  const scopeKey = useMemo(
    () => `${data.length}:${data.meta?.cursor ?? ""}:${definition.id}:${timeRange.from}:${timeRange.to}`,
    [data.length, data.meta?.cursor, definition.id, timeRange.from, timeRange.to],
  );
  const verificationStale = verifiedScopeKey !== scopeKey;
  const displayChain = verificationStale && chain.status !== "running" ? { status: "idle" as const } : chain;
  const displayRowStates = verificationStale && chain.status !== "running" ? {} : rowStates;

  const runVerify = async () => {
    if (!receiptDatasource?.verifyRange) {
      setChain({ status: "unknown", message: "Receipt datasource cannot verify ordered linkage." });
      setRowStates({});
      return;
    }
    if (rows.length === 0) {
      setChain({ status: "unknown", message: "No timeline events are available to verify." });
      setRowStates({});
      return;
    }

    setChain({ status: "running" });
    setRowStates({});

    try {
      const payload = timelineRowsForVerify(rows, opts);
      const result = await receiptDatasource.verifyRange(payload);
      const applied = applyRangeVerificationResult(result, rows.length);
      setChain(applied.chain);
      setRowStates(applied.rowStates);
      setVerifiedScopeKey(scopeKey);
    } catch (err: unknown) {
      setChain({ status: "failed", brokenAt: 0, message: errorMessage(err) });
      setRowStates({});
      setVerifiedScopeKey(scopeKey);
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between gap-3 pb-2 mb-2 border-b border-[var(--border-default)]">
        <ChainVerifyStatus chain={displayChain} />
        <button
          type="button"
          onClick={() => void runVerify()}
          disabled={displayChain.status === "running" || rows.length === 0}
          className="flex items-center gap-1.5 text-xs rounded-lg border px-3 py-1.5 cursor-pointer disabled:opacity-50"
          style={{ color: "var(--state-verified)", borderColor: "color-mix(in oklab, var(--state-verified) 40%, transparent)" }}
        >
          <Fingerprint size={13} /> Verify chain
        </button>
      </div>

      <ol className="flex-1 overflow-auto custom-scrollbar space-y-1 pr-1">
        {rows.map((row, index) => {
          const state = displayRowStates[index];
          const broken = displayChain.status === "failed" && displayChain.brokenAt === index + 1;
          const receiptHash =
            pickTimelineField(row, opts.receiptHashField)
            || pickTimelineField(row, "receipt_hash")
            || pickTimelineField(row, opts.receiptIdField);
          const prevHash =
            pickTimelineField(row, opts.prevHashField)
            || pickTimelineField(row, "prev_receipt_hash");
          const drilldown = definition.drilldowns?.[0];

          return (
            <li
              key={String(row.id ?? `${receiptHash}-${index}`)}
              className="flex flex-wrap items-center gap-2 text-xs py-1.5 px-2 rounded border"
              style={{
                borderColor: broken ? "var(--state-failed)" : "var(--border-default)",
                backgroundColor: broken ? "color-mix(in oklab, var(--state-failed) 12%, transparent)" : "transparent",
              }}
            >
              <span className="w-6 text-[var(--text-muted)] font-mono shrink-0">{index + 1}</span>
              <span className="text-[var(--text-muted)] font-mono w-16 shrink-0">
                {formatTime(pickTimelineTime(row, opts.timeField))}
              </span>
              <DecisionBadge decision={pickTimelineField(row, opts.decisionField) || undefined} />
              <span className="font-mono text-[var(--text-secondary)] truncate flex-1 min-w-[8rem]">
                {pickTimelineField(row, opts.labelField) || "event"}
                <span className="text-[var(--text-muted)]"> · {pickTimelineField(row, opts.agentField)}</span>
              </span>
              <HashChip hash={prevHash || "genesis"} kind="receipt" />
              <span className="text-[var(--text-muted)]">→</span>
              <HashChip
                hash={receiptHash}
                kind="receipt"
                onDrilldown={drilldown ? () => onDrilldown(drilldown, row) : undefined}
              />
              <span className="ml-auto shrink-0">
                {state?.status === "verified" ? (
                  <span title={state.message}><Check size={13} style={{ color: "var(--state-verified)" }} /></span>
                ) : state?.status === "failed" ? (
                  <span title={state.message}><X size={13} style={{ color: "var(--state-failed)" }} /></span>
                ) : state?.status === "unknown" ? (
                  <span title={state.message}><AlertTriangle size={13} style={{ color: "var(--state-pending)" }} /></span>
                ) : null}
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

function ChainVerifyStatus({ chain }: { chain: ChainVerifyState }) {
  if (chain.status === "running") {
    return (
      <span className="flex items-center gap-1.5 text-xs text-[var(--state-pending)]">
        <Loader2 size={13} className="animate-spin" /> Verifying ordered receipt linkage…
      </span>
    );
  }
  if (chain.status === "verified") {
    return (
      <span className="flex items-center gap-1.5 text-xs" style={{ color: "var(--state-verified)" }} title={chain.message}>
        <ShieldCheck size={13} /> Tamper-free ({chain.total}/{chain.total} links)
      </span>
    );
  }
  if (chain.status === "failed") {
    return (
      <span className="flex items-center gap-1.5 text-xs" style={{ color: "var(--state-failed)" }} title={chain.message}>
        <AlertTriangle size={13} />
        {chain.brokenAt > 0
          ? `Broken at event ${chain.brokenAt}: ${chain.message}`
          : chain.message}
      </span>
    );
  }
  if (chain.status === "unknown") {
    return (
      <span className="flex items-center gap-1.5 text-xs text-[var(--state-pending)]" title={chain.message}>
        <AlertTriangle size={13} /> {chain.message}
      </span>
    );
  }
  return <span className="text-xs text-[var(--text-muted)]">Chain not yet verified</span>;
}