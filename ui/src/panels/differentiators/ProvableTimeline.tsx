"use client";

import React, { useState } from "react";
import { ShieldCheck, AlertTriangle, Loader2, Fingerprint } from "lucide-react";
import { useDatasources } from "@/datasources/registry";
import { frameRows } from "@/datasources/frame";
import { formatTime, errorMessage } from "@/lib/format";
import DecisionBadge from "@/components/security/DecisionBadge";
import HashChip from "@/components/security/HashChip";
import type { PanelProps } from "../types";

export interface ProvableTimelineOptions {
  timeField?: string;
  labelField?: string;
  agentField?: string;
  decisionField?: string;
  receiptIdField?: string;
  receiptHashField?: string;
}

type Verify =
  | { status: "idle" }
  | { status: "running"; checked: number; total: number }
  | { status: "ok"; total: number }
  | { status: "failed"; brokenAt: number; message: string };

const DEFAULTS: Required<ProvableTimelineOptions> = {
  timeField: "created_at",
  labelField: "decision",
  agentField: "agent_id",
  decisionField: "decision",
  receiptIdField: "id",
  receiptHashField: "receipt_hash",
};

/**
 * The Provable Timeline — ordered events, each carrying its receipt, with a
 * one-click chain walk that proves the sequence is tamper-free or points at
 * the first broken link. The investigation differentiator.
 */
export default function ProvableTimeline({ definition, data, onDrilldown }: PanelProps<ProvableTimelineOptions>) {
  const datasources = useDatasources();
  const datasource = datasources.get(definition.datasourceId);
  const opts = { ...DEFAULTS, ...(definition.options ?? {}) };
  const [verify, setVerify] = useState<Verify>({ status: "idle" });

  const rows = frameRows(data);

  const pick = (row: Record<string, unknown>, field: string): string => {
    const v = row[field];
    return v === null || v === undefined ? "" : String(v);
  };

  const runVerify = async () => {
    if (!datasource?.verifyReceipt) {
      setVerify({ status: "failed", brokenAt: 0, message: "Datasource cannot verify receipts." });
      return;
    }
    setVerify({ status: "running", checked: 0, total: rows.length });
    for (let i = 0; i < rows.length; i++) {
      const receiptId = pick(rows[i], opts.receiptIdField);
      try {
        const result = await datasource.verifyReceipt(receiptId);
        if (!result.ok) {
          setVerify({ status: "failed", brokenAt: i + 1, message: result.message });
          return;
        }
      } catch (err: unknown) {
        setVerify({ status: "failed", brokenAt: i + 1, message: errorMessage(err) });
        return;
      }
      setVerify({ status: "running", checked: i + 1, total: rows.length });
    }
    setVerify({ status: "ok", total: rows.length });
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between gap-3 pb-2 mb-2 border-b border-[var(--border-default)]">
        <VerifyStatus verify={verify} />
        <button
          onClick={runVerify}
          disabled={verify.status === "running" || rows.length === 0}
          className="flex items-center gap-1.5 text-xs rounded-lg border px-3 py-1.5 cursor-pointer disabled:opacity-50"
          style={{ color: "var(--state-verified)", borderColor: "color-mix(in oklab, var(--state-verified) 40%, transparent)" }}
        >
          <Fingerprint size={13} /> Verify chain
        </button>
      </div>

      <ol className="flex-1 overflow-auto custom-scrollbar space-y-1 pr-1">
        {rows.map((row, i) => {
          const broken = verify.status === "failed" && verify.brokenAt === i + 1;
          const receiptId = pick(row, opts.receiptIdField);
          const receiptHash = pick(row, opts.receiptHashField) || receiptId;
          return (
            <li
              key={String(row.id ?? i)}
              className="flex items-center gap-3 text-xs py-1.5 px-2 rounded border"
              style={{
                borderColor: broken ? "var(--state-failed)" : "transparent",
                backgroundColor: broken ? "color-mix(in oklab, var(--state-failed) 12%, transparent)" : "transparent",
              }}
            >
              <span className="text-[var(--text-muted)] font-mono w-16 shrink-0">
                {formatTime(pick(row, opts.timeField))}
              </span>
              <DecisionBadge decision={pick(row, opts.decisionField) || undefined} />
              <span className="font-mono text-[var(--text-secondary)] truncate flex-1">
                {pick(row, opts.labelField) || "event"}
                <span className="text-[var(--text-muted)]"> · {pick(row, opts.agentField)}</span>
              </span>
              <HashChip
                hash={receiptHash}
                kind="receipt"
                onDrilldown={
                  definition.drilldowns?.[0]
                    ? () => onDrilldown(definition.drilldowns![0], row)
                    : undefined
                }
              />
            </li>
          );
        })}
      </ol>
    </div>
  );
}

function VerifyStatus({ verify }: { verify: Verify }) {
  if (verify.status === "running") {
    return (
      <span className="flex items-center gap-1.5 text-xs text-[var(--state-pending)]">
        <Loader2 size={13} className="animate-spin" /> Verifying {verify.checked}/{verify.total} links
      </span>
    );
  }
  if (verify.status === "ok") {
    return (
      <span className="flex items-center gap-1.5 text-xs" style={{ color: "var(--state-verified)" }}>
        <ShieldCheck size={13} /> Tamper-free ({verify.total}/{verify.total} links)
      </span>
    );
  }
  if (verify.status === "failed") {
    return (
      <span className="flex items-center gap-1.5 text-xs" style={{ color: "var(--state-failed)" }}>
        <AlertTriangle size={13} /> Broken at event {verify.brokenAt}: {verify.message}
      </span>
    );
  }
  return <span className="text-xs text-[var(--text-muted)]">Chain not yet verified</span>;
}
