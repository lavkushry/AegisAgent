import { useState } from "react";
import {
  AlertTriangle,
  Check,
  Loader2,
  ShieldCheck,
  X,
} from "lucide-react";
import { useAppStore } from "@/app/store";
import { DecisionBadge } from "@/components/security/DecisionBadge";
import { HashChip } from "@/components/security/HashChip";
import { TrustBadge } from "@/components/security/TrustBadge";
import { frameRows } from "@/datasources/frame";
import {
  verifyReceipt,
  verifyReceiptRange,
  type ReceiptRecord,
  type VerifyResult,
  type VerifyStatus,
} from "@/domains/receipts";
import { errorMessage, formatTime } from "@/lib/format";
import type { PanelProps } from "../types";

export interface ProvableTimelineOptions {
  /** Max timeline rows (default: 25). */
  maxRows?: number;
  /** Show Verify range control (default: true). */
  showRangeVerify?: boolean;
}

type RowState =
  | { status: "idle" }
  | { status: "running" }
  | VerifyResult;

function rowToReceipt(row: Record<string, unknown>): ReceiptRecord {
  const id = String(row.id ?? row.receipt_id ?? "");
  return {
    id,
    tool: row.tool !== undefined ? String(row.tool) : undefined,
    receipt_hash:
      row.receipt_hash !== undefined ? String(row.receipt_hash) : undefined,
    prev_receipt_hash:
      row.prev_receipt_hash !== undefined
        ? String(row.prev_receipt_hash)
        : undefined,
    action_hash:
      row.action_hash !== undefined ? String(row.action_hash) : undefined,
    ts: row.ts !== undefined ? String(row.ts) : undefined,
    created_at:
      row.created_at !== undefined ? String(row.created_at) : undefined,
    agent_id: row.agent_id !== undefined ? String(row.agent_id) : undefined,
    run_id: row.run_id !== undefined ? String(row.run_id) : undefined,
    decision: row.decision !== undefined ? String(row.decision) : undefined,
    source_trust:
      row.source_trust !== undefined ? String(row.source_trust) : undefined,
  };
}

function StatusIcon({ status }: { status: VerifyStatus | "running" | "idle" }) {
  if (status === "running") {
    return <Loader2 size={12} className="animate-spin text-[var(--state-pending)]" />;
  }
  if (status === "verified") {
    return <Check size={12} className="text-[var(--state-verified)]" />;
  }
  if (status === "failed") {
    return <X size={12} className="text-[var(--state-failed)]" />;
  }
  if (status === "unknown") {
    return <AlertTriangle size={12} className="text-[var(--sev-medium)]" />;
  }
  return null;
}

function statusClass(status: string): string {
  if (status === "verified") return "text-[var(--state-verified)]";
  if (status === "failed") return "text-[var(--state-failed)]";
  if (status === "running") return "text-[var(--state-pending)]";
  if (status === "unknown") return "text-[var(--sev-medium)]";
  return "text-[var(--text-muted)]";
}

function rowStateMessage(state: RowState): string {
  if (state.status === "idle") return "";
  if (state.status === "running") return "Walking stored chain…";
  return state.message;
}

/**
 * ★ Differentiator panel — provable timeline of hash-chained receipts.
 *
 * Each row carries receipt_hash / prev link; Verify walks the gateway check
 * (fail-closed normalizeVerification). Verify range walks the stored chain.
 */
export default function ProvableTimelinePanel(
  props: PanelProps<ProvableTimelineOptions>,
) {
  const maxRows = props.definition.options?.maxRows ?? 25;
  const showRangeVerify = props.definition.options?.showRangeVerify !== false;

  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const apiOpts = {
    gatewayUrl,
    bearerToken,
    tenantId: activeTenant,
  };

  const receipts = frameRows(props.data)
    .slice(0, maxRows)
    .map(rowToReceipt)
    .filter((r) => r.id);

  const [rowStates, setRowStates] = useState<Record<string, RowState>>({});
  const [rangeResult, setRangeResult] = useState<RowState>({ status: "idle" });
  const [rangeBusy, setRangeBusy] = useState(false);

  const verifyOne = async (receiptId: string) => {
    setRowStates((prev) => ({ ...prev, [receiptId]: { status: "running" } }));
    try {
      const result = await verifyReceipt(apiOpts, receiptId);
      setRowStates((prev) => ({ ...prev, [receiptId]: result }));
    } catch (err: unknown) {
      setRowStates((prev) => ({
        ...prev,
        [receiptId]: {
          status: "failed",
          ok: false,
          message: errorMessage(err),
        },
      }));
    }
  };

  const runRange = async () => {
    setRangeBusy(true);
    setRangeResult({ status: "running" });
    try {
      const result = await verifyReceiptRange(apiOpts);
      setRangeResult(result);
    } catch (err: unknown) {
      setRangeResult({
        status: "failed",
        ok: false,
        message: errorMessage(err),
      });
    } finally {
      setRangeBusy(false);
    }
  };

  if (receipts.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-xs text-[var(--text-muted)]">
        No receipts in range
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col gap-2">
      {showRangeVerify ? (
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            className="btn-primary inline-flex items-center gap-1 text-[10px]"
            disabled={rangeBusy}
            onClick={() => void runRange()}
          >
            {rangeBusy ? (
              <Loader2 size={11} className="animate-spin" />
            ) : (
              <ShieldCheck size={11} />
            )}
            Verify chain
          </button>
          {rangeResult.status !== "idle" ? (
            <span
              role="status"
              className={`inline-flex items-center gap-1 text-[10px] ${statusClass(rangeResult.status)}`}
            >
              <StatusIcon status={rangeResult.status} />
              {rowStateMessage(rangeResult)}
            </span>
          ) : (
            <span className="text-[10px] text-[var(--text-muted)]">
              {receipts.length} linked receipt
              {receipts.length === 1 ? "" : "s"}
            </span>
          )}
        </div>
      ) : null}

      <ol className="min-h-0 flex-1 space-y-1.5 overflow-auto pr-1 custom-scrollbar">
        {receipts.map((receipt, index) => {
          const state = rowStates[receipt.id] ?? { status: "idle" as const };
          const ts = receipt.ts ?? receipt.created_at;
          const drill = props.definition.drilldowns?.[0];

          return (
            <li
              key={receipt.id}
              className="rounded border border-[var(--border-default)] bg-[var(--surface-app)] p-2"
              data-testid="provable-timeline-row"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-1.5 text-[10px]">
                    <span className="font-mono text-[var(--text-muted)]">
                      #{index + 1}
                    </span>
                    {receipt.decision ? (
                      <DecisionBadge decision={receipt.decision} />
                    ) : null}
                    <TrustBadge trust={receipt.source_trust} />
                    {ts ? (
                      <time className="text-[var(--text-muted)]">
                        {formatTime(ts)}
                      </time>
                    ) : null}
                  </div>
                  <div className="mt-1 font-mono text-[10px] text-[var(--text-secondary)] truncate">
                    {receipt.id}
                    {receipt.agent_id ? (
                      <span className="text-[var(--text-muted)]">
                        {" "}
                        · {receipt.agent_id}
                      </span>
                    ) : null}
                  </div>
                  <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px]">
                    <span className="inline-flex items-center gap-1">
                      <span className="text-[var(--text-muted)]">receipt</span>
                      <HashChip hash={receipt.receipt_hash} kind="receipt" />
                    </span>
                    <span className="inline-flex items-center gap-1">
                      <span className="text-[var(--text-muted)]">prev</span>
                      <HashChip
                        hash={
                          receipt.prev_receipt_hash === "genesis"
                            ? undefined
                            : receipt.prev_receipt_hash
                        }
                        kind="receipt"
                      />
                      {receipt.prev_receipt_hash === "genesis" ? (
                        <span className="font-mono text-[var(--text-muted)]">
                          genesis
                        </span>
                      ) : null}
                    </span>
                  </div>
                  {state.status !== "idle" && state.status !== "running" ? (
                    <p
                      className={`mt-1 text-[10px] ${statusClass(state.status)}`}
                      role="status"
                    >
                      {state.message}
                    </p>
                  ) : null}
                </div>
                <div className="flex shrink-0 flex-col items-end gap-1">
                  <button
                    type="button"
                    className="inline-flex items-center gap-1 rounded border border-[var(--border-default)] px-1.5 py-0.5 text-[10px] text-[var(--text-secondary)] disabled:opacity-50"
                    disabled={state.status === "running"}
                    onClick={() => void verifyOne(receipt.id)}
                    title="POST /v1/receipts/:id/verify"
                  >
                    <StatusIcon
                      status={
                        state.status === "idle" ? "idle" : state.status
                      }
                    />
                    {state.status === "running" ? "Verifying…" : "Verify"}
                  </button>
                  {drill ? (
                    <button
                      type="button"
                      className="text-[10px] text-[var(--brand)] underline-offset-2 hover:underline"
                      onClick={() =>
                        props.onDrilldown(
                          drill,
                          receipt as unknown as Record<string, unknown>,
                        )
                      }
                    >
                      {drill.label}
                    </button>
                  ) : null}
                </div>
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
