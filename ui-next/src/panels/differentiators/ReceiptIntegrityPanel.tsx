import { useState } from "react";
import {
  AlertTriangle,
  Check,
  Download,
  Loader2,
  ShieldCheck,
  X,
} from "lucide-react";
import { useAppStore } from "@/app/store";
import { HashChip } from "@/components/security/HashChip";
import { frameRows } from "@/datasources/frame";
import {
  downloadComplianceEvidencePack,
  exportInvestigationEvidence,
} from "@/domains/evidence";
import {
  verifyReceiptRange,
  type VerifyResult,
} from "@/domains/receipts";
import { triggerBlobDownload } from "@/lib/http/client";
import { errorMessage } from "@/lib/format";
import type { PanelProps } from "../types";
import { summarizeChain } from "./receiptIntegrityModel";

export interface ReceiptIntegrityOptions {
  /** Show evidence pack download buttons (default: true). */
  showExports?: boolean;
  /** Show Verify range control (default: true). */
  showRangeVerify?: boolean;
}

type RangeState =
  | { status: "idle" }
  | { status: "running" }
  | VerifyResult;

function rangeMessage(state: RangeState): string {
  if (state.status === "idle") return "";
  if (state.status === "running") return "Walking stored chain…";
  return state.message;
}

function rangeClass(status: string): string {
  if (status === "verified") return "text-[var(--state-verified)]";
  if (status === "failed") return "text-[var(--state-failed)]";
  if (status === "running") return "text-[var(--state-pending)]";
  if (status === "unknown") return "text-[var(--sev-medium)]";
  return "text-[var(--text-muted)]";
}

/**
 * ★ Differentiator panel — receipt chain integrity control surface.
 *
 * Complements provable-timeline (per-row verify): chain summary stats,
 * Verify range, and investigation / compliance evidence pack exports.
 * Renders even when the receipt frame is empty so exports stay available.
 */
export default function ReceiptIntegrityPanel(
  props: PanelProps<ReceiptIntegrityOptions>,
) {
  const showExports = props.definition.options?.showExports !== false;
  const showRangeVerify = props.definition.options?.showRangeVerify !== false;

  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const apiOpts = {
    gatewayUrl,
    bearerToken,
    tenantId: activeTenant,
  };

  const summary = summarizeChain(frameRows(props.data));

  const [rangeResult, setRangeResult] = useState<RangeState>({
    status: "idle",
  });
  const [rangeBusy, setRangeBusy] = useState(false);
  const [exporting, setExporting] = useState<
    "investigation" | "compliance" | null
  >(null);
  const [exportFlash, setExportFlash] = useState<string | null>(null);

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

  const runExport = async (kind: "investigation" | "compliance") => {
    setExporting(kind);
    setExportFlash(null);
    try {
      const blob =
        kind === "investigation"
          ? await exportInvestigationEvidence(apiOpts, {})
          : await downloadComplianceEvidencePack(apiOpts);
      triggerBlobDownload(
        blob,
        kind === "investigation"
          ? `aegis-investigation-evidence-${Date.now()}.zip`
          : `aegis-compliance-evidence-${Date.now()}.zip`,
      );
      setExportFlash(`${kind} evidence pack downloaded.`);
    } catch (err: unknown) {
      setExportFlash(errorMessage(err));
    } finally {
      setExporting(null);
    }
  };

  return (
    <div
      className="flex h-full flex-col gap-3"
      data-testid="receipt-integrity-panel"
    >
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <div className="rounded border border-[var(--border-default)] bg-[var(--surface-app)] px-2 py-1.5">
          <div className="text-[9px] uppercase tracking-wider text-[var(--text-muted)]">
            Receipts
          </div>
          <div className="tabular-nums text-sm font-semibold text-[var(--text-primary)]">
            {summary.count}
          </div>
        </div>
        <div className="rounded border border-[var(--border-default)] bg-[var(--surface-app)] px-2 py-1.5">
          <div className="text-[9px] uppercase tracking-wider text-[var(--text-muted)]">
            Agents
          </div>
          <div className="tabular-nums text-sm font-semibold text-[var(--text-primary)]">
            {summary.uniqueAgents}
          </div>
        </div>
        <div className="rounded border border-[var(--border-default)] bg-[var(--surface-app)] px-2 py-1.5">
          <div className="text-[9px] uppercase tracking-wider text-[var(--text-muted)]">
            Genesis links
          </div>
          <div className="tabular-nums text-sm font-semibold text-[var(--text-primary)]">
            {summary.genesisLinks}
          </div>
        </div>
        <div className="rounded border border-[var(--border-default)] bg-[var(--surface-app)] px-2 py-1.5 min-w-0">
          <div className="text-[9px] uppercase tracking-wider text-[var(--text-muted)]">
            Head hash
          </div>
          <div className="mt-0.5 truncate">
            <HashChip hash={summary.headHash ?? undefined} kind="receipt" />
          </div>
        </div>
      </div>

      {summary.headId ? (
        <p className="font-mono text-[10px] text-[var(--text-muted)] truncate">
          head id {summary.headId}
        </p>
      ) : (
        <p className="text-[10px] text-[var(--text-muted)]">
          No receipts loaded — verify range and exports still hit the gateway.
        </p>
      )}

      <div className="flex flex-wrap items-center gap-2">
        {showRangeVerify ? (
          <button
            type="button"
            className="btn-primary inline-flex items-center gap-1 text-[10px]"
            disabled={rangeBusy}
            onClick={() => void runRange()}
            title="POST /v1/receipts/verify-range"
          >
            {rangeBusy ? (
              <Loader2 size={11} className="animate-spin" />
            ) : (
              <ShieldCheck size={11} />
            )}
            Verify range
          </button>
        ) : null}

        {showExports ? (
          <>
            <button
              type="button"
              className="inline-flex items-center gap-1 rounded border border-[var(--border-default)] px-2 py-0.5 text-[10px] text-[var(--text-secondary)] disabled:opacity-50"
              disabled={exporting !== null}
              onClick={() => void runExport("investigation")}
              title="POST /v1/evidence/export"
            >
              <Download size={11} />
              {exporting === "investigation"
                ? "Exporting…"
                : "Investigation pack"}
            </button>
            <button
              type="button"
              className="inline-flex items-center gap-1 rounded border border-[var(--border-default)] px-2 py-0.5 text-[10px] text-[var(--text-secondary)] disabled:opacity-50"
              disabled={exporting !== null}
              onClick={() => void runExport("compliance")}
              title="GET /v1/compliance/evidence-pack"
            >
              <Download size={11} />
              {exporting === "compliance" ? "Exporting…" : "Compliance pack"}
            </button>
          </>
        ) : null}
      </div>

      {rangeResult.status !== "idle" ? (
        <div
          role="status"
          className={`flex items-start gap-1.5 text-[10px] ${rangeClass(rangeResult.status)}`}
        >
          {rangeResult.status === "running" ? (
            <Loader2 size={12} className="mt-0.5 shrink-0 animate-spin" />
          ) : rangeResult.status === "verified" ? (
            <Check size={12} className="mt-0.5 shrink-0" />
          ) : rangeResult.status === "failed" ? (
            <AlertTriangle size={12} className="mt-0.5 shrink-0" />
          ) : (
            <X size={12} className="mt-0.5 shrink-0" />
          )}
          <span>{rangeMessage(rangeResult)}</span>
        </div>
      ) : null}

      {exportFlash ? (
        <p className="text-[10px] text-[var(--text-secondary)]" role="status">
          {exportFlash}
        </p>
      ) : null}
    </div>
  );
}
