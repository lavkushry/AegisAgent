import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  Check,
  Download,
  Loader2,
  ShieldCheck,
  X,
} from "lucide-react";
import { useAppStore } from "@/app/store";
import { TenantGate } from "@/components/TenantGate";
import { HashChip } from "@/components/security/HashChip";
import { TrustBadge } from "@/components/security/TrustBadge";
import { DecisionBadge } from "@/components/security/DecisionBadge";
import {
  listReceipts,
  verifyReceipt,
  verifyReceiptRange,
  type VerifyResult,
} from "@/domains/receipts";
import {
  downloadComplianceEvidencePack,
  exportInvestigationEvidence,
} from "@/domains/evidence";
import { triggerBlobDownload } from "@/lib/http/client";
import { errorMessage, formatTime } from "@/lib/format";

type RowState =
  | { status: "idle" }
  | { status: "running" }
  | VerifyResult;

function rangeBannerMessage(state: RowState): string {
  if (state.status === "idle") return "";
  if (state.status === "running") return "Walking stored chain…";
  return state.message;
}

export function IntegrityPage() {
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const tenantReady = Boolean(activeTenant.trim());
  const apiOpts = {
    gatewayUrl,
    bearerToken,
    tenantId: activeTenant,
  };

  const [rowStates, setRowStates] = useState<Record<string, RowState>>({});
  const [rangeResult, setRangeResult] = useState<RowState>({ status: "idle" });
  const [exporting, setExporting] = useState<"investigation" | "compliance" | null>(
    null,
  );
  const [exportFlash, setExportFlash] = useState<string | null>(null);

  const { data, error, isLoading, isFetching, refetch } = useQuery({
    queryKey: ["receipts", gatewayUrl, bearerToken, activeTenant],
    queryFn: () => listReceipts(apiOpts, 50),
    enabled: tenantReady,
    refetchInterval: 15_000,
    retry: false,
  });

  const rangeMutation = useMutation({
    mutationFn: () => verifyReceiptRange(apiOpts),
    onMutate: () => setRangeResult({ status: "running" }),
    onSuccess: (result) => setRangeResult(result),
    onError: (err: unknown) =>
      setRangeResult({
        status: "failed",
        ok: false,
        message: errorMessage(err),
      }),
  });

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

  if (!tenantReady) {
    return <TenantGate title="Select a tenant for Integrity" />;
  }

  const rows = data ?? [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-sm font-bold uppercase tracking-wider">
            Integrity
          </h1>
          <p className="mt-1 text-[11px] text-[var(--text-muted)]">
            Receipt hash chain — verify links to detect tampering
            {isFetching ? " · refreshing…" : null}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            className="btn-primary inline-flex items-center gap-1"
            disabled={rangeMutation.isPending}
            onClick={() => rangeMutation.mutate()}
          >
            {rangeMutation.isPending ? (
              <Loader2 size={12} className="animate-spin" />
            ) : (
              <ShieldCheck size={12} />
            )}
            Verify range
          </button>
          <button
            type="button"
            className="inline-flex items-center gap-1 rounded-md border border-[var(--border-default)] px-3 py-1.5 text-xs text-[var(--text-secondary)] disabled:opacity-50"
            disabled={exporting !== null}
            onClick={() => runExport("investigation")}
            title="POST /v1/evidence/export"
          >
            <Download size={12} />
            {exporting === "investigation" ? "Exporting…" : "Investigation pack"}
          </button>
          <button
            type="button"
            className="inline-flex items-center gap-1 rounded-md border border-[var(--border-default)] px-3 py-1.5 text-xs text-[var(--text-secondary)] disabled:opacity-50"
            disabled={exporting !== null}
            onClick={() => runExport("compliance")}
            title="GET /v1/compliance/evidence-pack"
          >
            <Download size={12} />
            {exporting === "compliance" ? "Exporting…" : "Compliance pack"}
          </button>
          <button
            type="button"
            className="rounded-md border border-[var(--border-default)] px-3 py-1.5 text-xs text-[var(--text-secondary)]"
            onClick={() => refetch()}
          >
            Refresh
          </button>
        </div>
      </div>

      {exportFlash ? (
        <p className="text-[11px] text-[var(--text-secondary)]" role="status">
          {exportFlash}
        </p>
      ) : null}

      {rangeResult.status !== "idle" ? (
        <div
          role="status"
          className={`panel-card flex items-start gap-2 text-xs ${
            rangeResult.status === "verified"
              ? "text-[var(--state-verified)]"
              : rangeResult.status === "failed"
                ? "text-[var(--state-failed)]"
                : rangeResult.status === "running"
                  ? "text-[var(--state-pending)]"
                  : "text-[var(--text-secondary)]"
          }`}
        >
          {rangeResult.status === "running" ? (
            <Loader2 size={14} className="mt-0.5 shrink-0 animate-spin" />
          ) : rangeResult.status === "verified" ? (
            <Check size={14} className="mt-0.5 shrink-0" />
          ) : rangeResult.status === "failed" ? (
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
          ) : (
            <X size={14} className="mt-0.5 shrink-0" />
          )}
          <span>{rangeBannerMessage(rangeResult)}</span>
        </div>
      ) : null}

      {isLoading && (
        <p className="text-xs text-[var(--text-muted)]">Loading receipts…</p>
      )}
      {error && (
        <div className="panel-card text-xs text-[var(--sev-high)]">
          {errorMessage(error)}
        </div>
      )}

      {!isLoading && !error && rows.length === 0 ? (
        <div className="panel-card text-xs text-[var(--text-secondary)]">
          No receipts for this tenant yet.
        </div>
      ) : null}

      <div className="space-y-2">
        {rows.map((r) => {
          const state = rowStates[r.id] ?? { status: "idle" as const };
          return (
            <article
              key={r.id}
              className="panel-card flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between"
            >
              <div className="min-w-0 space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[10px] text-[var(--text-muted)]">
                    {r.id}
                  </span>
                  {r.decision ? <DecisionBadge decision={r.decision} /> : null}
                  {r.source_trust ? (
                    <TrustBadge trust={r.source_trust} />
                  ) : null}
                </div>
                <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px]">
                  <span className="text-[var(--text-muted)]">
                    {formatTime(r.ts ?? r.created_at) || "—"}
                  </span>
                  <span className="font-mono text-[var(--text-secondary)]">
                    agent {r.agent_id ?? "—"}
                  </span>
                  {r.tool ? (
                    <span className="text-[var(--text-secondary)]">{r.tool}</span>
                  ) : null}
                </div>
                <div className="flex flex-wrap gap-3">
                  <div>
                    <div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
                      receipt_hash
                    </div>
                    <HashChip hash={r.receipt_hash} kind="receipt" />
                  </div>
                  <div>
                    <div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
                      prev
                    </div>
                    <HashChip hash={r.prev_receipt_hash} kind="receipt" />
                  </div>
                </div>
                {state.status !== "idle" && state.status !== "running" ? (
                  <p
                    className={`text-[11px] ${
                      state.status === "verified"
                        ? "text-[var(--state-verified)]"
                        : state.status === "failed"
                          ? "text-[var(--state-failed)]"
                          : "text-[var(--text-secondary)]"
                    }`}
                  >
                    {state.message}
                  </p>
                ) : null}
              </div>
              <button
                type="button"
                className="shrink-0 rounded-md border border-[var(--border-default)] px-3 py-1.5 text-xs font-medium text-[var(--text-primary)] hover:bg-[var(--interactive-bg-hover)] disabled:opacity-50"
                disabled={state.status === "running"}
                onClick={() => verifyOne(r.id)}
              >
                {state.status === "running" ? (
                  <span className="inline-flex items-center gap-1">
                    <Loader2 size={12} className="animate-spin" /> Verifying
                  </span>
                ) : (
                  "Verify"
                )}
              </button>
            </article>
          );
        })}
      </div>
    </div>
  );
}
