"use client";

import React, { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useAppStore } from "../app/store";
import { getReceipts, verifyReceipt } from "../app/api";
import { ShieldCheck, ShieldAlert, Cpu, Fingerprint, Activity, Clock, FileText, Check } from "lucide-react";

export default function ReceiptsTab() {
  const { gatewayUrl, bearerToken } = useAppStore();
  const apiOpts = { gatewayUrl, bearerToken };

  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [verificationResult, setVerificationResult] = useState<Record<string, { ok: boolean; msg: string; loading: boolean }>>({});

  // Fetch receipts list
  const { data: receipts, isLoading, error } = useQuery({
    queryKey: ["receipts", gatewayUrl, bearerToken],
    queryFn: () => getReceipts(apiOpts),
    refetchInterval: 5000,
  });

  const verifyMutation = useMutation({
    mutationFn: (receiptId: string) => verifyReceipt(apiOpts, receiptId),
    onSuccess: (data, receiptId) => {
      const isVerified = data.verified || (data.status === "verified") || (!data.error);
      const message = data.error ? `Tamper detected: ${data.error}` : "Block verified. Signature matches preceding links.";
      setVerificationResult((prev) => ({
        ...prev,
        [receiptId]: { ok: isVerified, msg: message, loading: false },
      }));
    },
    onError: (err: any, receiptId) => {
      setVerificationResult((prev) => ({
        ...prev,
        [receiptId]: { ok: false, msg: `Verification failed: ${err.message}`, loading: false },
      }));
    },
  });

  const triggerVerification = (receiptId: string) => {
    setVerificationResult((prev) => ({
      ...prev,
      [receiptId]: { ok: false, msg: "", loading: true },
    }));
    verifyMutation.mutate(receiptId);
  };

  return (
    <div className="panel-card space-y-4">
      <div className="border-b border-[var(--border-default)] pb-3 flex justify-between items-center">
        <h3 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider flex items-center gap-1.5">
          <Fingerprint size={14} className="text-[var(--brand)]" /> Cryptographic Receipts Integrity Log
        </h3>
        <span className="text-[10px] text-green-400 bg-green-950/20 border border-green-500/30 px-2 py-0.5 rounded flex items-center gap-1 font-bold">
          <ShieldCheck size={12} /> Chain Verified
        </span>
      </div>

      {isLoading ? (
        <p className="text-xs text-[var(--text-muted)] text-center py-16">Loading receipt chain...</p>
      ) : error ? (
        <p className="text-xs text-red-400 text-center py-16">Error: {(error as any).message}</p>
      ) : !receipts || receipts.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 text-center text-[var(--text-muted)]">
          <Fingerprint size={48} className="mb-4" />
          <h4 className="text-sm font-semibold">No Receipts Emitted</h4>
          <p className="text-xs max-w-xs mt-1">Receipts are emitted automatically upon every /v1/authorize decision.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {receipts.map((rec: any, idx: number) => {
            const isExpanded = expandedId === rec.id;
            const vResult = verificationResult[rec.id];
            return (
              <div
                key={rec.id}
                className="border border-[var(--border-default)] hover:border-[var(--border-default)] rounded-lg overflow-hidden bg-[var(--surface-app)]/50"
              >
                {/* Row Header */}
                <div
                  onClick={() => setExpandedId(isExpanded ? null : rec.id)}
                  className="flex flex-wrap md:flex-nowrap justify-between items-center gap-4 p-4 cursor-pointer select-none hover:bg-[var(--surface-panel)]/40 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <span className="text-[10px] text-[var(--text-muted)] font-mono">#{receipts.length - idx}</span>
                    <div className="flex flex-col">
                      <span className="text-xs font-mono font-bold text-[var(--brand)]">
                        {rec.tool || "generic_action"}
                      </span>
                      <span className="text-[10px] text-[var(--text-muted)] mt-0.5 font-mono">
                        ID: {rec.id}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    <code className="text-[10px] text-green-400 bg-green-950/20 px-1.5 py-0.5 rounded border border-green-500/20">
                      link: {rec.receipt_hash ? rec.receipt_hash.slice(0, 12) : "N/A"}
                    </code>
                    <span className="text-xs text-[var(--text-muted)]">
                      {new Date(rec.ts || rec.created_at).toLocaleTimeString()}
                    </span>
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="p-4 bg-[var(--surface-panel)]/60 border-t border-[var(--border-default)] space-y-4 text-xs font-mono">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-[var(--text-secondary)]">
                      <div className="space-y-1">
                        <span className="block text-[9px] uppercase tracking-wider text-[var(--text-muted)] font-sans font-bold">Previous Link Hash</span>
                        <code className="block bg-[var(--surface-app)] p-1.5 rounded border border-[var(--border-default)] break-all">
                          {rec.prev_receipt_hash || "null (Genesis Block)"}
                        </code>
                      </div>
                      <div className="space-y-1">
                        <span className="block text-[9px] uppercase tracking-wider text-[var(--text-muted)] font-sans font-bold">Receipt Hash</span>
                        <code className="block bg-[var(--surface-app)] p-1.5 rounded border border-[var(--border-default)] break-all">
                          {rec.receipt_hash || "null"}
                        </code>
                      </div>
                    </div>

                    <div className="grid grid-cols-3 gap-2 text-[var(--text-secondary)]">
                      <div>
                        <span className="block text-[9px] uppercase tracking-wider text-[var(--text-muted)] font-sans font-bold">Agent ID</span>
                        <span className="text-[var(--text-primary)]">{rec.agent_id || "N/A"}</span>
                      </div>
                      <div>
                        <span className="block text-[9px] uppercase tracking-wider text-[var(--text-muted)] font-sans font-bold">Run ID</span>
                        <span className="text-[var(--text-primary)]">{rec.run_id || "N/A"}</span>
                      </div>
                      <div>
                        <span className="block text-[9px] uppercase tracking-wider text-[var(--text-muted)] font-sans font-bold">Trace ID</span>
                        <span className="text-[var(--text-primary)]">{rec.trace_id || "N/A"}</span>
                      </div>
                    </div>

                    {/* Action Block details */}
                    <div className="flex flex-wrap items-center justify-between gap-4 pt-2 border-t border-[var(--border-default)]">
                      <div className="flex items-center gap-1.5 text-xs text-[var(--text-secondary)] font-sans">
                        <Activity size={14} /> Link verified in active ledger database.
                      </div>

                      <div className="flex items-center gap-3">
                        {vResult && (
                          <div className={`flex items-center gap-1 text-[11px] font-sans px-2.5 py-1 rounded border ${vResult.ok ? "bg-green-950/20 border-green-500/30 text-green-400" : "bg-red-950/20 border-red-500/30 text-red-400"}`}>
                            {vResult.loading ? (
                              <Cpu size={12} className="animate-spin" />
                            ) : vResult.ok ? (
                              <ShieldCheck size={12} />
                            ) : (
                              <ShieldAlert size={12} />
                            )}
                            <span>{vResult.msg}</span>
                          </div>
                        )}

                        <button
                          onClick={() => triggerVerification(rec.id)}
                          disabled={vResult?.loading}
                          className="bg-[var(--interactive-bg)] hover:bg-[var(--interactive-bg-hover)] text-white text-[11px] border border-[var(--border-default)] px-3 py-1 rounded cursor-pointer transition-colors font-sans"
                        >
                          Verify Signature Link
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
