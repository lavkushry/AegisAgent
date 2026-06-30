"use client";

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "../app/store";
import { downloadFromGateway, getIncidents, getIncidentDetail, fetchFromGateway, getIncidentGraph, verifyReceipt, type IncidentNarration } from "../app/api";
import { normalizeVerification } from "@/datasources/receiptVerification";
import { AlertOctagon, CheckSquare, FileText, Download, ShieldCheck, Activity, ShieldAlert, AlertTriangle } from "lucide-react";
import SeverityTag from "./security/SeverityTag";
import { errorMessage } from "@/lib/format";
import { ConfirmDialog } from "@/components/primitives";

type PendingIncidentAction = {
  kind: "close" | "export";
  incidentId: string;
};

export default function IncidentsTab() {
  const { gatewayUrl, bearerToken, activeTenant, authEpoch } = useAppStore();
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };
  const queryClient = useQueryClient();

  const selectedIncidentId = useAppStore((state) => state.activeIncidentId);
  const setSelectedIncidentId = useAppStore((state) => state.setActiveIncidentId);
  const [verifyingTimeline, setVerifyingTimeline] = useState(false);
  const [verificationOutput, setVerificationOutput] = useState<{
    status: "verified" | "failed" | "unknown";
    msg: string;
  } | null>(null);
  const [pendingAction, setPendingAction] = useState<PendingIncidentAction | null>(null);
  const [auditReason, setAuditReason] = useState("");
  const [exportingEvidence, setExportingEvidence] = useState(false);

  // Fetch list of incidents
  const { data: incidents, isLoading: isIncidentsLoading } = useQuery({
    queryKey: ["incidents", gatewayUrl, activeTenant, authEpoch],
    queryFn: () => getIncidents(apiOpts),
    refetchInterval: 5000,
  });

  // Fetch details for the selected incident
  const { data: incidentDetail, isLoading: isDetailLoading } = useQuery({
    queryKey: ["incidentDetail", gatewayUrl, activeTenant, authEpoch, selectedIncidentId],
    queryFn: () => getIncidentDetail(apiOpts, selectedIncidentId!),
    enabled: !!selectedIncidentId,
  });

  // Fetch RCA narration
  const { data: narration, isLoading: isNarrationLoading } = useQuery({
    queryKey: ["incidentNarration", gatewayUrl, activeTenant, authEpoch, selectedIncidentId],
    queryFn: () => fetchFromGateway<IncidentNarration>(apiOpts, `/v1/incidents/${selectedIncidentId}/narrate`),
    enabled: !!selectedIncidentId,
  });

  // Fetch evidence graph
  const { data: graph, isLoading: isGraphLoading } = useQuery({
    queryKey: ["incidentGraph", gatewayUrl, activeTenant, authEpoch, selectedIncidentId],
    queryFn: () => getIncidentGraph(apiOpts, selectedIncidentId!),
    enabled: !!selectedIncidentId,
  });

  // Mutation to close incident
  const closeIncidentMutation = useMutation({
    mutationFn: (id: string) => fetchFromGateway<Record<string, unknown>>(apiOpts, `/v1/incidents/${id}/close`, "POST"),
    onSuccess: () => {
      setPendingAction(null);
      setAuditReason("");
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["incidentDetail", selectedIncidentId] });
      queryClient.invalidateQueries({ queryKey: ["socSummary"] });
    },
  });

  const handleCloseIncident = (id: string) => {
    setPendingAction({ kind: "close", incidentId: id });
    setAuditReason("");
  };

  const handleDownloadEvidencePack = (id: string) => {
    setPendingAction({ kind: "export", incidentId: id });
    setAuditReason("");
  };

  const confirmIncidentAction = async () => {
    if (!pendingAction || !auditReason.trim()) return;
    if (pendingAction.kind === "close") {
      closeIncidentMutation.mutate(pendingAction.incidentId);
      return;
    }
    setExportingEvidence(true);
    try {
      const blob = await downloadFromGateway(apiOpts, `/v1/incidents/${pendingAction.incidentId}/evidence-pack`);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `aegis-incident-${pendingAction.incidentId}-evidence-pack.zip`;
      anchor.click();
      URL.revokeObjectURL(url);
      setPendingAction(null);
      setAuditReason("");
    } finally {
      setExportingEvidence(false);
    }
  };

  const handleVerifyTimeline = async () => {
    if (!graph || !graph.nodes) return;
    setVerifyingTimeline(true);
    setVerificationOutput(null);

    // Find all receipt nodes in the graph
    const receiptNodes = graph.nodes.filter((node) => node.group === "receipt");

    if (receiptNodes.length === 0) {
      setVerificationOutput({
        status: "unknown",
        msg: "No receipts are available, so this timeline cannot be verified.",
      });
      setVerifyingTimeline(false);
      return;
    }

    try {
      let allOk = true;
      let checkedCount = 0;
      for (const node of receiptNodes) {
        const verifyRes = await verifyReceipt(apiOpts, node.id);
        const result = normalizeVerification(verifyRes);
        if (result.status !== "verified") {
          allOk = false;
          setVerificationOutput({ status: result.status, msg: result.message });
          break;
        }
        checkedCount++;
      }

      if (allOk) {
        setVerificationOutput({
          status: "verified",
          msg: `Cryptographic validation complete: All ${checkedCount} actions in this incident timeline verified as tamper-free.`,
        });
      }
    } catch (err: unknown) {
      setVerificationOutput({
        status: "failed",
        msg: `Verification failed: ${errorMessage(err)}`,
      });
    } finally {
      setVerifyingTimeline(false);
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Incidents List (Left Side) */}
      <div className="panel-card lg:col-span-1 space-y-4">
        <h3 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">
          Security Incidents Case List
        </h3>
        
        {isIncidentsLoading ? (
          <p className="text-xs text-[var(--text-muted)] text-center py-8">Loading incidents list...</p>
        ) : !incidents || incidents.length === 0 ? (
          <p className="text-xs text-[var(--text-muted)] text-center py-8">No incidents recorded.</p>
        ) : (
          <div className="space-y-2 overflow-y-auto max-h-[500px] custom-scrollbar">
            {incidents.map((inc) => (
              <div
                key={inc.id}
                onClick={() => {
                  setSelectedIncidentId(inc.id);
                  setVerificationOutput(null);
                }}
                className={`p-3 border rounded-lg cursor-pointer transition-colors text-xs ${
                  selectedIncidentId === inc.id
                    ? "bg-[var(--brand)]/10 border-[var(--border-active)]"
                    : "bg-[var(--surface-app)]/40 border-[var(--border-default)] hover:border-[var(--border-default)]"
                }`}
              >
                <div className="flex justify-between items-start gap-2">
                  <SeverityTag severity={inc.severity} />
                  <span className={`text-[10px] font-semibold ${inc.status === "open" ? "text-red-400" : "text-green-400"}`}>
                    {(inc.status ?? "unknown").toUpperCase()}
                  </span>
                </div>
                <h4 className="font-semibold mt-2 text-[var(--text-primary)] truncate">{inc.kind}</h4>
                <p className="text-[var(--text-secondary)] text-[11px] mt-1 line-clamp-2">{inc.summary}</p>
                <div className="flex justify-between items-center text-[10px] text-[var(--text-muted)] mt-3">
                  <span>Agent: {inc.agent_id}</span>
                  <span>{new Date(inc.opened_at ?? 0).toLocaleDateString()}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Incident Detail Pane (Right Side) */}
      <div className="panel-card lg:col-span-2 space-y-6">
        {!selectedIncidentId ? (
          <div className="flex flex-col items-center justify-center py-32 text-center text-[var(--text-muted)]">
            <AlertOctagon size={48} className="mb-4" />
            <h4 className="text-sm font-semibold">No Incident Selected</h4>
            <p className="text-xs max-w-xs mt-1">Select an incident from the list to view the correlated provable evidence timeline.</p>
          </div>
        ) : isDetailLoading ? (
          <p className="text-sm text-[var(--text-muted)] text-center py-32">Loading incident details...</p>
        ) : !incidentDetail ? (
          <p className="text-sm text-red-400 text-center py-32">Incident details not found.</p>
        ) : (
          <div className="space-y-6">
            {/* Header Block */}
            <div className="flex flex-wrap items-start justify-between gap-4 pb-4 border-b border-[var(--border-default)]">
              <div>
                <h2 className="text-base font-bold text-rose-500 flex items-center gap-1.5">
                  <ShieldAlert size={18} /> {incidentDetail.kind}
                </h2>
                <div className="flex items-center gap-2 mt-1.5 text-xs text-[var(--text-secondary)]">
                  <span>Incident ID: <code className="text-[var(--text-primary)]">{incidentDetail.id.slice(-12)}</code></span>
                  <span>&middot;</span>
                  <span>Agent: <code className="text-[var(--brand)]">{incidentDetail.agent_id}</code></span>
                </div>
              </div>

              <div className="flex gap-2">
                <button
                  onClick={() => handleDownloadEvidencePack(incidentDetail.id)}
                  disabled={exportingEvidence}
                  className="flex items-center gap-1.5 bg-[var(--interactive-bg)] hover:bg-[var(--interactive-bg-hover)] text-[var(--text-primary)] border border-[var(--border-default)] px-3.5 py-1.5 rounded-lg text-xs transition-colors cursor-pointer"
                >
                  <Download size={14} /> Download Evidence Pack
                </button>

                {incidentDetail.status === "open" ? (
                  <button
                    onClick={() => handleCloseIncident(incidentDetail.id)}
                    disabled={closeIncidentMutation.isPending}
                    className="flex items-center gap-1.5 bg-green-700 hover:bg-green-800 text-white px-3.5 py-1.5 rounded-lg text-xs transition-colors cursor-pointer disabled:opacity-50"
                  >
                    <CheckSquare size={14} /> Resolve Case
                  </button>
                ) : (
                  <span className="bg-green-950/20 border border-green-500/30 text-green-400 font-bold px-3 py-1.5 rounded-lg text-xs">
                    Case Resolved
                  </span>
                )}
              </div>
            </div>

            {/* RCA Narrative (AI generated, sandboxed LLM) */}
            <div className="p-4 bg-[var(--surface-app)] border border-[var(--border-default)] rounded-lg">
              <h4 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <FileText size={14} className="text-[var(--brand)]" /> Root Cause Analysis (RCA) Narration
              </h4>
              {isNarrationLoading ? (
                <p className="text-xs text-[var(--text-muted)] py-2">Narrating incident timeline...</p>
              ) : (
                <div className="text-xs text-[var(--text-primary)] leading-relaxed whitespace-pre-wrap font-sans prose prose-invert max-w-none">
                  {narration?.narrative || narration?.summary || "RCA narrative is being prepared for this incident."}
                </div>
              )}
            </div>

            {/* Provable Cryptographic Timeline */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider flex items-center gap-1.5">
                  <Activity size={14} className="text-[var(--brand)]" /> Provable Incident Timeline
                </h4>
                
                <button
                  onClick={handleVerifyTimeline}
                  disabled={isGraphLoading || verifyingTimeline}
                  className="text-xs text-[var(--brand)] hover:text-[var(--brand)] font-medium underline flex items-center gap-1 cursor-pointer disabled:opacity-50"
                >
                  <ShieldCheck size={14} /> {verifyingTimeline ? "Verifying..." : "Verify Cryptographic Timeline"}
                </button>
              </div>

              {/* Verification Output Bar */}
              {verificationOutput && (
                <div className={`p-3 border rounded-lg text-xs flex items-center gap-2 ${
                  verificationOutput.status === "verified"
                    ? "bg-green-950/20 border-green-500/30 text-green-400"
                    : verificationOutput.status === "unknown"
                      ? "bg-amber-950/20 border-amber-500/30 text-amber-400"
                      : "bg-red-950/20 border-red-500/30 text-red-400"
                }`}>
                  {verificationOutput.status === "verified" ? <ShieldCheck size={16} /> : <AlertTriangle size={16} />}
                  <span>{verificationOutput.msg}</span>
                </div>
              )}

              {/* Timeline Nodes */}
              <div className="space-y-2 max-h-[300px] overflow-y-auto custom-scrollbar">
                {isGraphLoading ? (
                  <p className="text-xs text-[var(--text-muted)] text-center py-6">Reconstructing timeline graph...</p>
                ) : !graph || !graph.nodes || graph.nodes.length === 0 ? (
                  <p className="text-xs text-[var(--text-muted)] text-center py-6 font-mono">No actions bound to this incident case.</p>
                ) : (
                  graph.nodes
                    .filter((node) => node.group === "decision" || node.group === "receipt" || node.group === "approval")
                    .sort((a, b) => (a.timestamp || "").localeCompare(b.timestamp || ""))
                    .map((node, idx: number) => (
                      <div
                        key={idx}
                        className="flex justify-between items-center gap-4 p-3 bg-[var(--surface-app)]/30 border border-[var(--border-default)] rounded-lg text-xs"
                      >
                        <div className="flex items-center gap-2">
                          <span className={`w-2.5 h-2.5 rounded-full ${
                            node.group === "receipt" ? "bg-green-500" : node.group === "approval" ? "bg-amber-500" : "bg-[var(--brand)]"
                          }`} />
                          <div className="flex flex-col">
                            <span className="font-semibold text-[var(--text-primary)]">{node.label}</span>
                            {node.metadata !== undefined && node.metadata !== null && (
                              <span className="text-[10px] text-[var(--text-muted)] font-mono mt-0.5 truncate max-w-[300px]">
                                {typeof node.metadata === "string" ? node.metadata : JSON.stringify(node.metadata)}
                              </span>
                            )}
                          </div>
                        </div>

                        <span className="text-[10px] text-[var(--text-muted)] font-mono whitespace-nowrap">
                          {node.timestamp ? new Date(node.timestamp).toLocaleTimeString() : ""}
                        </span>
                      </div>
                    ))
                )}
              </div>
            </div>
          </div>
        )}
      </div>
      <ConfirmDialog
        open={pendingAction !== null}
        title={pendingAction?.kind === "close" ? "Resolve this incident?" : "Export this incident evidence pack?"}
        impact={
          pendingAction?.kind === "close"
            ? "This marks the incident as closed. Confirm only after the evidence, proof, and containment state have been reviewed."
            : "This downloads a gateway-generated evidence pack for the incident. Exported material may contain sensitive operational metadata and should be handled as audit evidence."
        }
        target={pendingAction?.incidentId ?? ""}
        reason={auditReason}
        onReasonChange={setAuditReason}
        confirmLabel={pendingAction?.kind === "close" ? "Resolve incident" : "Export evidence pack"}
        confirmDisabled={!auditReason.trim() || closeIncidentMutation.isPending || exportingEvidence}
        onConfirm={() => void confirmIncidentAction()}
        onCancel={() => {
          setPendingAction(null);
          setAuditReason("");
        }}
      />
    </div>
  );
}
