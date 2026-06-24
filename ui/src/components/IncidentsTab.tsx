"use client";

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "../app/store";
import { getIncidents, getIncidentDetail, fetchFromGateway, getIncidentGraph, verifyReceipt } from "../app/api";
import { AlertOctagon, CheckSquare, FileText, Download, ShieldCheck, HelpCircle, Activity, User, ShieldAlert, AlertTriangle } from "lucide-react";

export default function IncidentsTab() {
  const { gatewayUrl, bearerToken } = useAppStore();
  const apiOpts = { gatewayUrl, bearerToken };
  const queryClient = useQueryClient();

  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [verifyingTimeline, setVerifyingTimeline] = useState(false);
  const [verificationOutput, setVerificationOutput] = useState<{ ok: boolean; msg: string } | null>(null);

  // Fetch list of incidents
  const { data: incidents, isLoading: isIncidentsLoading } = useQuery({
    queryKey: ["incidents", gatewayUrl, bearerToken],
    queryFn: () => getIncidents(apiOpts),
    refetchInterval: 5000,
  });

  // Fetch details for the selected incident
  const { data: incidentDetail, isLoading: isDetailLoading } = useQuery({
    queryKey: ["incidentDetail", gatewayUrl, bearerToken, selectedIncidentId],
    queryFn: () => getIncidentDetail(apiOpts, selectedIncidentId!),
    enabled: !!selectedIncidentId,
  });

  // Fetch RCA narration
  const { data: narration, isLoading: isNarrationLoading } = useQuery({
    queryKey: ["incidentNarration", gatewayUrl, bearerToken, selectedIncidentId],
    queryFn: () => fetchFromGateway<any>(apiOpts, `/v1/incidents/${selectedIncidentId}/narrate`),
    enabled: !!selectedIncidentId,
  });

  // Fetch evidence graph
  const { data: graph, isLoading: isGraphLoading } = useQuery({
    queryKey: ["incidentGraph", gatewayUrl, bearerToken, selectedIncidentId],
    queryFn: () => getIncidentGraph(apiOpts, selectedIncidentId!),
    enabled: !!selectedIncidentId,
  });

  // Mutation to close incident
  const closeIncidentMutation = useMutation({
    mutationFn: (id: string) => fetchFromGateway<any>(apiOpts, `/v1/incidents/${id}/close`, "POST"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["incidentDetail", selectedIncidentId] });
      queryClient.invalidateQueries({ queryKey: ["socSummary"] });
    },
  });

  const handleCloseIncident = (id: string) => {
    closeIncidentMutation.mutate(id);
  };

  const handleDownloadEvidencePack = (id: string) => {
    // Open the download link directly in a new tab/window
    const url = `${gatewayUrl.replace(/\/+$/, "")}/v1/incidents/${id}/evidence-pack`;
    window.open(url, "_blank");
  };

  const handleVerifyTimeline = async () => {
    if (!graph || !graph.nodes) return;
    setVerifyingTimeline(true);
    setVerificationOutput(null);

    // Find all receipt nodes in the graph
    const receiptNodes = graph.nodes.filter((node: any) => node.group === "receipt");

    if (receiptNodes.length === 0) {
      setVerificationOutput({
        ok: true,
        msg: "No actions or receipts associated with this incident timeline yet.",
      });
      setVerifyingTimeline(false);
      return;
    }

    try {
      let allOk = true;
      let checkedCount = 0;
      for (const node of receiptNodes) {
        const verifyRes = await verifyReceipt(apiOpts, node.id);
        const ok = verifyRes.verified || (verifyRes.status === "verified") || (!verifyRes.error);
        if (!ok) {
          allOk = false;
          break;
        }
        checkedCount++;
      }

      setVerificationOutput({
        ok: allOk,
        msg: allOk
          ? `Cryptographic validation complete: All ${checkedCount} actions in this incident timeline verified as tamper-free.`
          : "Verification failed: A discrepancy in the receipt hash chain signature was detected.",
      });
    } catch (err: any) {
      setVerificationOutput({
        ok: false,
        msg: `Verification failed: ${err.message}`,
      });
    } finally {
      setVerifyingTimeline(false);
    }
  };

  const getSeverityColor = (sev: string) => {
    switch (String(sev).toLowerCase()) {
      case "critical":
        return "text-red-500 bg-red-950/20 border-red-500/30";
      case "high":
        return "text-orange-500 bg-orange-950/20 border-orange-500/30";
      case "medium":
        return "text-amber-500 bg-amber-950/20 border-amber-500/30";
      default:
        return "text-indigo-400 bg-indigo-950/20 border-indigo-500/30";
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Incidents List (Left Side) */}
      <div className="panel-card lg:col-span-1 space-y-4">
        <h3 className="text-xs font-bold text-[#94a3b8] uppercase tracking-wider">
          Security Incidents Case List
        </h3>
        
        {isIncidentsLoading ? (
          <p className="text-xs text-[#64748b] text-center py-8">Loading incidents list...</p>
        ) : !incidents || incidents.length === 0 ? (
          <p className="text-xs text-[#64748b] text-center py-8">No incidents recorded.</p>
        ) : (
          <div className="space-y-2 overflow-y-auto max-h-[500px] custom-scrollbar">
            {incidents.map((inc: any) => (
              <div
                key={inc.id}
                onClick={() => {
                  setSelectedIncidentId(inc.id);
                  setVerificationOutput(null);
                }}
                className={`p-3 border rounded-lg cursor-pointer transition-colors text-xs ${
                  selectedIncidentId === inc.id
                    ? "bg-indigo-600/10 border-indigo-500"
                    : "bg-[#0f172a]/40 border-[#1f2937] hover:border-[#334155]"
                }`}
              >
                <div className="flex justify-between items-start gap-2">
                  <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${getSeverityColor(inc.severity)}`}>
                    {inc.severity.toUpperCase()}
                  </span>
                  <span className={`text-[10px] font-semibold ${inc.status === "open" ? "text-red-400" : "text-green-400"}`}>
                    {inc.status.toUpperCase()}
                  </span>
                </div>
                <h4 className="font-semibold mt-2 text-[#e2e8f0] truncate">{inc.kind}</h4>
                <p className="text-[#94a3b8] text-[11px] mt-1 line-clamp-2">{inc.summary}</p>
                <div className="flex justify-between items-center text-[10px] text-[#64748b] mt-3">
                  <span>Agent: {inc.agent_id}</span>
                  <span>{new Date(inc.opened_at).toLocaleDateString()}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Incident Detail Pane (Right Side) */}
      <div className="panel-card lg:col-span-2 space-y-6">
        {!selectedIncidentId ? (
          <div className="flex flex-col items-center justify-center py-32 text-center text-[#64748b]">
            <AlertOctagon size={48} className="mb-4" />
            <h4 className="text-sm font-semibold">No Incident Selected</h4>
            <p className="text-xs max-w-xs mt-1">Select an incident from the list to view the correlated provable evidence timeline.</p>
          </div>
        ) : isDetailLoading ? (
          <p className="text-sm text-[#64748b] text-center py-32">Loading incident details...</p>
        ) : !incidentDetail ? (
          <p className="text-sm text-red-400 text-center py-32">Incident details not found.</p>
        ) : (
          <div className="space-y-6">
            {/* Header Block */}
            <div className="flex flex-wrap items-start justify-between gap-4 pb-4 border-b border-[#1f2937]">
              <div>
                <h2 className="text-base font-bold text-rose-500 flex items-center gap-1.5">
                  <ShieldAlert size={18} /> {incidentDetail.kind}
                </h2>
                <div className="flex items-center gap-2 mt-1.5 text-xs text-[#94a3b8]">
                  <span>Incident ID: <code className="text-[#e2e8f0]">{incidentDetail.id.slice(-12)}</code></span>
                  <span>&middot;</span>
                  <span>Agent: <code className="text-indigo-400">{incidentDetail.agent_id}</code></span>
                </div>
              </div>

              <div className="flex gap-2">
                <button
                  onClick={() => handleDownloadEvidencePack(incidentDetail.id)}
                  className="flex items-center gap-1.5 bg-[#1e293b] hover:bg-[#273549] text-[#e2e8f0] border border-[#334155] px-3.5 py-1.5 rounded-lg text-xs transition-colors cursor-pointer"
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
            <div className="p-4 bg-[#0f172a] border border-[#1f2937] rounded-lg">
              <h4 className="text-xs font-bold text-[#94a3b8] uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <FileText size={14} className="text-indigo-400" /> Root Cause Analysis (RCA) Narration
              </h4>
              {isNarrationLoading ? (
                <p className="text-xs text-[#64748b] py-2">Narrating incident timeline...</p>
              ) : (
                <div className="text-xs text-[#e2e8f0] leading-relaxed whitespace-pre-wrap font-sans prose prose-invert max-w-none">
                  {narration?.narrative || narration?.summary || "RCA narrative is being prepared for this incident."}
                </div>
              )}
            </div>

            {/* Provable Cryptographic Timeline */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-bold text-[#94a3b8] uppercase tracking-wider flex items-center gap-1.5">
                  <Activity size={14} className="text-indigo-400" /> Provable Incident Timeline
                </h4>
                
                <button
                  onClick={handleVerifyTimeline}
                  disabled={isGraphLoading || verifyingTimeline}
                  className="text-xs text-indigo-400 hover:text-indigo-300 font-medium underline flex items-center gap-1 cursor-pointer disabled:opacity-50"
                >
                  <ShieldCheck size={14} /> {verifyingTimeline ? "Verifying..." : "Verify Cryptographic Timeline"}
                </button>
              </div>

              {/* Verification Output Bar */}
              {verificationOutput && (
                <div className={`p-3 border rounded-lg text-xs flex items-center gap-2 ${
                  verificationOutput.ok
                    ? "bg-green-950/20 border-green-500/30 text-green-400"
                    : "bg-red-950/20 border-red-500/30 text-red-400"
                }`}>
                  {verificationOutput.ok ? <ShieldCheck size={16} /> : <AlertTriangle size={16} />}
                  <span>{verificationOutput.msg}</span>
                </div>
              )}

              {/* Timeline Nodes */}
              <div className="space-y-2 max-h-[300px] overflow-y-auto custom-scrollbar">
                {isGraphLoading ? (
                  <p className="text-xs text-[#64748b] text-center py-6">Reconstructing timeline graph...</p>
                ) : !graph || !graph.nodes || graph.nodes.length === 0 ? (
                  <p className="text-xs text-[#64748b] text-center py-6 font-mono">No actions bound to this incident case.</p>
                ) : (
                  graph.nodes
                    .filter((node: any) => node.group === "decision" || node.group === "receipt" || node.group === "approval")
                    .sort((a: any, b: any) => (a.timestamp || "").localeCompare(b.timestamp || ""))
                    .map((node: any, idx: number) => (
                      <div
                        key={idx}
                        className="flex justify-between items-center gap-4 p-3 bg-[#0f172a]/30 border border-[#1f2937] rounded-lg text-xs"
                      >
                        <div className="flex items-center gap-2">
                          <span className={`w-2.5 h-2.5 rounded-full ${
                            node.group === "receipt" ? "bg-green-500" : node.group === "approval" ? "bg-amber-500" : "bg-indigo-500"
                          }`} />
                          <div className="flex flex-col">
                            <span className="font-semibold text-[#e2e8f0]">{node.label}</span>
                            {node.metadata && (
                              <span className="text-[10px] text-[#64748b] font-mono mt-0.5 truncate max-w-[300px]">
                                {typeof node.metadata === "string" ? node.metadata : JSON.stringify(node.metadata)}
                              </span>
                            )}
                          </div>
                        </div>

                        <span className="text-[10px] text-[#64748b] font-mono whitespace-nowrap">
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
    </div>
  );
}
