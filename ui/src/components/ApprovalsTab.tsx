"use client";

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "../app/store";
import { getApprovals, approveApproval, rejectApproval } from "../app/api";
import { Clock, ShieldCheck, ShieldAlert, Check, X, AlertTriangle, Edit3, Save } from "lucide-react";

export default function ApprovalsTab() {
  const { gatewayUrl, bearerToken } = useAppStore();
  const apiOpts = { gatewayUrl, bearerToken };
  const queryClient = useQueryClient();

  const [approverId, setApproverId] = useState("platform_admin");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editParamsJson, setEditParamsJson] = useState("");
  const [editReason, setEditReason] = useState("");

  // Fetch pending approvals
  const { data: approvals, isLoading, error } = useQuery({
    queryKey: ["approvals", gatewayUrl, bearerToken],
    queryFn: () => getApprovals(apiOpts),
    refetchInterval: 3000, // Poll more frequently for approvals (every 3s)
  });

  const approveMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      approveApproval(apiOpts, id, approverId, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["approvals"] });
      queryClient.invalidateQueries({ queryKey: ["socSummary"] });
    },
  });

  const rejectMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      rejectApproval(apiOpts, id, approverId, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["approvals"] });
      queryClient.invalidateQueries({ queryKey: ["socSummary"] });
    },
  });

  const handleApprove = (id: string) => {
    approveMutation.mutate({ id, reason: "Approved via SOC dashboard." });
  };

  const handleReject = (id: string) => {
    rejectMutation.mutate({ id, reason: "Rejected via SOC dashboard." });
  };

  const startEditing = (approval: any) => {
    setEditingId(approval.id || approval.approval_id);
    const params = approval.tool_call?.parameters || {};
    setEditParamsJson(JSON.stringify(params, null, 2));
    setEditReason("Edited and adjusted parameters to comply with security guidelines.");
  };

  const handleSaveEdit = async (approval: any) => {
    try {
      const parsedParams = JSON.parse(editParamsJson);
      // To perform "Edit & Re-evaluate", we hit the edit endpoint
      // We will perform a PUT/POST to `/v1/approvals/:id/edit` (or whatever the path is)
      // Let's verify how edit approval is implemented in the gateway.
      // In CLAUDE.md:
      // "edit_approval_rehashes_and_stores_edited_call: edit approval rehashes and stores edited call"
      // Wait! Let's search for "edit" in `routes/approval.rs` to find the exact route.
      // Let's do that!
      const approvalId = approval.id || approval.approval_id;
      const res = await fetch(`${gatewayUrl.replace(/\/+$/, "")}/v1/approvals/${approvalId}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bearerToken}`,
        },
        body: JSON.stringify({
          parameters: parsedParams,
          reason: editReason,
        }),
      });
      if (!res.ok) {
        throw new Error(await res.text());
      }
      setEditingId(null);
      queryClient.invalidateQueries({ queryKey: ["approvals"] });
    } catch (err: any) {
      alert(`Failed to save edit: ${err.message}`);
    }
  };

  const getTrustBadge = (trust: string) => {
    switch (String(trust).toLowerCase()) {
      case "trusted_internal_signed":
        return <span className="px-2.5 py-1 text-xs font-semibold bg-green-500/20 text-green-400 border border-green-500/30 rounded">trusted_internal_signed</span>;
      case "trusted_internal_unsigned":
        return <span className="px-2.5 py-1 text-xs font-semibold bg-blue-500/20 text-blue-400 border border-blue-500/30 rounded">trusted_internal_unsigned</span>;
      case "semi_trusted_customer":
        return <span className="px-2.5 py-1 text-xs font-semibold bg-amber-500/20 text-amber-400 border border-amber-500/30 rounded">semi_trusted_customer</span>;
      case "untrusted_external":
        return <span className="px-2.5 py-1 text-xs font-semibold bg-red-500/20 text-red-400 border border-red-500/30 rounded">untrusted_external</span>;
      case "malicious_suspected":
        return <span className="px-2.5 py-1 text-xs font-semibold bg-rose-500/20 text-rose-500 border border-rose-500/40 rounded font-bold">malicious_suspected</span>;
      default:
        return <span className="px-2.5 py-1 text-xs font-semibold bg-slate-500/20 text-slate-400 border border-slate-500/30 rounded">unknown</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Approver Header Config */}
      <div className="flex flex-wrap justify-between items-center gap-4 bg-[#111827] border border-[#334155] rounded-xl p-4">
        <div>
          <h2 className="text-sm font-bold text-[#e2e8f0]">Operator Configuration</h2>
          <p className="text-xs text-[#94a3b8] mt-0.5">Define your approver signature name below.</p>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-[#94a3b8]">Approver Identity:</label>
          <input
            type="text"
            value={approverId}
            onChange={(e) => setApproverId(e.target.value)}
            className="bg-[#0f172a] border border-[#334155] rounded-md px-3 py-1 text-xs text-[#e2e8f0] focus:border-indigo-500 focus:outline-none font-mono"
          />
        </div>
      </div>

      {/* Approvals Queue */}
      <div className="panel-card space-y-4">
        <div className="flex items-center justify-between border-b border-[#1f2937] pb-3">
          <h3 className="text-xs font-bold text-[#94a3b8] uppercase tracking-wider flex items-center gap-1.5">
            <Clock size={14} className="text-amber-500" /> Pending Approvals Queue
          </h3>
          <span className="bg-amber-500/10 border border-amber-500/30 text-amber-500 text-xs font-bold px-2 py-0.5 rounded-full">
            {isLoading ? "..." : approvals?.length || 0} pending
          </span>
        </div>

        {isLoading ? (
          <p className="text-sm text-[#64748b] text-center py-16">Loading approvals queue...</p>
        ) : error ? (
          <p className="text-sm text-red-400 text-center py-16">Error: {(error as any).message}</p>
        ) : !approvals || approvals.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-center text-[#64748b]">
            <ShieldCheck size={48} className="text-green-500 mb-4 animate-pulse" />
            <h4 className="text-sm font-semibold">Queue Empty</h4>
            <p className="text-xs max-w-xs mt-1">There are no pending agent actions requiring human approval.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {approvals.map((app: any) => {
              const app_id = app.id || app.approval_id;
              const isEditing = editingId === app_id;
              return (
                <div
                  key={app_id}
                  className="bg-[#0f172a]/40 border border-[#1f2937] hover:border-[#334155] rounded-xl p-5 space-y-4 flex flex-col justify-between"
                >
                  <div className="space-y-3">
                    {/* Header */}
                    <div className="flex justify-between items-start gap-4">
                      <div>
                        <span className="text-[10px] text-amber-500 uppercase tracking-wider font-extrabold block">
                          ACTION AUTHORIZATION REQUEST
                        </span>
                        <h4 className="font-bold text-[#e2e8f0] text-sm font-mono mt-1 text-indigo-400">
                          {app.tool_call?.name || app.tool_name || "action"}
                        </h4>
                      </div>
                      <span className="text-[10px] text-[#64748b] font-mono whitespace-nowrap">
                        Expires in {app.expires_in || "N/A"}
                      </span>
                    </div>

                    {/* Meta values */}
                    <div className="grid grid-cols-2 gap-2 text-[11px] py-2 border-y border-[#1f2937] text-[#94a3b8]">
                      <div>
                        <span className="block text-[9px] uppercase tracking-wider text-[#64748b]">Agent ID</span>
                        <code className="text-[#e2e8f0] font-mono">{app.agent_id || "N/A"}</code>
                      </div>
                      <div>
                        <span className="block text-[9px] uppercase tracking-wider text-[#64748b]">Source Trust</span>
                        <div className="mt-0.5">{getTrustBadge(app.source_trust || "unknown")}</div>
                      </div>
                    </div>

                    {/* Action Hash */}
                    <div className="text-[10px]">
                      <span className="block uppercase tracking-wider text-[#64748b] font-semibold text-[9px]">Action Hash (frozen)</span>
                      <code className="text-[#94a3b8] block font-mono bg-[#0f172a] p-1.5 rounded border border-[#1f2937] select-all break-all mt-1">
                        {app.action_hash}
                      </code>
                    </div>

                    {/* Parameters Inspector or JSON Editor */}
                    <div className="space-y-1">
                      <span className="block uppercase tracking-wider text-[#64748b] font-semibold text-[9px]">Action Parameters</span>
                      {isEditing ? (
                        <div className="space-y-2">
                          <textarea
                            value={editParamsJson}
                            onChange={(e) => setEditParamsJson(e.target.value)}
                            rows={6}
                            className="w-full bg-[#0f172a] border border-[#334155] rounded-lg p-2 font-mono text-xs text-indigo-300 focus:outline-none focus:border-indigo-500"
                          />
                          <input
                            type="text"
                            placeholder="Reason for change"
                            value={editReason}
                            onChange={(e) => setEditReason(e.target.value)}
                            className="w-full bg-[#0f172a] border border-[#334155] rounded-lg px-2.5 py-1.5 text-xs text-[#e2e8f0] focus:outline-none focus:border-indigo-500"
                          />
                        </div>
                      ) : (
                        <pre className="bg-[#0f172a] border border-[#1f2937] rounded-lg p-3 text-[11px] text-indigo-300 font-mono overflow-auto max-h-40 custom-scrollbar whitespace-pre-wrap">
                          {JSON.stringify(app.tool_call?.parameters || {}, null, 2)}
                        </pre>
                      )}
                    </div>
                  </div>

                  {/* Actions buttons */}
                  <div className="flex gap-2 pt-4 border-t border-[#1f2937] mt-4">
                    {isEditing ? (
                      <>
                        <button
                          onClick={() => handleSaveEdit(app)}
                          className="flex-1 flex items-center justify-center gap-1.5 bg-indigo-600 hover:bg-indigo-700 text-white font-medium text-xs rounded-lg py-2 transition-colors cursor-pointer"
                        >
                          <Save size={14} /> Save & Re-evaluate
                        </button>
                        <button
                          onClick={() => setEditingId(null)}
                          className="bg-[#1e293b] hover:bg-[#273549] text-[#e2e8f0] font-medium text-xs rounded-lg px-4 py-2 transition-colors cursor-pointer border border-[#334155]"
                        >
                          Cancel
                        </button>
                      </>
                    ) : (
                      <>
                        <button
                          onClick={() => handleApprove(app_id)}
                          className="flex-1 flex items-center justify-center gap-1 bg-green-700 hover:bg-green-800 text-white font-medium text-xs rounded-lg py-2 transition-colors cursor-pointer"
                        >
                          <Check size={14} /> Approve Action
                        </button>
                        <button
                          onClick={() => startEditing(app)}
                          className="bg-[#1e293b] hover:bg-[#273549] text-white border border-[#334155] font-medium text-xs rounded-lg px-3 py-2 transition-colors cursor-pointer"
                          title="Edit action parameters"
                        >
                          <Edit3 size={14} />
                        </button>
                        <button
                          onClick={() => handleReject(app_id)}
                          className="flex-1 flex items-center justify-center gap-1 bg-red-700 hover:bg-red-800 text-white font-medium text-xs rounded-lg py-2 transition-colors cursor-pointer"
                        >
                          <X size={14} /> Reject Action
                        </button>
                      </>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
