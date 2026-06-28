"use client";

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "../app/store";
import { getApprovals, approveApproval, rejectApproval, editApproval, type ApprovalRecord } from "../app/api";
import { Clock, ShieldCheck, Check, X, Edit3, Save } from "lucide-react";
import { errorMessage } from "@/lib/format";
import TrustBadge from "./security/TrustBadge";

export default function ApprovalsTab() {
  const { gatewayUrl, bearerToken, activeTenant, authEpoch } = useAppStore();
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };
  const queryClient = useQueryClient();

  const [approverId, setApproverId] = useState("platform_admin");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editParamsJson, setEditParamsJson] = useState("");
  const [editReason, setEditReason] = useState("");

  // Fetch pending approvals
  const { data: approvals, isLoading, error } = useQuery({
    queryKey: ["approvals", gatewayUrl, activeTenant, authEpoch],
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

  const startEditing = (approval: ApprovalRecord) => {
    setEditingId(approval.id || approval.approval_id || null);
    const params = approval.tool_call?.parameters || {};
    setEditParamsJson(JSON.stringify(params, null, 2));
    setEditReason("Edited and adjusted parameters to comply with security guidelines.");
  };

  const handleSaveEdit = async (approval: ApprovalRecord) => {
    try {
      const parsedParams = JSON.parse(editParamsJson);
      const approvalId = approval.id || approval.approval_id;
      if (!approvalId) throw new Error("Approval ID is missing.");
      await editApproval(apiOpts, approvalId, parsedParams, editReason);
      setEditingId(null);
      queryClient.invalidateQueries({ queryKey: ["approvals"] });
    } catch (err: unknown) {
      alert(`Failed to save edit: ${errorMessage(err)}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Approver Header Config */}
      <div className="flex flex-wrap justify-between items-center gap-4 bg-[var(--surface-panel)] border border-[var(--border-default)] rounded-xl p-4">
        <div>
          <h2 className="text-sm font-bold text-[var(--text-primary)]">Operator Configuration</h2>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">Define your approver signature name below.</p>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-[var(--text-secondary)]">Approver Identity:</label>
          <input
            type="text"
            value={approverId}
            onChange={(e) => setApproverId(e.target.value)}
            className="bg-[var(--surface-app)] border border-[var(--border-default)] rounded-md px-3 py-1 text-xs text-[var(--text-primary)] focus:border-[var(--border-active)] focus:outline-none font-mono"
          />
        </div>
      </div>

      {/* Approvals Queue */}
      <div className="panel-card space-y-4">
        <div className="flex items-center justify-between border-b border-[var(--border-default)] pb-3">
          <h3 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider flex items-center gap-1.5">
            <Clock size={14} className="text-amber-500" /> Pending Approvals Queue
          </h3>
          <span className="bg-amber-500/10 border border-amber-500/30 text-amber-500 text-xs font-bold px-2 py-0.5 rounded-full">
            {isLoading ? "..." : approvals?.length || 0} pending
          </span>
        </div>

        {isLoading ? (
          <p className="text-sm text-[var(--text-muted)] text-center py-16">Loading approvals queue...</p>
        ) : error ? (
          <p className="text-sm text-red-400 text-center py-16">Error: {errorMessage(error)}</p>
        ) : !approvals || approvals.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-center text-[var(--text-muted)]">
            <ShieldCheck size={48} className="text-green-500 mb-4 animate-pulse" />
            <h4 className="text-sm font-semibold">Queue Empty</h4>
            <p className="text-xs max-w-xs mt-1">There are no pending agent actions requiring human approval.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {approvals.map((app) => {
              const app_id = app.id || app.approval_id || "";
              const isEditing = editingId === app_id;
              return (
                <div
                  key={app_id}
                  className="bg-[var(--surface-app)]/40 border border-[var(--border-default)] hover:border-[var(--border-default)] rounded-xl p-5 space-y-4 flex flex-col justify-between"
                >
                  <div className="space-y-3">
                    {/* Header */}
                    <div className="flex justify-between items-start gap-4">
                      <div>
                        <span className="text-[10px] text-amber-500 uppercase tracking-wider font-extrabold block">
                          ACTION AUTHORIZATION REQUEST
                        </span>
                        <h4 className="font-bold text-[var(--text-primary)] text-sm font-mono mt-1 text-[var(--brand)]">
                          {app.tool_call?.name || app.tool_name || "action"}
                        </h4>
                      </div>
                      <span className="text-[10px] text-[var(--text-muted)] font-mono whitespace-nowrap">
                        Expires in {app.expires_in || "N/A"}
                      </span>
                    </div>

                    {/* Meta values */}
                    <div className="grid grid-cols-2 gap-2 text-[11px] py-2 border-y border-[var(--border-default)] text-[var(--text-secondary)]">
                      <div>
                        <span className="block text-[9px] uppercase tracking-wider text-[var(--text-muted)]">Agent ID</span>
                        <code className="text-[var(--text-primary)] font-mono">{app.agent_id || "N/A"}</code>
                      </div>
                      <div>
                        <span className="block text-[9px] uppercase tracking-wider text-[var(--text-muted)]">Source Trust</span>
                        <div className="mt-0.5"><TrustBadge trust={app.source_trust || "unknown"} /></div>
                      </div>
                    </div>

                    {/* Action Hash */}
                    <div className="text-[10px]">
                      <span className="block uppercase tracking-wider text-[var(--text-muted)] font-semibold text-[9px]">Action Hash (frozen)</span>
                      <code className="text-[var(--text-secondary)] block font-mono bg-[var(--surface-app)] p-1.5 rounded border border-[var(--border-default)] select-all break-all mt-1">
                        {app.action_hash}
                      </code>
                    </div>

                    {/* Parameters Inspector or JSON Editor */}
                    <div className="space-y-1">
                      <span className="block uppercase tracking-wider text-[var(--text-muted)] font-semibold text-[9px]">Action Parameters</span>
                      {isEditing ? (
                        <div className="space-y-2">
                          <textarea
                            value={editParamsJson}
                            onChange={(e) => setEditParamsJson(e.target.value)}
                            rows={6}
                            className="w-full bg-[var(--surface-app)] border border-[var(--border-default)] rounded-lg p-2 font-mono text-xs text-[var(--brand)] focus:outline-none focus:border-[var(--border-active)]"
                          />
                          <input
                            type="text"
                            placeholder="Reason for change"
                            value={editReason}
                            onChange={(e) => setEditReason(e.target.value)}
                            className="w-full bg-[var(--surface-app)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-primary)] focus:outline-none focus:border-[var(--border-active)]"
                          />
                        </div>
                      ) : (
                        <pre className="bg-[var(--surface-app)] border border-[var(--border-default)] rounded-lg p-3 text-[11px] text-[var(--brand)] font-mono overflow-auto max-h-40 custom-scrollbar whitespace-pre-wrap">
                          {JSON.stringify(app.tool_call?.parameters || {}, null, 2)}
                        </pre>
                      )}
                    </div>
                  </div>

                  {/* Actions buttons */}
                  <div className="flex gap-2 pt-4 border-t border-[var(--border-default)] mt-4">
                    {isEditing ? (
                      <>
                        <button
                          onClick={() => handleSaveEdit(app)}
                          className="flex-1 flex items-center justify-center gap-1.5 bg-[var(--brand)] hover:bg-[var(--brand-emphasis)] text-white font-medium text-xs rounded-lg py-2 transition-colors cursor-pointer"
                        >
                          <Save size={14} /> Save & Re-evaluate
                        </button>
                        <button
                          onClick={() => setEditingId(null)}
                          className="bg-[var(--interactive-bg)] hover:bg-[var(--interactive-bg-hover)] text-[var(--text-primary)] font-medium text-xs rounded-lg px-4 py-2 transition-colors cursor-pointer border border-[var(--border-default)]"
                        >
                          Cancel
                        </button>
                      </>
                    ) : (
                      <>
                        <button
                          onClick={() => handleApprove(app_id)}
                          disabled={!app_id}
                          className="flex-1 flex items-center justify-center gap-1 bg-green-700 hover:bg-green-800 text-white font-medium text-xs rounded-lg py-2 transition-colors cursor-pointer"
                        >
                          <Check size={14} /> Approve Action
                        </button>
                        <button
                          onClick={() => startEditing(app)}
                          className="bg-[var(--interactive-bg)] hover:bg-[var(--interactive-bg-hover)] text-white border border-[var(--border-default)] font-medium text-xs rounded-lg px-3 py-2 transition-colors cursor-pointer"
                          title="Edit action parameters"
                        >
                          <Edit3 size={14} />
                        </button>
                        <button
                          onClick={() => handleReject(app_id)}
                          disabled={!app_id}
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
