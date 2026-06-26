"use client";

import React, { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, X, Edit3, Save, ArrowUpRight } from "lucide-react";
import { useAppStore, canApprove } from "@/app/store";
import { useEffectiveRole } from "@/hooks/useSessionRole";
import { approveApproval, rejectApproval } from "@/app/api";
import { frameRows } from "@/datasources/frame";
import { errorMessage } from "@/lib/format";
import TrustBadge from "@/components/security/TrustBadge";
import HashChip from "@/components/security/HashChip";
import type { PanelProps } from "../types";

const APPROVER_ID = "platform_admin";

interface ApprovalRow {
  id?: string;
  approval_id?: string;
  agent_id?: string;
  source_trust?: string;
  action_hash?: string;
  expires_in?: string;
  tool_name?: string;
  tool_call?: { name?: string; parameters?: Record<string, unknown> };
}

function approvalId(a: ApprovalRow): string {
  return a.id ?? a.approval_id ?? "";
}

/**
 * The Approval Queue panel — the human-in-the-loop control made visible.
 * Renders the frozen canonical action (the exact bytes that will run), its
 * action_hash, and source trust; Approve / Reject / Edit (re-hash +
 * re-evaluate). The differentiator surface Grafana/Kibana cannot show.
 */
export default function ApprovalCard({ data }: PanelProps) {
  const { gatewayUrl, bearerToken } = useAppStore();
  const { role } = useEffectiveRole();
  const canAct = canApprove(role);
  const denyReason = canAct ? undefined : "Requires the approver or admin role (separation of duties)";
  const apiOpts = { gatewayUrl, bearerToken };
  const queryClient = useQueryClient();

  const [editingId, setEditingId] = useState<string | null>(null);
  const [editParamsJson, setEditParamsJson] = useState("");
  const [editError, setEditError] = useState<string | null>(null);

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["panel"] });
    queryClient.invalidateQueries({ queryKey: ["approvals"] });
    queryClient.invalidateQueries({ queryKey: ["socSummary"] });
  };

  const approveMutation = useMutation({
    mutationFn: (id: string) => approveApproval(apiOpts, id, APPROVER_ID, "Approved from SOC console."),
    onSuccess: invalidate,
  });
  const rejectMutation = useMutation({
    mutationFn: (id: string) => rejectApproval(apiOpts, id, APPROVER_ID, "Rejected from SOC console."),
    onSuccess: invalidate,
  });

  const startEditing = (a: ApprovalRow) => {
    setEditingId(approvalId(a));
    setEditParamsJson(JSON.stringify(a.tool_call?.parameters ?? {}, null, 2));
    setEditError(null);
  };

  const saveEdit = async (a: ApprovalRow) => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(editParamsJson);
    } catch {
      setEditError("Parameters must be valid JSON.");
      return;
    }
    try {
      const res = await fetch(
        `${gatewayUrl.replace(/\/+$/, "")}/v1/approvals/${approvalId(a)}`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${bearerToken}` },
          body: JSON.stringify({ parameters: parsed, reason: "Edited via SOC console; re-hash and re-evaluate." }),
        },
      );
      if (!res.ok) throw new Error(await res.text());
      setEditingId(null);
      invalidate();
    } catch (err: unknown) {
      setEditError(`Edit failed: ${errorMessage(err)}`);
    }
  };

  const approvals = frameRows(data) as ApprovalRow[];

  return (
    <div className="flex flex-col h-full">
      {!canAct ? (
        <p
          className="text-[11px] mb-2 px-2 py-1 rounded border"
          style={{
            color: "var(--text-secondary)",
            borderColor: "var(--border-default)",
            backgroundColor: "var(--surface-app)",
          }}
        >
          Read-only as <strong>{role}</strong>: {denyReason}. The gateway also enforces this server-side.
        </p>
      ) : null}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 overflow-auto custom-scrollbar flex-1 pr-1">
        {approvals.map((a) => {
        const id = approvalId(a);
        const isEditing = editingId === id;
        const busy = approveMutation.isPending || rejectMutation.isPending;
        return (
          <div
            key={id}
            className="bg-[var(--surface-app)]/40 border border-[var(--border-default)] rounded-xl p-4 space-y-3 flex flex-col"
          >
            <div className="flex justify-between items-start gap-3">
              <div>
                <span className="text-[9px] text-[var(--state-pending)] uppercase tracking-wider font-extrabold block">
                  Action authorization request
                </span>
                <h4 className="font-bold text-sm font-mono mt-0.5 text-[var(--brand)]">
                  {a.tool_call?.name ?? a.tool_name ?? "action"}
                </h4>
              </div>
              <span className="text-[10px] text-[var(--text-muted)] font-mono whitespace-nowrap">
                expires {a.expires_in ?? "N/A"}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-[11px] py-2 border-y border-[var(--border-default)]">
              <div>
                <span className="block text-[9px] uppercase tracking-wider text-[var(--text-muted)]">Agent</span>
                <code className="text-[var(--text-primary)] font-mono">{a.agent_id ?? "N/A"}</code>
              </div>
              <div>
                <span className="block text-[9px] uppercase tracking-wider text-[var(--text-muted)]">Source trust</span>
                <div className="mt-0.5"><TrustBadge trust={a.source_trust ?? "unknown"} /></div>
              </div>
            </div>

            <div className="text-[10px]">
              <span className="block uppercase tracking-wider text-[var(--text-muted)] font-semibold text-[9px] mb-1">
                Action hash (frozen — you approve exactly these bytes)
              </span>
              <HashChip hash={a.action_hash} kind="action" head={20} tail={8} />
            </div>

            <div className="space-y-1 flex-1">
              <span className="block uppercase tracking-wider text-[var(--text-muted)] font-semibold text-[9px]">
                Canonical parameters
              </span>
              {isEditing ? (
                <textarea
                  value={editParamsJson}
                  onChange={(e) => setEditParamsJson(e.target.value)}
                  rows={6}
                  className="w-full bg-[var(--surface-app)] border border-[var(--border-default)] rounded-lg p-2 font-mono text-xs text-[var(--brand)] focus:outline-none focus:border-[var(--border-active)]"
                />
              ) : (
                <pre className="bg-[var(--surface-app)] border border-[var(--border-default)] rounded-lg p-2.5 text-[11px] text-[var(--brand)] font-mono overflow-auto max-h-32 custom-scrollbar whitespace-pre-wrap">
                  {JSON.stringify(a.tool_call?.parameters ?? {}, null, 2)}
                </pre>
              )}
              {isEditing ? (
                <p className="text-[10px] text-[var(--state-pending)]">
                  Editing re-hashes and re-evaluates — you will be approving the new bytes.
                </p>
              ) : null}
              {editError && isEditing ? (
                <p className="text-[10px] text-[var(--state-failed)]">{editError}</p>
              ) : null}
            </div>

            <div className="flex gap-2 pt-3 border-t border-[var(--border-default)]">
              {isEditing ? (
                <>
                  <button
                    onClick={() => saveEdit(a)}
                    disabled={!canAct}
                    title={denyReason}
                    className="flex-1 flex items-center justify-center gap-1.5 bg-[var(--brand)] hover:bg-[var(--brand-emphasis)] text-[var(--text-on-brand)] font-medium text-xs rounded-lg py-1.5 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <Save size={13} /> Save &amp; re-evaluate
                  </button>
                  <button
                    onClick={() => setEditingId(null)}
                    className="bg-[var(--interactive-bg)] hover:bg-[var(--interactive-bg-hover)] text-[var(--text-primary)] text-xs rounded-lg px-3 py-1.5 cursor-pointer border border-[var(--border-default)]"
                  >
                    Cancel
                  </button>
                </>
              ) : (
                <>
                  <button
                    onClick={() => approveMutation.mutate(id)}
                    disabled={busy || !canAct}
                    title={denyReason}
                    className="flex-1 flex items-center justify-center gap-1 text-[var(--text-on-brand)] font-medium text-xs rounded-lg py-1.5 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                    style={{ backgroundColor: "var(--decision-allow)" }}
                  >
                    <Check size={13} /> Approve
                  </button>
                  <button
                    onClick={() => startEditing(a)}
                    disabled={!canAct}
                    title={denyReason ?? "Edit parameters (re-hash + re-evaluate)"}
                    className="bg-[var(--interactive-bg)] hover:bg-[var(--interactive-bg-hover)] text-[var(--text-primary)] border border-[var(--border-default)] text-xs rounded-lg px-2.5 py-1.5 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <Edit3 size={13} />
                  </button>
                  <button
                    disabled
                    title="Escalation routing not configured"
                    className="bg-[var(--interactive-bg)] text-[var(--text-muted)] border border-[var(--border-default)] text-xs rounded-lg px-2.5 py-1.5 cursor-not-allowed"
                  >
                    <ArrowUpRight size={13} />
                  </button>
                  <button
                    onClick={() => rejectMutation.mutate(id)}
                    disabled={busy || !canAct}
                    title={denyReason}
                    className="flex-1 flex items-center justify-center gap-1 text-[var(--text-on-brand)] font-medium text-xs rounded-lg py-1.5 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                    style={{ backgroundColor: "var(--decision-deny)" }}
                  >
                    <X size={13} /> Reject
                  </button>
                </>
              )}
            </div>
          </div>
        );
        })}
      </div>
    </div>
  );
}
