"use client";

import React, { useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Lock, Unlock } from "lucide-react";
import { useAppStore } from "@/app/store";
import { useEffectiveRole } from "@/hooks/useSessionRole";
import { freezeAgent, unfreezeAgent } from "@/app/api";
import { frameRows } from "@/datasources/frame";
import StatusBadge from "@/components/security/StatusBadge";
import { ConfirmDialog } from "@/components/primitives";
import VirtualTable, { type VirtualTableColumn } from "@/components/primitives/VirtualTable";
import type { PanelProps } from "../types";

interface AgentRow {
  id?: string;
  status?: string;
  risk_tier?: string;
  environment?: string;
  model?: string;
}

type PendingAgentAction = {
  kind: "freeze" | "unfreeze";
  agentId: string;
};

/**
 * Fleet inventory panel with role-gated Active Response (freeze / restore).
 * Virtualized for large tenant fleets (#1317); writes go through api.ts.
 */
export default function AgentTablePanel({ data }: PanelProps) {
  const { gatewayUrl, bearerToken, activeTenant } = useAppStore();
  const { role } = useEffectiveRole();
  const canRespond = role !== "viewer";
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };
  const queryClient = useQueryClient();
  const [pendingAction, setPendingAction] = useState<PendingAgentAction | null>(null);
  const [auditReason, setAuditReason] = useState("");

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["panel"] });
    queryClient.invalidateQueries({ queryKey: ["agents"] });
  };

  const freezeMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) => freezeAgent(apiOpts, id, reason),
    onSuccess: () => {
      setPendingAction(null);
      setAuditReason("");
      invalidate();
    },
  });
  const unfreezeMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) => unfreezeAgent(apiOpts, id, reason),
    onSuccess: () => {
      setPendingAction(null);
      setAuditReason("");
      invalidate();
    },
  });
  const busy = freezeMutation.isPending || unfreezeMutation.isPending;

  const agents = frameRows(data) as AgentRow[];

  const requestAgentAction = (kind: PendingAgentAction["kind"], agentId: string) => {
    setPendingAction({ kind, agentId });
    setAuditReason("");
  };

  const confirmAgentAction = () => {
    if (!pendingAction || !auditReason.trim()) return;
    if (pendingAction.kind === "freeze") {
      freezeMutation.mutate({ id: pendingAction.agentId, reason: auditReason.trim() });
    } else {
      unfreezeMutation.mutate({ id: pendingAction.agentId, reason: auditReason.trim() });
    }
  };

  const columns = useMemo<VirtualTableColumn<AgentRow>[]>(
    () => [
      {
        key: "id",
        header: "Agent key",
        headerClassName: "py-2",
        cellClassName: "py-2 font-mono text-[var(--brand)] font-bold",
        cell: (agent) => agent.id,
      },
      {
        key: "status",
        header: "Status",
        headerClassName: "py-2",
        cellClassName: "py-2",
        cell: (agent) => <StatusBadge status={agent.status} size="sm" />,
      },
      {
        key: "risk_tier",
        header: "Risk tier",
        headerClassName: "py-2",
        cellClassName: "py-2 font-semibold",
        cell: (agent) => (
          <span style={{ color: "var(--sev-high)" }}>{agent.risk_tier || "low"}</span>
        ),
      },
      {
        key: "environment",
        header: "Environment",
        headerClassName: "py-2",
        cellClassName: "py-2 font-mono text-[var(--text-secondary)]",
        cell: (agent) => agent.environment || "production",
      },
      {
        key: "model",
        header: "Model",
        headerClassName: "py-2",
        cellClassName: "py-2 text-[var(--text-primary)]",
        cell: (agent) => agent.model || "N/A",
      },
      {
        key: "actions",
        header: "Active response",
        headerClassName: "py-2 text-right",
        cellClassName: "py-2 text-right",
        cell: (agent) => {
          const id = agent.id;
          const isFrozen = agent.status === "frozen";
          const revoked = agent.status === "revoked";
          if (revoked) {
            return <span className="text-[var(--text-muted)] italic">Revoked</span>;
          }
          return (
            <button
              onClick={(event) => {
                event.stopPropagation();
                if (id) requestAgentAction(isFrozen ? "unfreeze" : "freeze", id);
              }}
              disabled={busy || !canRespond || !id}
              title={canRespond ? undefined : "Requires analyst, approver, or admin role"}
              className="inline-flex items-center gap-1 text-[11px] font-semibold border rounded-lg px-3 py-1 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
              style={
                isFrozen
                  ? {
                      color: "var(--state-verified)",
                      borderColor: "color-mix(in oklab, var(--state-verified) 40%, transparent)",
                    }
                  : {
                      color: "var(--state-pending)",
                      borderColor: "color-mix(in oklab, var(--state-pending) 40%, transparent)",
                    }
              }
            >
              {isFrozen ? (
                <>
                  <Unlock size={12} /> Restore
                </>
              ) : (
                <>
                  <Lock size={12} /> Freeze
                </>
              )}
            </button>
          );
        },
      },
    ],
    [busy, canRespond],
  );

  return (
    <div className="h-full">
      <VirtualTable
        rows={agents}
        columns={columns}
        getRowKey={(agent, index) => agent.id ?? `agent-${index}`}
        tableClassName="w-full text-left text-xs min-w-[680px]"
        maxHeight="100%"
        rowClassName="border-b border-[var(--border-default)] hover:bg-[var(--surface-elevated)]"
      />
      <ConfirmDialog
        open={pendingAction !== null}
        title={pendingAction?.kind === "freeze" ? "Freeze this agent?" : "Restore this frozen agent?"}
        impact={
          pendingAction?.kind === "freeze"
            ? "Future authorize calls for this agent will fail closed until an operator restores the agent. The reason is sent to the gateway frozen_reason field."
            : "The agent will be restored to active status. The gateway currently clears frozen_reason on restore; this UI reason is required to prevent accidental recovery."
        }
        target={pendingAction?.agentId ?? ""}
        reason={auditReason}
        onReasonChange={setAuditReason}
        confirmLabel={pendingAction?.kind === "freeze" ? "Freeze agent" : "Restore agent"}
        confirmDisabled={!auditReason.trim() || busy}
        onConfirm={confirmAgentAction}
        onCancel={() => {
          setPendingAction(null);
          setAuditReason("");
        }}
      />
    </div>
  );
}