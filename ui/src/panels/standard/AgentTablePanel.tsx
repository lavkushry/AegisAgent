"use client";

import React from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Lock, Unlock } from "lucide-react";
import { useAppStore } from "@/app/store";
import { useEffectiveRole } from "@/hooks/useSessionRole";
import { freezeAgent, unfreezeAgent } from "@/app/api";
import { frameRows } from "@/datasources/frame";
import StatusBadge from "@/components/security/StatusBadge";
import type { PanelProps } from "../types";

interface AgentRow {
  id?: string;
  status?: string;
  risk_tier?: string;
  environment?: string;
  model?: string;
}

/**
 * Fleet inventory panel with role-gated Active Response (freeze / restore).
 * Reads agent rows from the DataFrame; writes go through the api.ts control
 * endpoints. The gateway enforces authorization server-side regardless.
 */
export default function AgentTablePanel({ data }: PanelProps) {
  const { gatewayUrl, bearerToken, activeTenant } = useAppStore();
  const { role } = useEffectiveRole();
  const canRespond = role !== "viewer";
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };
  const queryClient = useQueryClient();

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["panel"] });
    queryClient.invalidateQueries({ queryKey: ["agents"] });
  };

  const freezeMutation = useMutation({
    mutationFn: (id: string) => freezeAgent(apiOpts, id),
    onSuccess: invalidate,
  });
  const unfreezeMutation = useMutation({
    mutationFn: (id: string) => unfreezeAgent(apiOpts, id),
    onSuccess: invalidate,
  });
  const busy = freezeMutation.isPending || unfreezeMutation.isPending;

  const agents = frameRows(data) as AgentRow[];

  return (
    <div className="overflow-auto custom-scrollbar h-full">
      <table className="w-full text-left text-xs min-w-[680px]">
        <thead>
          <tr className="text-[var(--text-muted)] uppercase text-[10px] tracking-wider font-semibold border-b border-[var(--border-default)]">
            <th className="py-2">Agent key</th>
            <th className="py-2">Status</th>
            <th className="py-2">Risk tier</th>
            <th className="py-2">Environment</th>
            <th className="py-2">Model</th>
            <th className="py-2 text-right">Active response</th>
          </tr>
        </thead>
        <tbody>
          {agents.map((agent, i) => {
            const id = agent.id;
            const isFrozen = agent.status === "frozen";
            const revoked = agent.status === "revoked";
            return (
              <tr
                key={id ?? `agent-${i}`}
                className="border-b border-[var(--border-default)] hover:bg-[var(--surface-elevated)]"
                style={{ height: "var(--row-height, 28px)" }}
              >
                <td className="py-2 font-mono text-[var(--brand)] font-bold">{agent.id}</td>
                <td className="py-2"><StatusBadge status={agent.status} size="sm" /></td>
                <td className="py-2 font-semibold" style={{ color: "var(--sev-high)" }}>
                  {agent.risk_tier || "low"}
                </td>
                <td className="py-2 font-mono text-[var(--text-secondary)]">{agent.environment || "production"}</td>
                <td className="py-2 text-[var(--text-primary)]">{agent.model || "N/A"}</td>
                <td className="py-2 text-right">
                  {revoked ? (
                    <span className="text-[var(--text-muted)] italic">Revoked</span>
                  ) : (
                    <button
                      onClick={() => id && (isFrozen ? unfreezeMutation : freezeMutation).mutate(id)}
                      disabled={busy || !canRespond || !id}
                      title={canRespond ? undefined : "Requires analyst, approver, or admin role"}
                      className="inline-flex items-center gap-1 text-[11px] font-semibold border rounded-lg px-3 py-1 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                      style={
                        isFrozen
                          ? { color: "var(--state-verified)", borderColor: "color-mix(in oklab, var(--state-verified) 40%, transparent)" }
                          : { color: "var(--state-pending)", borderColor: "color-mix(in oklab, var(--state-pending) 40%, transparent)" }
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
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
