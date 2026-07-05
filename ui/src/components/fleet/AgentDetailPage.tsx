"use client";

import React, { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  ExternalLink,
  Lock,
  ShieldAlert,
  Unlock,
  UserX,
  ShieldCheck,
} from "lucide-react";
import { useAppStore } from "@/app/store";
import {
  freezeAgent,
  getAgent,
  listAgentPermissions,
  restoreAgent,
  revokeAgent,
  unfreezeAgent,
  type AgentRecord,
} from "@/app/api";
import { GatewayEntityDatasource } from "@/datasources/gatewayEntity";
import { decisionRowsFromFrame, type ExploreEventRecord } from "@/components/exploreData";
import { useEffectiveRole } from "@/hooks/useSessionRole";
import { errorMessage } from "@/lib/format";
import StatusBadge from "@/components/security/StatusBadge";
import { ConfirmDialog } from "@/components/primitives";
import {
  controlConfirmLabel,
  controlDisabledReason,
  controlImpact,
  controlTitle,
  type AgentControlKind,
} from "./agentControls";
import {
  formatFrameworkModel,
  formatLastSeen,
  formatOwner,
  UNAVAILABLE,
} from "./agentFleetData";

type PendingControl = {
  kind: AgentControlKind;
  agentId: string;
};

type AgentDetailPageProps = {
  agentId: string;
  onBack: () => void;
};

const DEFAULT_TIME_RANGE = { from: "now-24h", to: "now" } as const;

export default function AgentDetailPage({ agentId, onBack }: AgentDetailPageProps) {
  const { gatewayUrl, bearerToken, activeTenant, authEpoch, setActiveView, setExploreSeed, setActiveIncidentId } =
    useAppStore();
  const apiOpts = useMemo(
    () => ({ gatewayUrl, bearerToken, tenantId: activeTenant }),
    [gatewayUrl, bearerToken, activeTenant],
  );
  const entityDatasource = useMemo(() => new GatewayEntityDatasource(apiOpts), [apiOpts]);
  const queryClient = useQueryClient();
  const { role } = useEffectiveRole();

  const [pendingControl, setPendingControl] = useState<PendingControl | null>(null);
  const [auditReason, setAuditReason] = useState("");
  const [mutationError, setMutationError] = useState<string | null>(null);

  const { data: agent, isLoading, error } = useQuery({
    queryKey: ["agentDetail", gatewayUrl, activeTenant, authEpoch, agentId],
    queryFn: () => getAgent(apiOpts, agentId),
  });

  const { data: permissions = [] } = useQuery({
    queryKey: ["agentPermissions", gatewayUrl, activeTenant, authEpoch, agentId],
    queryFn: () => listAgentPermissions(apiOpts, agentId),
    enabled: Boolean(agentId),
  });

  const { data: decisionsFrame } = useQuery({
    queryKey: ["agentDecisions", gatewayUrl, activeTenant, authEpoch, agentId],
    queryFn: ({ signal }) =>
      entityDatasource.query({
        entity: "decision",
        limit: 100,
        timeRange: DEFAULT_TIME_RANGE,
        variables: {},
        signal,
      }),
    enabled: Boolean(agentId),
  });

  const recentDecisions = useMemo(() => {
    const rows = decisionRowsFromFrame(decisionsFrame);
    return rows
      .filter((row) => row.agent_id === agentId || row.agent_id === agent?.agent_key)
      .slice(0, 8);
  }, [decisionsFrame, agentId, agent?.agent_key]);

  const invalidateAgentQueries = () => {
    queryClient.invalidateQueries({ queryKey: ["agents"] });
    queryClient.invalidateQueries({ queryKey: ["agentDetail"] });
    queryClient.invalidateQueries({ queryKey: ["panel"] });
  };

  const runControl = async (kind: AgentControlKind, id: string, reason: string) => {
    switch (kind) {
      case "freeze":
        return freezeAgent(apiOpts, id, reason);
      case "unfreeze":
        return unfreezeAgent(apiOpts, id, reason);
      case "restore":
        return restoreAgent(apiOpts, id, reason);
      case "revoke":
        return revokeAgent(apiOpts, id, reason);
      default:
        throw new Error("Unsupported control");
    }
  };

  const controlMutation = useMutation({
    mutationFn: ({ kind, id, reason }: { kind: AgentControlKind; id: string; reason: string }) =>
      runControl(kind, id, reason),
    onSuccess: () => {
      setPendingControl(null);
      setAuditReason("");
      setMutationError(null);
      invalidateAgentQueries();
    },
    onError: (err: unknown) => {
      setMutationError(errorMessage(err) || "Active response failed");
    },
  });

  const openControl = (kind: AgentControlKind) => {
    setPendingControl({ kind, agentId });
    setAuditReason("");
    setMutationError(null);
  };

  const confirmControl = () => {
    if (!pendingControl || !auditReason.trim()) return;
    controlMutation.mutate({
      kind: pendingControl.kind,
      id: pendingControl.agentId,
      reason: auditReason.trim(),
    });
  };

  const drillExplore = (template: string) => {
    setExploreSeed(template);
    setActiveView("explore");
  };

  if (isLoading) {
    return <p className="py-12 text-center text-xs text-[var(--text-muted)]">Loading agent detail...</p>;
  }

  if (error || !agent) {
    return (
      <div className="space-y-4">
        <button
          type="button"
          onClick={onBack}
          className="inline-flex items-center gap-1 text-xs font-semibold text-[var(--brand)]"
        >
          <ArrowLeft size={14} /> Back to fleet
        </button>
        <p className="text-xs text-red-400">Failed to load agent: {errorMessage(error)}</p>
      </div>
    );
  }

  return (
    <AgentDetailBody
      agent={agent}
      permissions={permissions.map((permission) => permission.tool_key)}
      recentDecisions={recentDecisions}
      role={role}
      mutationError={mutationError}
      pendingControl={pendingControl}
      auditReason={auditReason}
      busy={controlMutation.isPending}
      onBack={onBack}
      onOpenControl={openControl}
      onReasonChange={setAuditReason}
      onConfirmControl={confirmControl}
      onCancelControl={() => {
        setPendingControl(null);
        setAuditReason("");
      }}
      onDrillExplore={drillExplore}
      onDrillIncidents={() => {
        setActiveIncidentId(null);
        setActiveView("incidents");
      }}
      onDrillApprovals={() => setActiveView("approvals")}
      onDrillMcp={() => setActiveView("mcp")}
      onDrillReceipts={() => setActiveView("receipts")}
    />
  );
}

type AgentDetailBodyProps = {
  agent: AgentRecord;
  permissions: string[];
  recentDecisions: ExploreEventRecord[];
  role: ReturnType<typeof useEffectiveRole>["role"];
  mutationError: string | null;
  pendingControl: PendingControl | null;
  auditReason: string;
  busy: boolean;
  onBack: () => void;
  onOpenControl: (kind: AgentControlKind) => void;
  onReasonChange: (reason: string) => void;
  onConfirmControl: () => void;
  onCancelControl: () => void;
  onDrillExplore: (template: string) => void;
  onDrillIncidents: () => void;
  onDrillApprovals: () => void;
  onDrillMcp: () => void;
  onDrillReceipts: () => void;
};

export function AgentDetailBody({
  agent,
  permissions,
  recentDecisions,
  role,
  mutationError,
  pendingControl,
  auditReason,
  busy,
  onBack,
  onOpenControl,
  onReasonChange,
  onConfirmControl,
  onCancelControl,
  onDrillExplore,
  onDrillIncidents,
  onDrillApprovals,
  onDrillMcp,
  onDrillReceipts,
}: AgentDetailBodyProps) {
  const controls: Array<{ kind: AgentControlKind; label: string; icon: React.ReactNode }> = [
    { kind: "freeze", label: "Freeze", icon: <Lock size={12} /> },
    { kind: "unfreeze", label: "Unfreeze", icon: <Unlock size={12} /> },
    { kind: "restore", label: "Restore quarantined", icon: <ShieldCheck size={12} /> },
    { kind: "revoke", label: "Revoke", icon: <UserX size={12} /> },
  ];

  return (
    <div className="space-y-6">
      <button
        type="button"
        onClick={onBack}
        className="inline-flex items-center gap-1 text-xs font-semibold text-[var(--brand)]"
      >
        <ArrowLeft size={14} /> Back to fleet
      </button>

      <div className="space-y-1">
        <h2 className="font-mono text-sm font-bold text-[var(--text-primary)]">{agent.agent_key}</h2>
        <p className="text-[11px] text-[var(--text-muted)]">{agent.name}</p>
      </div>

      {mutationError && (
        <p className="rounded-lg border border-red-500/20 bg-red-950/20 p-3 text-xs text-red-400">{mutationError}</p>
      )}

      <div className="panel-card grid grid-cols-1 gap-4 text-xs md:grid-cols-2">
        <DetailField label="Status" value={<StatusBadge status={agent.status} />} />
        <DetailField label="Risk tier" value={agent.risk_tier} />
        <DetailField label="Owner" value={formatOwner(agent)} />
        <DetailField label="Environment" value={agent.environment || UNAVAILABLE} />
        <DetailField label="Framework / model" value={formatFrameworkModel(agent)} />
        <DetailField label="Last seen" value={formatLastSeen(agent.last_seen_at)} />
        <DetailField label="Force approval" value={agent.force_approval ? "Enabled" : "Off"} />
        <DetailField
          label="Frozen reason"
          value={agent.frozen_reason?.trim() ? agent.frozen_reason : UNAVAILABLE}
        />
        <DetailField label="mTLS CN" value={agent.mtls_cn?.trim() ? agent.mtls_cn : UNAVAILABLE} />
        <DetailField
          label="Identity governance"
          value="Managed by gateway identity epic #1389 — permissions below are tool bindings only."
        />
      </div>

      <div className="panel-card space-y-3">
        <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
          Tool permissions
        </h3>
        {permissions.length === 0 ? (
          <p className="text-[11px] text-[var(--text-muted)]">
            No explicit tool permissions — agent may be unrestricted. See #1389 for full identity governance.
          </p>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {permissions.map((toolKey) => (
              <span
                key={toolKey}
                className="rounded border border-[var(--border-default)] bg-[var(--surface-app)] px-2 py-0.5 font-mono text-[10px] text-[var(--brand)]"
              >
                {toolKey}
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="panel-card space-y-3">
        <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
          Recent decisions (24h sample)
        </h3>
        {recentDecisions.length === 0 ? (
          <p className="text-[11px] text-[var(--text-muted)]">No recent decisions matched this agent in the current window.</p>
        ) : (
          <div className="space-y-1">
            {recentDecisions.map((decision) => (
              <div
                key={decision.id}
                className="flex items-center justify-between rounded border border-[var(--border-default)] px-2 py-1.5 font-mono text-[10px]"
              >
                <span className="text-[var(--brand)]">
                  {decision.tool ?? decision.skill ?? "tool"}
                </span>
                <span className="text-[var(--text-secondary)]">{decision.decision ?? UNAVAILABLE}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="panel-card space-y-3">
        <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
          SOC evidence drilldowns
        </h3>
        <div className="flex flex-wrap gap-2">
          <DrillButton
            label="Explore decisions"
            onClick={() => onDrillExplore(`agent_id:${agent.id}`)}
          />
          <DrillButton label="Incidents" onClick={onDrillIncidents} />
          <DrillButton label="Approvals queue" onClick={onDrillApprovals} />
          <DrillButton label="MCP servers" onClick={onDrillMcp} />
          <DrillButton label="Receipts log" onClick={onDrillReceipts} />
        </div>
      </div>

      <div className="panel-card space-y-3">
        <h3 className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
          <ShieldAlert size={14} className="text-[var(--brand)]" />
          Active response
        </h3>
        <p className="text-[11px] text-[var(--text-muted)]">
          Gateway-authoritative containment controls. Every action requires an audit reason. Risk scores never
          auto-enforce containment.
        </p>
        <div className="flex flex-wrap gap-2">
          {controls.map((control) => {
            const disabledReason = controlDisabledReason(control.kind, agent.status, role);
            return (
              <button
                key={control.kind}
                type="button"
                disabled={Boolean(disabledReason) || busy}
                title={disabledReason ?? undefined}
                onClick={() => onOpenControl(control.kind)}
                className="inline-flex items-center gap-1 rounded border border-[var(--border-default)] px-3 py-1.5 text-[11px] font-semibold text-[var(--text-primary)] transition-colors hover:bg-[var(--surface-elevated)] disabled:cursor-not-allowed disabled:opacity-50"
              >
                {control.icon}
                {control.label}
              </button>
            );
          })}
        </div>
      </div>

      <ConfirmDialog
        open={pendingControl !== null}
        title={pendingControl ? controlTitle(pendingControl.kind) : ""}
        impact={pendingControl ? controlImpact(pendingControl.kind) : ""}
        target={`${agent.agent_key} · ${agent.name}`}
        reason={auditReason}
        onReasonChange={onReasonChange}
        confirmLabel={pendingControl ? controlConfirmLabel(pendingControl.kind) : "Confirm"}
        confirmDisabled={!auditReason.trim() || busy}
        onConfirm={onConfirmControl}
        onCancel={onCancelControl}
      />
    </div>
  );
}

function DetailField({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <span className="mb-1 block text-[10px] font-bold uppercase tracking-wider text-[var(--text-muted)]">
        {label}
      </span>
      <div className="text-[var(--text-primary)]">{value}</div>
    </div>
  );
}

function DrillButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex items-center gap-1 rounded border border-[var(--border-default)] px-3 py-1.5 text-[11px] font-semibold text-[var(--brand)] hover:bg-[var(--surface-elevated)]"
    >
      <ExternalLink size={12} />
      {label}
    </button>
  );
}