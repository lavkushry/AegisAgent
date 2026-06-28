"use client";

import React, { useState } from "react";
import { useAppStore, type Theme, type Density, type Role } from "../app/store";
import { RefreshCw, Database, ShieldAlert, KeyRound } from "lucide-react";
import { DEMO_MODE } from "../app/runtimeConfig";

const INPUT_CLASS =
  "bg-[var(--surface-app)] border border-[var(--border-default)] rounded-md px-3 py-1.5 text-xs text-[var(--text-primary)] focus:border-[var(--border-focus)] focus:outline-none";

export default function ConfigBar({
  onRefresh,
  isFetching,
  statusMessage,
}: {
  onRefresh: () => void;
  isFetching: boolean;
  statusMessage: string;
}) {
  const {
    gatewayUrl,
    bearerToken,
    activeTenant,
    timeRange,
    variables,
    liveMode,
    theme,
    density,
    role,
    setGatewayUrl,
    setBearerToken,
    setActiveTenant,
    setTimeRange,
    setVariables,
    setLiveMode,
    setTheme,
    setDensity,
    setRole,
  } = useAppStore();

  const [localUrl, setLocalUrl] = useState(gatewayUrl);
  const [localToken, setLocalToken] = useState(bearerToken);
  const [localTenant, setLocalTenant] = useState(activeTenant);
  const [showToken, setShowToken] = useState(false);

  const handleSave = () => {
    setGatewayUrl(localUrl);
    setBearerToken(localToken);
    setActiveTenant(localTenant);
    setTimeout(onRefresh, 100);
  };

  return (
    <div className="flex flex-wrap items-center gap-4 bg-[var(--surface-panel)] border border-[var(--border-default)] rounded-xl p-4 text-sm">
      {(!activeTenant || !bearerToken) && (
        <div className="basis-full rounded-md border border-amber-500/30 bg-amber-950/20 px-3 py-2 text-xs text-amber-300" role="status">
          {!activeTenant
            ? "Select a tenant before loading SOC data."
            : "No bearer token is stored. Configure an in-memory token or use gateway-managed session/mTLS authentication."}
        </div>
      )}
      {/* Gateway URL */}
      <div className="flex flex-col gap-1 min-w-[200px]">
        <label className="text-xs text-[var(--text-secondary)] font-medium flex items-center gap-1">
          <Database size={12} /> Gateway URL
        </label>
        <input
          type="text"
          value={localUrl}
          onChange={(e) => setLocalUrl(e.target.value)}
          className={INPUT_CLASS}
        />
      </div>

      {/* Bearer Token */}
      <div className="flex flex-col gap-1 min-w-[150px]">
        <label className="text-xs text-[var(--text-secondary)] font-medium flex items-center gap-1">
          <KeyRound size={12} /> Bearer Token
        </label>
        <div className="relative">
          <input
            type={showToken ? "text" : "password"}
            value={localToken}
            onChange={(e) => setLocalToken(e.target.value)}
            className={`w-full ${INPUT_CLASS} pr-8`}
          />
          <button
            type="button"
            onClick={() => setShowToken(!showToken)}
            className="absolute right-2 top-2 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
          >
            {showToken ? "Hide" : "Show"}
          </button>
        </div>
      </div>

      {/* Tenant ID */}
      <div className="flex flex-col gap-1 min-w-[120px]">
        <label className="text-xs text-[var(--text-secondary)] font-medium flex items-center gap-1">
          <ShieldAlert size={12} /> Tenant ID
        </label>
        <input
          type="text"
          value={localTenant}
          onChange={(e) => setLocalTenant(e.target.value)}
          className={INPUT_CLASS}
        />
      </div>

      {/* Time Range */}
      <div className="flex flex-col gap-1 min-w-[100px]">
        <label className="text-xs text-[var(--text-secondary)] font-medium">Time Range</label>
        <select
          value={timeRange}
          onChange={(e) => setTimeRange(e.target.value)}
          className={INPUT_CLASS}
        >
          <option value="1h">Last 1 hour</option>
          <option value="24h">Last 24 hours</option>
          <option value="7d">Last 7 days</option>
          <option value="30d">Last 30 days</option>
        </select>
      </div>

      <div className="flex flex-col gap-1 min-w-[120px]">
        <label className="text-xs text-[var(--text-secondary)] font-medium">Agent variable</label>
        <input
          type="text"
          value={variables.agent ?? ""}
          placeholder="All agents"
          onChange={(event) => setVariables({ ...variables, agent: event.target.value })}
          className={INPUT_CLASS}
        />
      </div>

      <label className="flex items-center gap-2 self-end pb-2 text-xs text-[var(--text-secondary)]">
        <input type="checkbox" checked={liveMode} onChange={(event) => setLiveMode(event.target.checked)} />
        Live refresh
      </label>

      {/* Theme */}
      <div className="flex flex-col gap-1 min-w-[110px]">
        <label className="text-xs text-[var(--text-secondary)] font-medium">Theme</label>
        <select
          value={theme}
          onChange={(e) => setTheme(e.target.value as Theme)}
          className={INPUT_CLASS}
        >
          <option value="dark-soc">Dark SOC</option>
          <option value="light">Light</option>
          <option value="oled">OLED</option>
        </select>
      </div>

      {/* Density */}
      <div className="flex flex-col gap-1 min-w-[100px]">
        <label className="text-xs text-[var(--text-secondary)] font-medium">Density</label>
        <select
          value={density}
          onChange={(e) => setDensity(e.target.value as Density)}
          className={INPUT_CLASS}
        >
          <option value="compact">Compact</option>
          <option value="cozy">Cozy</option>
        </select>
      </div>

      {/* Role */}
      <div className="flex flex-col gap-1 min-w-[110px]">
        <label className="text-xs text-[var(--text-secondary)] font-medium">Role</label>
        <select
          value={role}
          onChange={(e) => setRole(e.target.value as Role)}
          disabled={!DEMO_MODE}
          title={DEMO_MODE ? "Local demo role override" : "Role is supplied by the authenticated gateway session"}
          className={INPUT_CLASS}
        >
          <option value="viewer">Viewer</option>
          <option value="analyst">Analyst</option>
          <option value="approver">Approver</option>
          <option value="admin">Admin</option>
        </select>
      </div>

      {/* Buttons */}
      <div className="flex items-end gap-2 h-full mt-auto pt-4 md:pt-0">
        <button
          onClick={handleSave}
          className="bg-[var(--brand)] hover:bg-[var(--brand-emphasis)] text-[var(--text-on-brand)] font-medium text-xs rounded-md px-4 py-2 transition-colors cursor-pointer"
        >
          Apply Config
        </button>
        <button
          onClick={onRefresh}
          disabled={isFetching}
          className="flex items-center gap-1.5 bg-[var(--interactive-bg)] hover:bg-[var(--interactive-bg-hover)] text-[var(--text-primary)] text-xs border border-[var(--border-default)] rounded-md px-4 py-2 transition-colors cursor-pointer disabled:opacity-50"
        >
          <RefreshCw size={12} className={isFetching ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      {/* Status Message */}
      {statusMessage && (
        <span className="ml-auto text-xs text-[var(--text-secondary)] italic max-w-[200px] text-right truncate">
          {statusMessage}
        </span>
      )}
    </div>
  );
}
