"use client";

import React, { useState } from "react";
import { useAppStore } from "../app/store";
import { RefreshCw, Database, ShieldAlert, KeyRound } from "lucide-react";

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
    setGatewayUrl,
    setBearerToken,
    setActiveTenant,
    setTimeRange,
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
    <div className="flex flex-wrap items-center gap-4 bg-[#111827] border border-[#334155] rounded-xl p-4 text-sm">
      {/* Gateway URL */}
      <div className="flex flex-col gap-1 min-w-[200px]">
        <label className="text-xs text-[#94a3b8] font-medium flex items-center gap-1">
          <Database size={12} /> Gateway URL
        </label>
        <input
          type="text"
          value={localUrl}
          onChange={(e) => setLocalUrl(e.target.value)}
          className="bg-[#0f172a] border border-[#334155] rounded-md px-3 py-1.5 text-xs text-[#e2e8f0] focus:border-indigo-500 focus:outline-none"
        />
      </div>

      {/* Bearer Token */}
      <div className="flex flex-col gap-1 min-w-[150px]">
        <label className="text-xs text-[#94a3b8] font-medium flex items-center gap-1">
          <KeyRound size={12} /> Bearer Token
        </label>
        <div className="relative">
          <input
            type={showToken ? "text" : "password"}
            value={localToken}
            onChange={(e) => setLocalToken(e.target.value)}
            className="w-full bg-[#0f172a] border border-[#334155] rounded-md pl-3 pr-8 py-1.5 text-xs text-[#e2e8f0] focus:border-indigo-500 focus:outline-none"
          />
          <button
            type="button"
            onClick={() => setShowToken(!showToken)}
            className="absolute right-2 top-2 text-xs text-[#94a3b8] hover:text-[#e2e8f0]"
          >
            {showToken ? "Hide" : "Show"}
          </button>
        </div>
      </div>

      {/* Tenant ID */}
      <div className="flex flex-col gap-1 min-w-[120px]">
        <label className="text-xs text-[#94a3b8] font-medium flex items-center gap-1">
          <ShieldAlert size={12} /> Tenant ID
        </label>
        <input
          type="text"
          value={localTenant}
          onChange={(e) => setLocalTenant(e.target.value)}
          className="bg-[#0f172a] border border-[#334155] rounded-md px-3 py-1.5 text-xs text-[#e2e8f0] focus:border-indigo-500 focus:outline-none"
        />
      </div>

      {/* Time Range */}
      <div className="flex flex-col gap-1 min-w-[100px]">
        <label className="text-xs text-[#94a3b8] font-medium">Time Range</label>
        <select
          value={timeRange}
          onChange={(e) => setTimeRange(e.target.value)}
          className="bg-[#0f172a] border border-[#334155] rounded-md px-3 py-1.5 text-xs text-[#e2e8f0] focus:border-indigo-500 focus:outline-none"
        >
          <option value="1h">Last 1 hour</option>
          <option value="24h">Last 24 hours</option>
          <option value="7d">Last 7 days</option>
          <option value="30d">Last 30 days</option>
        </select>
      </div>

      {/* Buttons */}
      <div className="flex items-end gap-2 h-full mt-auto pt-4 md:pt-0">
        <button
          onClick={handleSave}
          className="bg-indigo-600 hover:bg-indigo-700 text-white font-medium text-xs rounded-md px-4 py-2 transition-colors cursor-pointer"
        >
          Apply Config
        </button>
        <button
          onClick={onRefresh}
          disabled={isFetching}
          className="flex items-center gap-1.5 bg-[#1e293b] hover:bg-[#273549] text-[#e2e8f0] text-xs border border-[#334155] rounded-md px-4 py-2 transition-colors cursor-pointer disabled:opacity-50"
        >
          <RefreshCw size={12} className={isFetching ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      {/* Status Message */}
      {statusMessage && (
        <span className="ml-auto text-xs text-[#94a3b8] italic max-w-[200px] text-right truncate">
          {statusMessage}
        </span>
      )}
    </div>
  );
}
