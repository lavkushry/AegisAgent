"use client";

import { useQuery } from "@tanstack/react-query";
import { getSocSummary } from "@/app/api";
import { useAppStore } from "@/app/store";
import { SOC_SUMMARY_QUERY_KEY } from "./useSocStream";

/** Tenant-scoped SOC summary used for nav badges and overview vitals. */
export function useSocSummary() {
  const gatewayUrl = useAppStore((state) => state.gatewayUrl);
  const bearerToken = useAppStore((state) => state.bearerToken);
  const activeTenant = useAppStore((state) => state.activeTenant);
  const authEpoch = useAppStore((state) => state.authEpoch);
  const liveMode = useAppStore((state) => state.liveMode);
  const streamStatus = useAppStore((state) => state.streamStatus);

  const enabled = Boolean(gatewayUrl && bearerToken && activeTenant);
  const pollMs = liveMode && streamStatus !== "live" ? 5_000 : liveMode ? 30_000 : false;

  return useQuery({
    queryKey: [SOC_SUMMARY_QUERY_KEY, gatewayUrl, bearerToken, activeTenant, authEpoch],
    enabled,
    staleTime: 10_000,
    refetchInterval: pollMs,
    queryFn: ({ signal }) =>
      getSocSummary({
        gatewayUrl,
        bearerToken,
        tenantId: activeTenant,
        signal,
      }),
  });
}