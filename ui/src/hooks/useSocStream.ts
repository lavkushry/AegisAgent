"use client";

import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useDatasources } from "@/datasources/registry";
import { STREAM_DATASOURCE_ID, type StreamConnectionStatus } from "@/datasources/stream";
import type { StreamEvent, StreamTopic } from "@/datasources/types";
import { useAppStore } from "@/app/store";

export const SOC_SUMMARY_QUERY_KEY = "soc-summary";

const DEFAULT_TOPICS: ReadonlyArray<StreamTopic> = ["ase", "alert", "approval"];

export function invalidateForStreamEvent(queryClient: ReturnType<typeof useQueryClient>, event: StreamEvent) {
  void queryClient.invalidateQueries({ queryKey: ["panel"] });
  void queryClient.invalidateQueries({ queryKey: [SOC_SUMMARY_QUERY_KEY] });

  switch (event.topic) {
    case "approval":
      void queryClient.invalidateQueries({ queryKey: ["entity", "approval"] });
      break;
    case "alert":
      void queryClient.invalidateQueries({ queryKey: ["entity", "alert"] });
      break;
    case "ase":
      void queryClient.invalidateQueries({ queryKey: ["entity", "decision"] });
      void queryClient.invalidateQueries({ queryKey: ["entity", "incident"] });
      break;
    default:
      break;
  }
}

/**
 * Subscribes to the advisory SOC stream when live mode is enabled. Reconciles
 * with TanStack Query polling by invalidating the same query keys the panels use.
 */
export function useSocStream(options?: { enabled?: boolean; topics?: ReadonlyArray<StreamTopic> }) {
  const queryClient = useQueryClient();
  const datasources = useDatasources();
  const gatewayUrl = useAppStore((state) => state.gatewayUrl);
  const bearerToken = useAppStore((state) => state.bearerToken);
  const activeTenant = useAppStore((state) => state.activeTenant);
  const authEpoch = useAppStore((state) => state.authEpoch);
  const liveMode = useAppStore((state) => state.liveMode);
  const setStreamStatus = useAppStore((state) => state.setStreamStatus);

  const enabled =
    (options?.enabled ?? liveMode) && Boolean(gatewayUrl && bearerToken && activeTenant);
  const topics = options?.topics ?? DEFAULT_TOPICS;
  const topicKey = topics.join(",");

  useEffect(() => {
    if (!enabled) {
      setStreamStatus("closed");
      return undefined;
    }

    const datasource = datasources.get(STREAM_DATASOURCE_ID);
    if (!datasource?.subscribe) {
      setStreamStatus("polling");
      return undefined;
    }

    const subscription = datasource.subscribe(
      { topics: [...topics], variables: {} },
      (event) => invalidateForStreamEvent(queryClient, event),
      (status: StreamConnectionStatus) => setStreamStatus(status),
    );

    return () => subscription.close();
  }, [
    enabled,
    gatewayUrl,
    bearerToken,
    activeTenant,
    authEpoch,
    topicKey,
    datasources,
    queryClient,
    setStreamStatus,
    topics,
  ]);
}