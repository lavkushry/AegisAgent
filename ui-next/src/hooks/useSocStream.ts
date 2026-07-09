import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useDatasources } from "@/datasources/registry";
import { STREAM_DATASOURCE_ID } from "@/datasources/stream";
import type {
  StreamConnectionStatus,
  StreamEvent,
  StreamTopic,
} from "@/datasources/types";
import { useAppStore } from "@/app/store";

const DEFAULT_TOPICS: ReadonlyArray<StreamTopic> = [
  "ase",
  "alert",
  "approval",
];

export function invalidateForStreamEvent(
  queryClient: ReturnType<typeof useQueryClient>,
  event: StreamEvent,
): void {
  void queryClient.invalidateQueries({ queryKey: ["panel"] });
  switch (event.topic) {
    case "approval":
      void queryClient.invalidateQueries({ queryKey: ["approvals"] });
      break;
    case "alert":
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      break;
    case "ase":
      void queryClient.invalidateQueries({ queryKey: ["explore"] });
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      break;
    default:
      break;
  }
}

/**
 * When live mode is on, poll SOC topics and invalidate panel/list queries.
 */
export function useSocStream(options?: {
  enabled?: boolean;
  topics?: ReadonlyArray<StreamTopic>;
}): void {
  const queryClient = useQueryClient();
  const datasources = useDatasources();
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const liveMode = useAppStore((s) => s.liveMode);
  const setStreamStatus = useAppStore((s) => s.setStreamStatus);

  const enabled =
    (options?.enabled ?? liveMode) &&
    Boolean(gatewayUrl && activeTenant.trim());
  const topics = options?.topics ?? DEFAULT_TOPICS;
  const topicKey = topics.join(",");

  useEffect(() => {
    if (!enabled) {
      setStreamStatus("closed");
      return undefined;
    }

    const datasource = datasources.get(STREAM_DATASOURCE_ID);
    if (!datasource?.subscribe) {
      setStreamStatus("closed");
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
    topicKey,
    datasources,
    queryClient,
    setStreamStatus,
    topics,
  ]);
}
