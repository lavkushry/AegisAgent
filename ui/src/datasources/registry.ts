"use client";

import { useMemo } from "react";
import { useAppStore } from "@/app/store";
import { GatewayEntityDatasource } from "./gatewayEntity";
import type { Datasource } from "./types";

export const DEFAULT_DATASOURCE_ID = "gateway-entity";

/**
 * Build the datasource map from the current gateway connection settings.
 * Memoized on the connection so instances are stable between renders but
 * rebuild when the user changes gateway URL or token.
 */
export function useDatasources(): Map<string, Datasource> {
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);

  return useMemo(() => {
    const opts = { gatewayUrl, bearerToken };
    const entity = new GatewayEntityDatasource(opts);
    const map = new Map<string, Datasource>();
    map.set(entity.id, entity);
    return map;
  }, [gatewayUrl, bearerToken]);
}
