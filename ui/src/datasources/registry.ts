"use client";

import { useMemo } from "react";
import { useAppStore } from "@/app/store";
import { GatewayEntityDatasource } from "./gatewayEntity";
import { ReceiptDatasource } from "./receipt";
import { SocQueryDatasource } from "./socQuery";
import { SocStreamDatasource } from "./stream";
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
  const tenantId = useAppStore((s) => s.activeTenant);

  return useMemo(() => {
    const opts = { gatewayUrl, bearerToken, tenantId };
    const entity = new GatewayEntityDatasource(opts);
    const socQuery = new SocQueryDatasource(opts);
    const receipts = new ReceiptDatasource(opts);
    const stream = new SocStreamDatasource(opts);
    const map = new Map<string, Datasource>();
    map.set(entity.id, entity);
    map.set(socQuery.id, socQuery);
    map.set(receipts.id, receipts);
    map.set(stream.id, stream);
    return map;
  }, [gatewayUrl, bearerToken, tenantId]);
}
