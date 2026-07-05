import { describe, expect, it } from "vitest";

import type { WebhookSubscriptionRecord } from "@/app/api";
import { buildNotificationPolicies } from "./notificationPolicies";

describe("buildNotificationPolicies", () => {
  it("derives policies from webhook subscriptions", () => {
    const subs: WebhookSubscriptionRecord[] = [
      {
        id: "sub-1",
        tenant_id: "tenant-a",
        url: "https://hooks.slack.com/services/T/B/X",
        event_types: "alert",
        status: "active",
        min_severity: "high",
        format: "json",
        delivery_status: "healthy",
        consecutive_failures: 0,
        created_at: "2026-01-01T00:00:00Z",
      },
    ];
    const policies = buildNotificationPolicies(subs);
    expect(policies).toHaveLength(1);
    expect(policies[0]).toMatchObject({
      channel: "slack",
      eventTypes: "alert",
      minSeverity: "high",
      deliveryStatus: "healthy",
    });
  });
});