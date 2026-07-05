import { describe, expect, it } from "vitest";

import type { WebhookSubscriptionRecord } from "@/app/api";
import { classifyWebhookUrl, contactChannelStatuses } from "./supportStates";

const baseSub = (url: string): WebhookSubscriptionRecord => ({
  id: "sub-1",
  tenant_id: "tenant-a",
  url,
  event_types: "alert,incident",
  status: "active",
  min_severity: "info",
  format: "json",
  delivery_status: "healthy",
  consecutive_failures: 0,
  created_at: "2026-01-01T00:00:00Z",
});

describe("classifyWebhookUrl", () => {
  it("detects slack, pagerduty, email, and generic webhooks", () => {
    expect(classifyWebhookUrl("https://hooks.slack.com/services/T/B/X")).toBe("slack");
    expect(classifyWebhookUrl("https://events.pagerduty.com/v2/enqueue/abc")).toBe("pagerduty");
    expect(classifyWebhookUrl("mailto:ops@example.com")).toBe("email");
    expect(classifyWebhookUrl("https://example.com/hook")).toBe("webhook");
  });
});

describe("contactChannelStatuses", () => {
  it("marks slack supported when a slack webhook exists", () => {
    const statuses = contactChannelStatuses({ webhooks: true, playbooks: true, silences: false }, [
      baseSub("https://hooks.slack.com/services/T/B/X"),
    ]);
    const slack = statuses.find((s) => s.channel === "slack");
    expect(slack?.support).toBe("supported");
  });

  it("marks pagerduty standby and email unsupported", () => {
    const statuses = contactChannelStatuses({ webhooks: true, playbooks: true, silences: false }, []);
    expect(statuses.find((s) => s.channel === "pagerduty")?.support).toBe("standby");
    expect(statuses.find((s) => s.channel === "email")?.support).toBe("unsupported");
  });

  it("marks all channels unsupported when webhooks API is absent", () => {
    const statuses = contactChannelStatuses({ webhooks: false, playbooks: false, silences: false }, []);
    expect(statuses.find((s) => s.channel === "slack")?.support).toBe("unsupported");
    expect(statuses.find((s) => s.channel === "webhook")?.support).toBe("unsupported");
  });
});