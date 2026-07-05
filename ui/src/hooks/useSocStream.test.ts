import { describe, expect, it, vi } from "vitest";
import { QueryClient } from "@tanstack/react-query";
import type { StreamEvent } from "@/datasources/types";
import { invalidateForStreamEvent, SOC_SUMMARY_QUERY_KEY } from "./useSocStream";

describe("invalidateForStreamEvent", () => {
  it("invalidates panel and summary queries for every stream event", () => {
    const queryClient = new QueryClient();
    const invalidateSpy = vi.spyOn(queryClient, "invalidateQueries");

    invalidateForStreamEvent(queryClient, {
      topic: "ase",
      ts: "2026-07-05T08:00:00Z",
      payload: { event_id: "evt-1" },
    });

    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ["panel"] });
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: [SOC_SUMMARY_QUERY_KEY] });
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ["entity", "decision"] });
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ["entity", "incident"] });
  });

  it("invalidates approval entities for approval events", () => {
    const queryClient = new QueryClient();
    const invalidateSpy = vi.spyOn(queryClient, "invalidateQueries");

    invalidateForStreamEvent(queryClient, {
      topic: "approval",
      ts: "2026-07-05T08:00:00Z",
      payload: { approval_id: "approval-1" },
    } satisfies StreamEvent);

    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ["entity", "approval"] });
  });

  it("invalidates alert entities for alert events", () => {
    const queryClient = new QueryClient();
    const invalidateSpy = vi.spyOn(queryClient, "invalidateQueries");

    invalidateForStreamEvent(queryClient, {
      topic: "alert",
      ts: "2026-07-05T08:00:00Z",
      payload: { alert_id: "alert-1" },
    } satisfies StreamEvent);

    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ["entity", "alert"] });
  });
});