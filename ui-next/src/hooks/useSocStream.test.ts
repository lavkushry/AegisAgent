import { describe, expect, test } from "bun:test";
import { invalidateForStreamEvent } from "./useSocStream";

describe("invalidateForStreamEvent", () => {
  test("invalidates panel and topic-specific keys", () => {
    const keys: string[][] = [];
    const queryClient = {
      invalidateQueries: ({ queryKey }: { queryKey: string[] }) => {
        keys.push(queryKey);
      },
    };
    invalidateForStreamEvent(queryClient as never, {
      topic: "approval",
      payload: {},
      ts: new Date().toISOString(),
    });
    expect(keys.some((k) => k[0] === "panel")).toBe(true);
    expect(keys.some((k) => k[0] === "approvals")).toBe(true);
  });
});
