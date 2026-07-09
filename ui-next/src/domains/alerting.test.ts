import { describe, expect, test } from "bun:test";
import { redactUrl } from "./alerting";

describe("redactUrl", () => {
  test("strips query secrets", () => {
    expect(redactUrl("https://hooks.example/x?token=secret")).toBe(
      "https://hooks.example/x",
    );
  });

  test("handles invalid URLs", () => {
    expect(redactUrl("not-a-url?secret=abc")).toContain("***");
  });
});
