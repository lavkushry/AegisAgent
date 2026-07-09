import { describe, expect, test } from "bun:test";
import {
  looksLikeSecretValue,
  redactJsonForDisplay,
  redactSecrets,
  REDACTED,
} from "./redact";

describe("redactSecrets", () => {
  test("redacts sensitive keys", () => {
    const out = redactSecrets({
      tool: "github",
      api_key: "sk-live-super-secret-do-not-leak",
      nested: { token: "abc", ok: true },
    }) as Record<string, unknown>;
    expect(out.api_key).toBe(REDACTED);
    expect((out.nested as Record<string, unknown>).token).toBe(REDACTED);
    expect((out.nested as Record<string, unknown>).ok).toBe(true);
    expect(out.tool).toBe("github");
  });

  test("redacts secret-shaped values under innocuous keys", () => {
    const out = redactSecrets({ note: "sk-live-abcdef" }) as {
      note: string;
    };
    expect(out.note).toBe(REDACTED);
  });

  test("does not mutate input", () => {
    const input = { api_key: "secret", keep: 1 };
    redactSecrets(input);
    expect(input.api_key).toBe("secret");
  });

  test("redactJsonForDisplay is parseable and redacted", () => {
    const json = redactJsonForDisplay({
      authorization: `Bearer ${"x".repeat(20)}`,
      count: 2,
    });
    const parsed = JSON.parse(json) as { authorization: string; count: number };
    expect(parsed.authorization).toBe(REDACTED);
    expect(parsed.count).toBe(2);
  });
});

describe("looksLikeSecretValue", () => {
  test("detects common prefixes", () => {
    expect(looksLikeSecretValue("sk-live-abc")).toBe(true);
    expect(looksLikeSecretValue("ghp_abc")).toBe(true);
    expect(looksLikeSecretValue("plain text")).toBe(false);
  });
});
