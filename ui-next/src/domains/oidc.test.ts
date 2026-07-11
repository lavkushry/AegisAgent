import { describe, expect, test } from "bun:test";
import { oidcLoginUrl, parseOidcCallbackFragment } from "./oidc";

function base64UrlEncode(json: string): string {
  return Buffer.from(json)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fakeJwt(claims: Record<string, unknown>): string {
  const header = base64UrlEncode(JSON.stringify({ alg: "HS256" }));
  const payload = base64UrlEncode(JSON.stringify(claims));
  return `${header}.${payload}.fake-signature`;
}

describe("oidcLoginUrl", () => {
  test("appends the login path and strips trailing slashes", () => {
    expect(oidcLoginUrl("https://gw.example.com/")).toBe(
      "https://gw.example.com/v1/auth/oidc/login",
    );
    expect(oidcLoginUrl("https://gw.example.com")).toBe(
      "https://gw.example.com/v1/auth/oidc/login",
    );
  });
});

describe("parseOidcCallbackFragment", () => {
  test("returns null for a fragment with neither token nor error", () => {
    expect(parseOidcCallbackFragment("")).toBeNull();
    expect(parseOidcCallbackFragment("#")).toBeNull();
    expect(parseOidcCallbackFragment("#foo=bar")).toBeNull();
  });

  test("extracts the access token and decodes its tenant_id claim", () => {
    const jwt = fakeJwt({ sub: "tenant_a", tenant_id: "tenant_a", exp: 123 });
    const parsed = parseOidcCallbackFragment(`#access_token=${jwt}`);
    expect(parsed?.accessToken).toBe(jwt);
    expect(parsed?.tenantId).toBe("tenant_a");
    expect(parsed?.error).toBeUndefined();
  });

  test("tolerates a malformed token by leaving tenantId undefined", () => {
    const parsed = parseOidcCallbackFragment("#access_token=not-a-jwt");
    expect(parsed?.accessToken).toBe("not-a-jwt");
    expect(parsed?.tenantId).toBeUndefined();
  });

  test("extracts an error reason", () => {
    const parsed = parseOidcCallbackFragment("#error=identity_not_linked");
    expect(parsed?.accessToken).toBeUndefined();
    expect(parsed?.error).toBe("identity_not_linked");
  });
});
