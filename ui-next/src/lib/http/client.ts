import { getCsrfToken } from "./csrf";
import { GatewayRequestError, TenantRequiredError } from "./errors";

export interface FetchOptions {
  gatewayUrl: string;
  bearerToken: string;
  tenantId: string;
  signal?: AbortSignal;
}

export function buildGatewayHeaders(
  options: FetchOptions,
  hasBody = false,
): Record<string, string> {
  const tenantId = options.tenantId.trim();
  if (!tenantId) {
    throw new TenantRequiredError();
  }

  const headers: Record<string, string> = {
    Accept: "application/json",
    "X-Aegis-Tenant-ID": tenantId,
  };
  const token = options.bearerToken.trim();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  if (hasBody) {
    headers["Content-Type"] = "application/json";
  }
  const csrfToken = getCsrfToken();
  if (csrfToken) {
    headers["X-CSRF-Token"] = csrfToken;
  }
  return headers;
}

async function readGatewayJson<T>(response: Response): Promise<T> {
  if (response.status === 204) {
    return {} as T;
  }
  if (!response.ok) {
    let errorMsg = `HTTP ${response.status}: ${response.statusText}`;
    try {
      const errJson: unknown = await response.json();
      if (
        typeof errJson === "object" &&
        errJson !== null &&
        "message" in errJson &&
        typeof (errJson as { message: unknown }).message === "string"
      ) {
        errorMsg = (errJson as { message: string }).message;
      }
    } catch {
      // keep status message
    }
    throw new GatewayRequestError(errorMsg, response.status);
  }
  return response.json() as Promise<T>;
}

export async function fetchFromGateway<T>(
  options: FetchOptions,
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const url = `${options.gatewayUrl.replace(/\/+$/, "")}${path}`;
  const hasBody = body !== undefined;
  const response = await fetch(url, {
    method,
    headers: buildGatewayHeaders(options, hasBody),
    signal: options.signal,
    body: hasBody ? JSON.stringify(body) : undefined,
  });
  return readGatewayJson<T>(response);
}

export async function probeLivez(
  gatewayUrl: string,
  signal?: AbortSignal,
): Promise<boolean> {
  try {
    const res = await fetch(`${gatewayUrl.replace(/\/+$/, "")}/livez`, {
      signal,
    });
    return res.ok;
  } catch {
    return false;
  }
}
