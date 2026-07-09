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

/**
 * Soft capability probe: true if the path responds as present.
 * 404/405/501 → false; other errors (auth, network) → true so the UI still
 * attempts the real call rather than silently disabling the feature.
 */
export async function probeGatewayEndpoint(
  opts: FetchOptions,
  path: string,
): Promise<boolean> {
  try {
    await fetchFromGateway<unknown>(opts, path);
    return true;
  } catch (error) {
    if (
      error instanceof GatewayRequestError &&
      [404, 405, 501].includes(error.status)
    ) {
      return false;
    }
    return true;
  }
}

/** Binary download (evidence packs). Fail-closed on non-2xx. */
export async function downloadFromGateway(
  options: FetchOptions,
  path: string,
  method: "GET" | "POST" = "GET",
  body?: unknown,
): Promise<Blob> {
  const url = `${options.gatewayUrl.replace(/\/+$/, "")}${path}`;
  const hasBody = body !== undefined;
  const headers = buildGatewayHeaders(options, hasBody);
  // Prefer zip for export endpoints; Accept still ok as */*
  headers.Accept = "application/zip, application/octet-stream, */*";
  const response = await fetch(url, {
    method,
    headers,
    signal: options.signal,
    body: hasBody ? JSON.stringify(body) : undefined,
  });
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
  return response.blob();
}

export function triggerBlobDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
