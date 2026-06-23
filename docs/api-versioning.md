# API Versioning Strategy

AegisAgent employs prefix-based API versioning to ensure backward compatibility for SDKs and clients while supporting ongoing feature development.

---

## 1. Overview

The AegisAgent control plane APIs are versioned using URL path prefixes. Currently, two prefixes are supported:
* `/v1/`: Legacy/Stable API version. The endpoints under this prefix are deprecated and scheduled for deprecation.
* `/v2/`: Current/Stable API version. All active and new feature developments are exposed here.

System diagnostic endpoints (`/health`, `/livez`, `/readyz`, `/startupz`), Prometheus metrics (`/metrics`), and the static SOC Console Dashboard (`/dashboard/*`) are unversioned and mapped directly on the root context.

---

## 2. Deprecation and Sunset Headers

To communicate the deprecation status of the `/v1/` endpoints to client SDKs and calling systems, the gateway automatically appends HTTP response headers to all responses returned by endpoints matching the `/v1/` prefix.

These headers follow standard practices:
* **`deprecation`**: Set to `true` to signal that the endpoint is deprecated.
* **`sunset`**: Set to a standard HTTP-date (`Wed, 31 Dec 2026 23:59:59 GMT`) indicating the time when the `/v1/` prefix endpoints are scheduled to be removed.

Example HTTP response headers for a `/v1/` request:
```http
HTTP/1.1 200 OK
content-type: application/json
deprecation: true
sunset: Wed, 31 Dec 2026 23:59:59 GMT
```

Calling SDKs and clients should log warnings when these headers are received, encouraging administrators to update the gateway endpoint configurations to `/v2/`.

---

## 3. Implementation Details

AegisAgent implements prefix-based version routing using Axum's nested routing structure inside `gateway/src/main.rs`:

1. **`api_routes` Router Builder:** Contains all registration, interception, SOC, and compliance endpoint registrations *without* any version prefixes.
2. **Nesting and Middleware:**
   * `/v1` nests `api_routes` with the `deprecation_middleware` layer.
   * `/v2` nests `api_routes` directly without any additional layers.

```text
               ┌──► /v1/ (deprecation_middleware) ──► api_routes (v1 handler pool)
Client Request ┼──► /v2/ ───────────────────────────► api_routes (v2 handler pool)
               └──► /health, /readyz, /metrics, etc. (unversioned)
```

---

## 4. Developer Guidelines

When modifying existing handlers or adding new ones:
* **Non-Breaking Changes:** If a change is backward-compatible (e.g. adding an optional query param or enriching a response body), register it in `api_routes()`. It will automatically be served under both `/v1/` and `/v2/` prefixes.
* **Breaking Changes:** If you need to make a breaking change (e.g. removing a field, changing JSON structure):
  1. Extract the route registration from the shared `api_routes` function.
  2. Implement/register the legacy handler explicitly under the `/v1` mount in `main.rs`.
  3. Register the new version of the handler explicitly under the `/v2` mount.

---

## 5. Content Negotiation

Clients and SDKs can request version-specific endpoints without using the path prefixes `/v1/` or `/v2/` by supplying an `Accept` HTTP header. 

When a request is sent to an unversioned route (e.g. `/authorize`, `/agents`), the gateway dynamically inspects the `Accept` header and rewrites the request URI path:
* **`Accept: application/vnd.aegis.v2+json`**: Rewrites and routes the request internally as `/v2/...`.
* **`Accept: application/vnd.aegis.v1+json`**: Rewrites and routes the request internally as `/v1/...`.
* **Unspecified / Other Accept Headers**: Defaults to `/v1/...` for backward compatibility.

Diagnostic and static endpoints (e.g., `/health`, `/livez`, `/readyz`, `/startupz`, `/metrics`, `/debug/runtime`, and `/dashboard/*`) are exempt from content negotiation and are always served directly from the root context.

