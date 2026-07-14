# Blueprint: Week-3 typed AuthorizeService extraction

**Roadmap:** Phase 1 Week 3 · **Law:** `docs/architecture.md` §5 (thin
adapters), §4 (target seams) · **Status:** Phase A types + Phase B flag path +
Phase C equality corpus landed on `feat/typed-authorize-service`
(`authorize_service.rs` unit + `equality_*` tests, gRPC dual path). Phase D
default-on cleanup remains.

## 1. Architectural scope & impact

Today `POST /v1/authorize` is one 8.5k-line `authorize_action_impl`
(`src/src/routes/authorize.rs`) taking `HeaderMap`/`Bytes`/`SocketAddr` and
returning `axum::response::Response`. The gRPC `authorize`
(`src/src/grpc.rs:157`) violates law §5 verbatim: it JSON-serializes the
request, forges headers and a `127.0.0.1:0` peer address, calls the REST
impl, buffers the Axum body, re-parses response JSON, and collapses every
structured error into `Status::internal`.

Target seam (protocol-neutral, transport concerns stay in adapters):

```text
REST adapter: parse bytes -> transport auth (bearer/HMAC-over-raw-body/mTLS
              headers) -> AuthorizeExecution -> map to (StatusCode, Json)
gRPC adapter: metadata auth -> AuthorizeExecution -> map to proto / Status

AuthorizeExecution (new module src/src/authorize_service.rs):
    pub struct AuthorizeContext { tenant_id, client_addr, transport,
        authenticated_agent_cn, raw_body_verified, ... }
    pub async fn authorize(state, ctx, payload: AuthorizeRequest)
        -> Result<AuthorizedOutcome, StatusError>
    pub struct AuthorizedOutcome { status: StatusCode, body: AuthorizeResponse }
```

`StatusError` and `AuthorizeResponse` are the two shapes behind all 114
current response sites — the conversion is mechanical, no behavior change.

## 2. Execution phases

- **Phase A (boundary split):** inside authorize.rs, split
  `authorize_action_impl` into `parse_and_authenticate` (REST-only: JSON
  parse, HMAC over raw bytes, header tenant, mTLS CN, auth-failure tracker)
  and `authorize_core(state, ctx, payload) -> Result<AuthorizedOutcome,
  StatusError>`. Convert the 114 `into_response()` sites to typed returns.
  REST handler output is byte-identical (same StatusError JSON envelope,
  same success payloads).
- **Phase B (gRPC direct path):** feature flag `AEGIS_TYPED_AUTHORIZE`
  (default off). When on, gRPC authenticates from metadata and calls
  `authorize_core` directly — no JSON round-trip, no forged headers, real
  peer address from tonic remote_addr, typed StatusError→Status mapping
  (bad_request→InvalidArgument, unauthorized→Unauthenticated,
  forbidden→PermissionDenied, conflict→Aborted, too_many_requests→
  ResourceExhausted, internal→Internal). When off, legacy path unchanged.
- **Phase C (equality gate):** replay-corpus test driving both paths with
  identical requests (allow / deny / require_approval / replay-nonce /
  dry-run / banned agent / bad payload) asserting equal decisions,
  action_hashes, approval rows, receipts, and error classes. CI job runs
  the suite with the flag on and off.
- **Phase D (flip + cleanup):** default flag on; delete the round-trip;
  move `authorize_core` toward a `lib/`-hosted service crate in a later
  week (not this PR).

## 3. Verification targets

`cargo test --workspace -- --test-threads=1` (existing authorize route
tests must pass unchanged), the new equality corpus, `cargo clippy
--workspace --all-targets -- -D warnings`, fmt, `scripts/
loadtest-authorize.sh` smoke, benchmark regression gates (authorize bench
must not regress >25%).

## 4. Security audit checklist

- [x] HMAC verification still runs over the exact raw REST bytes (stays in
      the REST adapter — the service never re-serializes for auth; gRPC
      typed path serializes once for signature compatibility only)
- [x] auth-failure tracker still keyed by real client address per transport
      (typed gRPC uses tonic `remote_addr`, not forged loopback)
- [x] tenant binding: `ctx.tenant_id` is the single authority the service
      uses when building service headers
- [x] fail-closed: any context the adapter cannot authenticate never
      constructs an AuthorizeContext (missing bearer/mTLS → Unauthenticated)
- [x] no behavior change to Cedar, approvals, receipts, replay, bans
      (Phase C equality corpus)
- [ ] security-review sign-off before Phase D flips the default
