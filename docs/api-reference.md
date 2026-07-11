# API reference

> **Status:** Generated HTTP reference for the current gateway route annotations. Protobuf files in `lib/api/proto/` remain the source of truth for shared REST/gRPC API types.

The gateway exposes its full HTTP API contract two ways:

- **Live, against a running gateway** — `GET /v1/docs` serves a Swagger UI rendering, fetched from `GET /v1/docs/openapi.json`. This always reflects exactly what that running instance accepts, including any local Cedar policy or feature-flag differences.
- **Static, last merge to `main`** — **[Rendered API reference (Redoc)](api/index.html)**, published alongside this site. `docs/api/openapi.json` is regenerated fresh on every push to `main` that touches the gateway's route annotations, via `cargo run --release --bin export_openapi` from the `src/` crate in the [Docs CI workflow](https://github.com/lavkushry/AegisAgent/blob/main/.github/workflows/docs.yml) — never a checked-in snapshot that can go stale.

Both render the same underlying spec (`gateway::routes::openapi::ApiDoc`, a `utoipa::OpenApi` derive over every handler's `#[utoipa::path(...)]` annotation) — pick whichever fits: Swagger UI for "try it out" against your own deployment, Redoc for a faster-loading reference you don't need a running gateway to read.

See [the runtime authorization API guide](runtime-authorization-api.md) for a narrative walkthrough of the core `/v1/authorize` flow, and the [full endpoint contract in `CLAUDE.md`](https://github.com/lavkushry/AegisAgent/blob/main/CLAUDE.md#api-endpoints-contract) for a single-page summary of every route.

## Quick verification

```bash
curl -fsS http://127.0.0.1:8080/v1/openapi.json | python3 -m json.tool
cargo run -p gateway --bin export_openapi > /tmp/aegis-openapi.json
```

The first reads the running instance; the second exports compile-time route metadata without starting the gateway. Generated output must not contain credentials or environment-specific secret values.

## References

[Runtime Authorization API](runtime-authorization-api.md) · [API Versioning](api-versioning.md) · [Architecture Patterns](architecture.md) · [gRPC Protobuf Definitions](https://github.com/lavkushry/AegisAgent/tree/main/lib/api/proto)
