# API reference

The gateway exposes its full HTTP API contract two ways:

- **Live, against a running gateway** — `GET /v1/docs` serves a Swagger UI rendering, fetched from `GET /v1/docs/openapi.json`. This always reflects exactly what that running instance accepts, including any local Cedar policy or feature-flag differences.
- **Static, last merge to `main`** — **[Rendered API reference (Redoc)](api/index.html)**, published alongside this site. `docs/api/openapi.json` is regenerated fresh on every push to `main` that touches the gateway's route annotations, via `cargo run --release --bin export_openapi --manifest-path gateway/Cargo.toml` in the [Docs CI workflow](https://github.com/lavkushry/AegisAgent/blob/main/.github/workflows/docs.yml) — never a checked-in snapshot that can go stale.

Both render the same underlying spec (`gateway::routes::openapi::ApiDoc`, a `utoipa::OpenApi` derive over every handler's `#[utoipa::path(...)]` annotation) — pick whichever fits: Swagger UI for "try it out" against your own deployment, Redoc for a faster-loading reference you don't need a running gateway to read.

See [the runtime authorization API guide](runtime-authorization-api.md) for a narrative walkthrough of the core `/v1/authorize` flow, and the [full endpoint contract in `CLAUDE.md`](https://github.com/lavkushry/AegisAgent/blob/main/CLAUDE.md#api-endpoints-contract) for a single-page summary of every route.
