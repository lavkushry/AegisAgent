# Dashboard: Bun SPA (ui-next). Built with Bun and copied to
# /app/ui/dist and /app/ui-next/dist so gateway path resolution works
# under AEGIS_UI_BUNDLE=next|legacy and AEGIS_UI_DIST overrides.
#
# See docs/components/Console_UI_Bun_Contracts.md §6 (Phase E cutover).
FROM oven/bun:1.4-debian AS ui-builder
WORKDIR /build/ui-next
COPY ui-next/package.json ui-next/bun.lock ./
RUN bun install --frozen-lockfile
COPY ui-next ./
# Production static export with base /dashboard/ (vite.config.ts).
RUN bun run build

FROM rust:1.97-bookworm AS builder
WORKDIR /build

# Network resilience for the crate fetch: crates.io downloads intermittently
# drop with "unexpected eof while reading" under cargo's HTTP/2 multiplexing.
# (The CI workflow sets these too, but they don't reach inside the docker build.)
ENV CARGO_NET_RETRY=10
ENV CARGO_HTTP_MULTIPLEXING=false

# aegis-api's build.rs (lib/api/build.rs) compiles proto/*.proto via
# prost-build/tonic-build, which needs the protoc binary on PATH.
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# #1160: repo-root .cargo/config.toml sets `--cfg tokio_unstable` (needed by
# the /debug/runtime endpoint's per-worker poll/busy-duration counters) — this
# build runs `cargo build` from /build (this WORKDIR), mirroring how CI invokes
# it from the repo root, so the config must land at the same relative path.
#
# Cargo-workspace layout (post-refactor): the gateway binary crate lives at
# src/, with sibling library crates under lib/{common,api,storage,policy,soc}
# and standalone runtime-control-plane binaries under bins/{aegis-node-sensor,...}
# — copy the whole workspace rather than the old single-crate `gateway/` tree.
# `cargo build -p gateway` still needs every member's Cargo.toml on disk to
# resolve the workspace manifest, even though only the gateway package itself
# is compiled in this stage.
COPY .cargo ./.cargo
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY lib ./lib
COPY bins ./bins
RUN cargo build --release -p gateway --bin gateway
# Strip debug symbols (~15% smaller binary) — the builder has `strip`
# available; the distroless final stage below does not.
RUN strip /build/target/release/gateway
# Pre-create the data dir owned by distroless's built-in nonroot uid/gid
# (65532) — the final stage below has no shell/mkdir to do this itself.
RUN mkdir -p /data && chown 65532:65532 /data

# distroless/cc-debian12 (#1207): no shell, no package manager. ":nonroot"
# runs as uid/gid 65532 by default — no `USER`/`useradd` needed (useradd
# isn't available here either). ca-certificates is copied explicitly from
# the builder rather than relying on whichever bundle this distroless
# variant happens to ship, since reqwest's TLS calls (webhook delivery,
# GitHub API, Qdrant) need a real CA store to verify outbound HTTPS
# regardless of what's baked into the base image.
FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /build/target/release/gateway /usr/local/bin/aegis-gateway
COPY policies.cedar /app/policies.cedar
# Place Bun SPA at the historical ui/dist path (gateway default + prefer-next).
COPY --from=ui-builder --chown=65532:65532 /build/ui-next/dist /app/ui/dist
# Also install under ui-next/dist so AEGIS_UI_BUNDLE=next resolves without remount.
COPY --from=ui-builder --chown=65532:65532 /build/ui-next/dist /app/ui-next/dist
COPY --from=builder --chown=65532:65532 /data /data

ENV DATABASE_URL=sqlite:///data/aegis.db
ENV CEDAR_POLICY_PATH=/app/policies.cedar
ENV RUST_LOG=info,gateway=debug,sqlx=info
# Explicit: serve Bun rewrite (redundant with files present; documents cutover).
ENV AEGIS_UI_BUNDLE=next

# No curl/shell in this image — `--healthcheck` execs the gateway binary
# itself, which GETs its own /livez and exits 0/1 (see main.rs).
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
    CMD ["/usr/local/bin/aegis-gateway", "--healthcheck"]

CMD ["/usr/local/bin/aegis-gateway"]
