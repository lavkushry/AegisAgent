# Dashboard (#1326): the gateway's serve_dashboard_index/serve_dashboard_static
# handlers (src/src/routes/dashboard.rs) read a static-exported Next.js build
# from the relative path `ui/dist` at runtime — ui/next.config.ts sets
# `output: "export", distDir: "dist"` for exactly this. Build it here and copy
# the result into the final image; without this stage the gateway has no
# `ui/dist` and every /dashboard/* request 404s.
FROM node:20-bookworm AS ui-builder
WORKDIR /build/ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui ./
RUN npm run build

FROM rust:1.96-bookworm AS builder
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
# — copy the whole workspace rather than the old single-crate `gateway/` tree.
COPY .cargo ./.cargo
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY lib ./lib
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
#
# Image size note: ~88MB measured (base alone is ~37MB of glibc + libgcc +
# libssl; the gateway binary is ~35MB even stripped) — cedar-policy,
# qdrant-client/tonic, sqlx, and rustls/aws-lc-rs are real weight, not bloat
# to trim further. The issue's <50MB target assumed a `static-debian12` +
# musl-static build; that's not reachable here, since several transitive
# deps (aws-lc-rs's C code, SQLite's bundled C amalgamation) need a musl
# toolchain to cross-compile against, and a from-scratch musl build is
# unverified and out of scope for this PR. ~88MB is still a substantial
# improvement over the prior debian:bookworm-slim+apt image, and meets the
# criteria that actually harden the runtime: no shell, no package manager,
# non-root.
FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /build/target/release/gateway /usr/local/bin/aegis-gateway
COPY policies.cedar /app/policies.cedar
COPY --from=ui-builder --chown=65532:65532 /build/ui/dist /app/ui/dist
COPY --from=builder --chown=65532:65532 /data /data

ENV DATABASE_URL=sqlite:///data/aegis.db
ENV CEDAR_POLICY_PATH=/app/policies.cedar
ENV RUST_LOG=info,gateway=debug,sqlx=info

# No curl/shell in this image — `--healthcheck` execs the gateway binary
# itself, which GETs its own /livez and exits 0/1 (see main.rs).
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
    CMD ["/usr/local/bin/aegis-gateway", "--healthcheck"]

CMD ["/usr/local/bin/aegis-gateway"]
