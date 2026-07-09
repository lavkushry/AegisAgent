# aegis-egress-proxy: the network egress choke point (Phase 5.3). A
# separate binary/image from the gateway (see lib.rs) — it forwards agent
# traffic and asks the gateway (or a local rule set) allow/deny per
# connection, so it must be independently deployable and independently
# scalable from the gateway itself.
FROM rust:1.96-bookworm AS builder
WORKDIR /build

# Network resilience for the crate fetch, mirroring src/Dockerfile.
ENV CARGO_NET_RETRY=10
ENV CARGO_HTTP_MULTIPLEXING=false

# #1160: repo-root .cargo/config.toml sets `--cfg tokio_unstable` — copy it
# so this build (run from /build, mirroring CI's repo-root invocation)
# resolves the same workspace config the gateway's Dockerfile does.
COPY .cargo ./.cargo
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY lib ./lib
COPY bins ./bins
RUN cargo build --release -p aegis-egress-proxy --bin aegis-egress-proxy
RUN strip /build/target/release/aegis-egress-proxy

# distroless/cc-debian12 (no shell, no package manager), matching the
# gateway image's hardening posture. ca-certificates copied explicitly —
# the proxy's GatewayDecider calls the gateway's /v1/egress/check over
# HTTPS in production and needs a real CA store to verify it.
FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /build/target/release/aegis-egress-proxy /usr/local/bin/aegis-egress-proxy

ENV RUST_LOG=info

# No HTTP health endpoint on this binary — it's a CONNECT/forward proxy,
# not an HTTP server with a /livez route. Kubernetes' `tcpSocket` liveness
# probe against the listen port covers "is the process still accepting
# connections" without needing a fabricated health-check flag; see the
# Helm chart's deployment.yaml.
ENTRYPOINT ["/usr/local/bin/aegis-egress-proxy"]
CMD ["--listen", "0.0.0.0:8888"]
