# aegis-tool-broker: standalone tool-broker execution engine (Phase 1
# extraction). A separate binary/image from the gateway — the gateway no
# longer links aegis-tool-broker-connectors at all, so this is the only
# process that resolves a real provider credential or executes a connector.
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
RUN cargo build --release -p aegis-tool-broker --bin aegis-tool-broker
RUN strip /build/target/release/aegis-tool-broker

# distroless/cc-debian12 (no shell, no package manager), matching the
# gateway image's hardening posture. ca-certificates copied explicitly — the
# GithubConnector's real mode and HttpConnector both make outbound HTTPS
# calls and need a real CA store to verify them.
FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /build/target/release/aegis-tool-broker /usr/local/bin/aegis-tool-broker

ENV RUST_LOG=info

# Unlike aegis-egress-proxy (a CONNECT proxy with no HTTP health route),
# this binary is a real HTTP JSON API — `--healthcheck` self-GETs /livez and
# exits 0/1, used here instead of pulling curl/wget into the distroless
# final image.
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
    CMD ["/usr/local/bin/aegis-tool-broker", "--healthcheck"]

ENTRYPOINT ["/usr/local/bin/aegis-tool-broker"]
CMD ["--listen", "0.0.0.0:8899"]
