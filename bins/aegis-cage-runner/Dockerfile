# aegis-cage-runner: disposable Docker sandbox executor for unknown agents.
# Separate binary/image from the gateway (docs/AegisAgent_Agent_Cage.md).
#
# Runtime needs the Docker CLI + a mounted host docker.sock so create/start/
# kill of sandbox containers use the host engine (not Docker-in-Docker).
FROM rust:1.96-bookworm AS builder
WORKDIR /build

ENV CARGO_NET_RETRY=10
ENV CARGO_HTTP_MULTIPLEXING=false

COPY .cargo ./.cargo
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY lib ./lib
COPY bins ./bins
RUN cargo build --release -p aegis-cage-runner --bin aegis-cage-runner
RUN strip /build/target/release/aegis-cage-runner
RUN mkdir -p /var/lib/aegis-cage && chown 65532:65532 /var/lib/aegis-cage

# bookworm-slim + docker CLI (glibc matches the release binary). Distroless
# is not suitable: we must shell out to `docker` against a mounted socket.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates docker.io \
    && rm -rf /var/lib/apt/lists/* \
    && # Keep only the client bits we need; drop the dockerd unit noise.
       rm -f /usr/sbin/dockerd /usr/bin/dockerd 2>/dev/null || true

WORKDIR /var/lib/aegis-cage
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /build/target/release/aegis-cage-runner /usr/local/bin/aegis-cage-runner
COPY --from=builder /var/lib/aegis-cage /var/lib/aegis-cage

ENV RUST_LOG=info

# Root is intentional for local/dev docker.sock access. Production should
# run as a dedicated user in the docker group matching the host socket GID.
ENTRYPOINT ["/usr/local/bin/aegis-cage-runner"]
CMD ["--config", "/etc/aegis-cage/runner.toml"]
