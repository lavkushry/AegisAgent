FROM rust:1.96-bookworm AS builder
WORKDIR /build

# Network resilience for the crate fetch: crates.io downloads intermittently
# drop with "unexpected eof while reading" under cargo's HTTP/2 multiplexing.
# (The CI workflow sets these too, but they don't reach inside the docker build.)
ENV CARGO_NET_RETRY=10
ENV CARGO_HTTP_MULTIPLEXING=false

COPY gateway/Cargo.toml gateway/Cargo.lock ./gateway/
COPY gateway/src ./gateway/src
COPY gateway/policies.cedar ./gateway/policies.cedar
RUN cargo build --release --manifest-path gateway/Cargo.toml

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/gateway/target/release/gateway /usr/local/bin/aegis-gateway
COPY policies.cedar /app/policies.cedar
RUN mkdir -p /data

ENV DATABASE_URL=sqlite:///data/aegis.db
ENV CEDAR_POLICY_PATH=/app/policies.cedar
ENV RUST_LOG=info,gateway=debug,sqlx=info

CMD ["/usr/local/bin/aegis-gateway"]
