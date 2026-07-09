# aegis-llm-gateway: Phase 7.3 OpenAI-compatible reverse proxy that captures
# model-call lineage (hashes + token metadata) and ships it to the control
# plane. Separate binary/image from the gateway — scalable independently and
# never runs agent code.
FROM rust:1.96-bookworm AS builder
WORKDIR /build

ENV CARGO_NET_RETRY=10
ENV CARGO_HTTP_MULTIPLEXING=false

COPY .cargo ./.cargo
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY lib ./lib
COPY bins ./bins
RUN cargo build --release -p aegis-llm-gateway --bin aegis-llm-gateway
RUN strip /build/target/release/aegis-llm-gateway

FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /build/target/release/aegis-llm-gateway /usr/local/bin/aegis-llm-gateway

ENV RUST_LOG=info

# HTTP reverse proxy — kube tcpSocket/httpGet against the listen port works.
ENTRYPOINT ["/usr/local/bin/aegis-llm-gateway"]
CMD ["--listen", "0.0.0.0:8090"]
