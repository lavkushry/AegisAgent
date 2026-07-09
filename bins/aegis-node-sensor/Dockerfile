# aegis-node-sensor: runtime telemetry + signed command enforcement,
# deliberately kept as a separate process/image from both the gateway and
# the cage runner (see lib.rs doc comment) so a compromised sandbox can't
# reach sensor state directly.
FROM rust:1.96-bookworm AS builder
WORKDIR /build

ENV CARGO_NET_RETRY=10
ENV CARGO_HTTP_MULTIPLEXING=false

COPY .cargo ./.cargo
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY lib ./lib
COPY bins ./bins
RUN cargo build --release -p aegis-node-sensor --bin aegis-node-sensor
RUN strip /build/target/release/aegis-node-sensor
# The sensor's identity key and spool dir default to CWD-relative paths
# (config.rs's DEFAULT_IDENTITY_KEY_PATH/DEFAULT_SPOOL_DIR) — give the
# distroless nonroot uid (65532) a writable /var/lib/aegis-sensor to hold
# both, since the final stage has no shell/mkdir to do this itself.
RUN mkdir -p /var/lib/aegis-sensor && chown 65532:65532 /var/lib/aegis-sensor

FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /build/target/release/aegis-node-sensor /usr/local/bin/aegis-node-sensor
COPY --from=builder --chown=65532:65532 /var/lib/aegis-sensor /var/lib/aegis-sensor

ENV RUST_LOG=info

WORKDIR /var/lib/aegis-sensor
ENTRYPOINT ["/usr/local/bin/aegis-node-sensor"]
# --config points at a mounted TOML (see helm/aegis-node-sensor's
# ConfigMap); identity_key_path/spool_dir in that file should stay under
# /var/lib/aegis-sensor so they land on the mounted volume, not the
# read-only image layer.
CMD ["--config", "/etc/aegis-sensor/sensor.toml"]
