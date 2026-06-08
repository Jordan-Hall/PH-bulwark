# Containerized aegis-server (the cluster/control-plane tier) + the aegis_admin
# provisioning CLI. Build context is the repo root:
#
#   docker build -f deploy/docker/Dockerfile -t aegis-server .
#
# aegis-proto compiles its .proto hermetically via protox (pure Rust) — no system
# protoc needed. The default build excludes the `push` feature (no reqwest/openssl);
# enable FCM push with --build-arg FEATURES=push (and keep ca-certificates, below).

# ---- builder ------------------------------------------------------------------
FROM rust:1-bookworm AS builder
ARG FEATURES=""
WORKDIR /src
COPY . .
# Build aegis-server (the default bin) + aegis_admin. `ring` needs a C compiler,
# present in the full rust:bookworm image.
RUN if [ -n "$FEATURES" ]; then \
        cargo build --release -p aegis-server --features "$FEATURES"; \
    else \
        cargo build --release -p aegis-server; \
    fi

# ---- runtime ------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
# ca-certificates for outbound TLS (SMTP / FCM) when those are configured.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -m -d /var/lib/aegis aegis
COPY --from=builder /src/target/release/aegis-server /usr/local/bin/aegis-server
COPY --from=builder /src/target/release/aegis_admin  /usr/local/bin/aegis_admin
USER aegis
# Sensible container defaults; override per deployment. State persists on a volume.
ENV AEGIS_BIND=0.0.0.0:8443 \
    AEGIS_STATE_DIR=/var/lib/aegis
EXPOSE 8443
VOLUME ["/var/lib/aegis"]
# grpc.health.v1.Health is served on the same port for orchestrator probes.
ENTRYPOINT ["/usr/local/bin/aegis-server"]
CMD ["--role", "all-in-one"]
