# Containerized aegis-server (the cluster/control-plane tier) + the aegis_admin
# provisioning CLI. Build context is the repo root:
#
#   docker build -f deploy/docker/Dockerfile -t aegis-server .
#   docker build --build-arg FEATURES=onnx ...   # real image scoring + bundled model
#
# aegis-proto compiles its .proto hermetically via protox (pure Rust) — no system
# protoc needed. FEATURES is optional: e.g. `onnx` (ONNX Runtime image scoring),
# `push` (FCM), `classifier` (text backstop). The ORT/release build needs RAM, so
# this image is built in CI (not on the small instance) — see .github/workflows/deploy.yml.

# ---- builder ------------------------------------------------------------------
FROM rust:1-bookworm AS builder
ARG FEATURES=""
WORKDIR /src
COPY . .
# Build aegis-server (the default bin) + aegis_admin, then stage the binaries and —
# for FEATURES=onnx — the ONNX Runtime shared lib that `ort` (download-binaries)
# fetched, so the slim runtime can load it. `ring` needs a C compiler (present here).
RUN if [ -n "$FEATURES" ]; then \
        cargo build --release -p aegis-server --features "$FEATURES"; \
    else \
        cargo build --release -p aegis-server; \
    fi \
    && mkdir -p /out/lib \
    && cp target/release/aegis-server target/release/aegis_admin /out/ \
    && find target/release -name 'libonnxruntime*.so*' -exec cp -L {} /out/lib/ \; \
    && ls -l /out /out/lib

# ---- runtime ------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
# ca-certificates for outbound TLS (SMTP / FCM) when those are configured.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -m -d /var/lib/aegis aegis
COPY --from=builder /out/aegis-server /usr/local/bin/aegis-server
COPY --from=builder /out/aegis_admin  /usr/local/bin/aegis_admin
# ONNX Runtime shared lib — present only for FEATURES=onnx builds (the dir is always
# created so this COPY never fails). LD_LIBRARY_PATH points the loader at it; for the
# default build the dir is empty and this is harmless.
COPY --from=builder /out/lib/ /usr/local/lib/aegis/
ENV LD_LIBRARY_PATH=/usr/local/lib/aegis
USER aegis
# Sensible container defaults; override per deployment. State persists on a volume.
ENV AEGIS_BIND=0.0.0.0:8443 \
    AEGIS_STATE_DIR=/var/lib/aegis
EXPOSE 8443
VOLUME ["/var/lib/aegis"]
# grpc.health.v1.Health is served on the same port for orchestrator probes.
ENTRYPOINT ["/usr/local/bin/aegis-server"]
CMD ["--role", "all-in-one"]
