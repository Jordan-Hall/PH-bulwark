# Containerized aegis-server (the cluster/control-plane tier) + the aegis_admin CLI.
# Build context is the repo root:
#   docker build -f deploy/docker/Dockerfile -t aegis-server .
#   docker build --build-arg FEATURES=onnx ...   # real image scoring + bundled model
#
# Built in CI (which has the RAM for the ORT/release build) and pulled by the small
# instance — see .github/workflows/deploy.yml. On Linux, onnx uses ort `load-dynamic`
# (see aegis-vision/Cargo.toml): the build does NOT static-link onnxruntime (which
# drags in undefined abseil symbols and fails the slim-builder link); instead ort
# dlopens the .so at runtime, which we stage below and point ORT_DYLIB_PATH at.
# aegis-proto compiles its .proto hermetically via protox — no system protoc needed.

# ---- builder ------------------------------------------------------------------
FROM rust:1-bookworm AS builder
ARG FEATURES=""
WORKDIR /src
COPY . .
RUN if [ -n "$FEATURES" ]; then \
        cargo build --release -p aegis-server --features "$FEATURES"; \
    else \
        cargo build --release -p aegis-server; \
    fi \
    && mkdir -p /out/lib \
    && cp target/release/aegis-server target/release/aegis_admin /out/ \
    && so="$(find target/release -name 'libonnxruntime.so*' -type f | head -1)" \
    && if [ -n "$so" ]; then cp "$so" /out/lib/libonnxruntime.so; fi \
    && ls -l /out /out/lib

# ---- runtime ------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -m -d /var/lib/aegis aegis
COPY --from=builder /out/aegis-server /usr/local/bin/aegis-server
COPY --from=builder /out/aegis_admin  /usr/local/bin/aegis_admin
# ONNX Runtime shared lib — present only for FEATURES=onnx builds (the dir always
# exists, so this COPY never fails). ort (load-dynamic) dlopens it via ORT_DYLIB_PATH.
# For the default build the dir is empty and ort isn't compiled in, so this is inert.
COPY --from=builder /out/lib/ /usr/local/lib/aegis/
ENV ORT_DYLIB_PATH=/usr/local/lib/aegis/libonnxruntime.so
USER aegis
# Sensible container defaults; override per deployment. State persists on a volume.
ENV AEGIS_BIND=0.0.0.0:8443 \
    AEGIS_STATE_DIR=/var/lib/aegis
EXPOSE 8443
VOLUME ["/var/lib/aegis"]
# grpc.health.v1.Health is served on the same port for orchestrator probes.
ENTRYPOINT ["/usr/local/bin/aegis-server"]
CMD ["--role", "all-in-one"]
