# Containerized aegis-server (the cluster/control-plane tier) + the aegis_admin CLI.
# Build context is the repo root:
#   docker build -f deploy/docker/Dockerfile -t aegis-server .
#   docker build --build-arg FEATURES=onnx ...   # real image scoring + bundled model
#
# Built in CI (which has the RAM for the ORT/release build) and pulled by the small
# instance — see .github/workflows/deploy.yml. Base = Ubuntu 24.04 (matches the CI
# runner where `aegis-server --features onnx` links cleanly; on debian-slim the
# onnxruntime static link fails with undefined abseil symbols). `ort`
# (download-binaries) downloads + links the matching onnxruntime; if that yields a
# shared lib we stage it next to the binary (LD_LIBRARY_PATH). aegis-proto compiles
# its .proto hermetically via protox — no system protoc needed.

# ---- builder ------------------------------------------------------------------
FROM ubuntu:24.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl ca-certificates build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*
# Pinned-channel stable Rust via rustup (matches the workspace rust-toolchain).
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal
ENV PATH=/root/.cargo/bin:$PATH
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
    && find target/release -name 'libonnxruntime.so*' -type f -exec cp {} /out/lib/ \; \
    && ls -l /out /out/lib

# ---- runtime ------------------------------------------------------------------
# Ubuntu 24.04 too, so the binary's glibc/libstdc++ match the builder.
FROM ubuntu:24.04 AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -m -d /var/lib/aegis aegis
COPY --from=builder /out/aegis-server /usr/local/bin/aegis-server
COPY --from=builder /out/aegis_admin  /usr/local/bin/aegis_admin
# onnxruntime shared lib if the onnx build linked one (present only for
# FEATURES=onnx; the dir always exists so this COPY never fails). LD_LIBRARY_PATH
# lets the loader find it; empty + inert for the default build.
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
