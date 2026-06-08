# Containerized bulwark-server (the cluster/control-plane tier) + the bulwark_admin CLI.
# Build context is the repo root:
#   docker build -f deploy/docker/Dockerfile -t bulwark-server .
#   docker build --build-arg FEATURES=onnx ...   # real image scoring + bundled model
#
# Built in CI (which has the RAM for the ORT/release build) and pulled by the small
# instance — see .github/workflows/deploy.yml. Base = Ubuntu 24.04 (matches the CI
# runner where `bulwark-server --features onnx` links cleanly; on debian-slim the
# onnxruntime static link fails with undefined abseil symbols). `ort`
# (download-binaries) downloads + links the matching onnxruntime; if that yields a
# shared lib we stage it next to the binary (LD_LIBRARY_PATH). bulwark-proto compiles
# its .proto hermetically via protox — no system protoc needed.

# ---- builder ------------------------------------------------------------------
FROM ubuntu:24.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl ca-certificates build-essential pkg-config libssl-dev cmake \
        clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*
# Pinned-channel stable Rust via rustup (matches the workspace rust-toolchain).
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal
ENV PATH=/root/.cargo/bin:$PATH
ARG FEATURES=""
WORKDIR /src
COPY . .
RUN if [ -n "$FEATURES" ]; then \
        cargo build --release -p bulwark-server --features "$FEATURES"; \
    else \
        cargo build --release -p bulwark-server; \
    fi \
    && mkdir -p /out/lib \
    && cp target/release/bulwark-server target/release/bulwark_admin /out/ \
    && find target/release -name 'libonnxruntime.so*' -type f -exec cp {} /out/lib/ \; \
    && { curl -fsSL https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-tiny.en-q5_1.bin \
           -o /out/ggml-tiny.en-q5_1.bin || touch /out/ggml-tiny.en-q5_1.bin; } \
    && ls -l /out /out/lib

# ---- runtime ------------------------------------------------------------------
# Ubuntu 24.04 too, so the binary's glibc/libstdc++ match the builder.
FROM ubuntu:24.04 AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -m -d /var/lib/bulwark bulwark
COPY --from=builder /out/bulwark-server /usr/local/bin/bulwark-server
COPY --from=builder /out/bulwark_admin  /usr/local/bin/bulwark_admin
# onnxruntime shared lib if the onnx build linked one (present only for
# FEATURES=onnx; the dir always exists so this COPY never fails). LD_LIBRARY_PATH
# lets the loader find it; empty + inert for the default build.
COPY --from=builder /out/lib/ /usr/local/lib/bulwark/
ENV LD_LIBRARY_PATH=/usr/local/lib/bulwark
# whisper STT model (staged above; empty placeholder if the download was skipped).
# The audio analyzer (FEATURES=whisper) loads it; absent/empty => audio fail-CLOSES.
COPY --from=builder /out/ggml-tiny.en-q5_1.bin /usr/local/share/bulwark/ggml-tiny.en-q5_1.bin
ENV BULWARK_WHISPER_MODEL=/usr/local/share/bulwark/ggml-tiny.en-q5_1.bin
USER bulwark
# Sensible container defaults; override per deployment. State persists on a volume.
ENV BULWARK_BIND=0.0.0.0:8443 \
    BULWARK_STATE_DIR=/var/lib/bulwark
EXPOSE 8443
VOLUME ["/var/lib/bulwark"]
# grpc.health.v1.Health is served on the same port for orchestrator probes.
ENTRYPOINT ["/usr/local/bin/bulwark-server"]
CMD ["--role", "all-in-one"]
