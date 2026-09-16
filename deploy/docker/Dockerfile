# Containerized bulwark-server (cluster/control plane + Remote VPN filter runtime).
# Build context is the repo root.

FROM ubuntu:24.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl ca-certificates build-essential pkg-config libssl-dev cmake \
        clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*
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
    && curl -fL --retry 3 https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-tiny.en-q5_1.bin \
         -o /out/ggml-tiny.en-q5_1.bin \
    && test -s /out/ggml-tiny.en-q5_1.bin \
    && test -s crates/bulwark-vision/models/nsfw_detector.onnx \
    && ls -l /out /out/lib crates/bulwark-vision/models/nsfw_detector.onnx

FROM ubuntu:24.04 AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates ffmpeg \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -m -d /var/lib/bulwark bulwark
COPY --from=builder /out/bulwark-server /usr/local/bin/bulwark-server
COPY --from=builder /out/bulwark_admin /usr/local/bin/bulwark_admin
COPY --from=builder /out/lib/ /usr/local/lib/bulwark/
COPY --from=builder /out/ggml-tiny.en-q5_1.bin /usr/local/share/bulwark/ggml-tiny.en-q5_1.bin
# The production vision model is a required release artifact, not an optional
# host volume. This keeps server/Remote VPN image coverage deterministic.
COPY --from=builder /src/crates/bulwark-vision/models/nsfw_detector.onnx /usr/local/share/bulwark/nsfw_detector.onnx
ENV LD_LIBRARY_PATH=/usr/local/lib/bulwark \
    BULWARK_WHISPER_MODEL=/usr/local/share/bulwark/ggml-tiny.en-q5_1.bin \
    BULWARK_NSFW_MODEL=/usr/local/share/bulwark/nsfw_detector.onnx \
    BULWARK_FFMPEG_BINARY=/usr/bin/ffmpeg
USER bulwark
ENV BULWARK_BIND=0.0.0.0:8443 \
    BULWARK_STATE_DIR=/var/lib/bulwark
EXPOSE 8443
VOLUME ["/var/lib/bulwark"]
ENTRYPOINT ["/usr/local/bin/bulwark-server"]
CMD ["--role", "all-in-one"]
