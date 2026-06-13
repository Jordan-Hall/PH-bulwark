# Predator Hunters Research static site — build the Dioxus 0.8 web/wasm bundle in
# CI, then serve it from a tiny nginx image. Multi-stage so the runtime image
# carries only the static bundle (no Rust toolchain).
#
# Build context is the REPO ROOT (the app embeds branding/logo.jpg via a
# ../../../branding relative include, and is a detached cargo workspace under
# apps/research with its own Cargo.lock).

# ---- build stage -----------------------------------------------------------
FROM rust:1-bookworm AS build
RUN rustup target add wasm32-unknown-unknown
# dx (the Dioxus CLI), pinned to the same 0.8 alpha the app is proven against.
RUN cargo install dioxus-cli --version 0.8.0-alpha.0 --locked

WORKDIR /app
COPY . .

WORKDIR /app/apps/research
RUN dx build --platform web --release

# dx emits the servable bundle to target/dx/<name>/release/web/public — locate
# the produced index.html robustly and stage its directory.
RUN set -eux; \
    PUB="$(dirname "$(find /app -type f -name index.html -path '*release/web/public*' | head -n1)")"; \
    test -n "$PUB"; \
    mkdir -p /site; cp -r "$PUB"/. /site/; \
    ls -la /site

# ---- runtime stage ---------------------------------------------------------
FROM nginx:1.27-alpine
COPY deploy/research/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /site /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=4s --retries=3 CMD wget -qO- http://127.0.0.1/healthz || exit 1
