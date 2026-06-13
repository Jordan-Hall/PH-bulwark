# Predator Hunters Research static site — build the Dioxus 0.8 web/wasm bundle,
# then serve it from Caddy with the Cloudflare DNS plugin. Caddy auto-provisions
# a real Let's Encrypt certificate via DNS-01 (using CF_API_TOKEN), so the origin
# presents a publicly-trusted cert that satisfies Cloudflare "Full (strict)" —
# with no acme-on-box and no cert files to mount. Multi-stage so the runtime
# image carries only the static bundle + the Caddy binary.
#
# Build context is the REPO ROOT (the app embeds branding/* via ../../../ relative
# includes, and is a detached cargo workspace under apps/research).

# ---- 1. build the wasm bundle ---------------------------------------------
FROM rust:1-bookworm AS build
RUN rustup target add wasm32-unknown-unknown
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

# ---- 2. build Caddy with the Cloudflare DNS plugin ------------------------
FROM caddy:2-builder AS caddybuild
RUN xcaddy build --with github.com/caddy-dns/cloudflare

# ---- 3. runtime -----------------------------------------------------------
FROM caddy:2-alpine
COPY --from=caddybuild /usr/bin/caddy /usr/bin/caddy
COPY deploy/research/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /site /srv
EXPOSE 80 443
