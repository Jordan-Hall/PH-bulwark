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
# Fullstack SSG: build a server binary that pre-renders every static route to
# real HTML (great for crawlers / link bots / no-JS), then the wasm hydrates.
RUN dx build --fullstack --ssg --release
# SSG emits client assets to .../release/web/public and the pre-rendered
# per-route HTML to .../release/web/static. Merge into /site: assets first, then
# the rendered HTML (which provides index.html and the per-route directories).
RUN set -eux; \
    WEB="$(dirname "$(find /app -type d -path '*release/web/public' | head -n1)")"; \
    test -n "$WEB"; test -d "$WEB/static"; \
    mkdir -p /site; \
    cp -r "$WEB/public/." /site/; \
    cp -r "$WEB/static/." /site/; \
    echo "=== /site routes ==="; find /site -name index.html | sort

# ---- 2. build Caddy with the Cloudflare DNS plugin ------------------------
FROM caddy:2-builder AS caddybuild
RUN xcaddy build --with github.com/caddy-dns/cloudflare

# ---- 3. runtime -----------------------------------------------------------
FROM caddy:2-alpine
COPY --from=caddybuild /usr/bin/caddy /usr/bin/caddy
COPY deploy/research/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /site /srv
# Static SEO + share files, served at the root: /og.png, /robots.txt,
# /sitemap.xml, /apple-touch-icon.png (copied after the bundle so they sit at
# /srv root, not under /assets).
COPY deploy/research/static/ /srv/
EXPOSE 80 443
