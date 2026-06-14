# Predator Hunters Research site — build the Dioxus 0.8 fullstack bundle, then
# serve it with Caddy (Cloudflare DNS plugin) + the fullstack server beside it.
#
# Caddy serves the pre-rendered static SSG site and auto-provisions a real
# Let's Encrypt cert via the Cloudflare DNS-01 challenge (CF_API_TOKEN), so the
# origin is valid under Cloudflare "Full (strict)". Cert state persists in the
# /data host volume. Caddy reverse-proxies only /api/* to the fullstack server
# (the waitlist endpoint); if that server is down, Caddy still serves the whole
# site and the form falls back to mailto, so the server can't take the site down.
#
# Runtime is debian-slim (not alpine) because the Rust server binary is glibc;
# the Caddy binary from xcaddy is static and runs fine here.
#
# Build context is the REPO ROOT (the app is a detached cargo workspace under
# apps/research).

# ---- 1. build the wasm bundle + fullstack server -------------------------
FROM rust:1-bookworm AS build
RUN rustup target add wasm32-unknown-unknown
RUN cargo install dioxus-cli --version 0.8.0-alpha.0 --locked
WORKDIR /app
COPY . .
WORKDIR /app/apps/research
# Fullstack SSG: pre-render every static route to real HTML (crawlers / no-JS),
# the wasm hydrates on the client, and the same build emits a `server` binary
# that handles /api/* server functions (the waitlist).
RUN dx build --fullstack --ssg --release
# The bundle is .../release/web/{server, public/, static/}. Merge public+static
# into /site for Caddy's static root, and stage the whole bundle (incl. the
# server binary) into /srvapp for the fullstack server process to run from.
RUN set -eux; \
    WEB="$(dirname "$(find /app -type d -path '*release/web/public' | head -n1)")"; \
    test -n "$WEB"; test -d "$WEB/static"; \
    mkdir -p /site; \
    cp -r "$WEB/public/." /site/; \
    cp -r "$WEB/static/." /site/; \
    mkdir -p /srvapp; \
    cp -r "$WEB/." /srvapp/; \
    test -x /srvapp/server || { echo "ERROR: no executable server binary in bundle"; ls -la "$WEB"; exit 1; }; \
    echo "=== /site routes ==="; find /site -name index.html | sort; \
    echo "=== server binary ==="; ls -la /srvapp/server

# ---- 2. build Caddy with the Cloudflare DNS plugin ------------------------
FROM caddy:2-builder AS caddybuild
RUN xcaddy build --with github.com/caddy-dns/cloudflare

# ---- 3. runtime ----------------------------------------------------------
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=caddybuild /usr/bin/caddy /usr/bin/caddy
# Match the caddy:2 image's dirs so the existing /data volume's LE cert state is
# reused (no re-issuance): Caddy stores certs under $XDG_DATA_HOME/caddy.
ENV XDG_CONFIG_HOME=/config \
    XDG_DATA_HOME=/data
COPY deploy/research/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /site /srv
COPY --from=build /srvapp /srvapp
# Static SEO + share files at the root: /robots.txt, /sitemap.xml, /og*.png,
# /apple-touch-icon.png, /.well-known/security.txt.
COPY deploy/research/static/ /srv/
COPY deploy/research/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
EXPOSE 80 443
# CMD (not ENTRYPOINT) so the CI smoke test `docker run IMAGE caddy version`
# still works by overriding the command.
CMD ["/usr/local/bin/entrypoint.sh"]
