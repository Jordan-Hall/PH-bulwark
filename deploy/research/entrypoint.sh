#!/bin/sh
# Run the Dioxus fullstack server (handles /api/* server functions) in the
# background, then Caddy in the foreground. Caddy serves the static SSG site
# directly and reverse-proxies only /api/* to the server on 127.0.0.1:3000.
#
# Caddy is always the foreground process, so if the server binary is missing or
# crashes the SITE STAYS UP — /api just 502s and the waitlist form falls back to
# its mailto. The server can never take the whole site down.
set -e

if [ -x /srvapp/server ]; then
  ( cd /srvapp && IP=127.0.0.1 PORT=3000 ./server ) &
  echo "started fullstack server on 127.0.0.1:3000"
else
  echo "WARN: /srvapp/server missing or not executable — /api disabled, form uses mailto"
fi

exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
