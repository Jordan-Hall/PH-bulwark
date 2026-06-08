# Containerized bulwark-server

Runs the **cluster / control-plane tier** (the `bulwark-server` gRPC service) plus the
`bulwark_admin` provisioning CLI in a container — for a VPS or always-on home server.
The child-device filter (`bulwark_proxy`/`bulwark_vpn`) and the parent console run on
their own devices, not here.

## Build & run

```sh
# from the repo root
docker compose -f deploy/docker/docker-compose.yml up -d --build
```

This brings up `bulwark-server --role all-in-one` on `:8443` with accounts enabled and
durable state on the `bulwark-state` volume (`BULWARK_STATE_DIR=/var/lib/bulwark`).

## Provision guardians

```sh
docker compose -f deploy/docker/docker-compose.yml exec \
  -e BULWARK_ADMIN_PASSWORD='choose-a-strong-one' \
  bulwark-server bulwark_admin create-account guardian@home.example "Guardian"
# then `login` to mint a session token (kept off argv via the env vars).
```

## Health, lifecycle, TLS

- **Health:** `grpc.health.v1.Health` is served on `:8443` — point your orchestrator
  / load balancer / `grpc_health_probe` at it.
- **Shutdown:** `docker compose stop` sends `SIGTERM`; the server drains in-flight
  gRPC calls before exiting.
- **TLS / mTLS:** the default image serves plaintext (dev). For production, supply the
  server's cert material (mount certs + configure via `bulwark-core` config) or run
  behind a TLS-terminating proxy. See `docs/deployment.md` §4.
- **FCM push:** rebuild with `--build-arg FEATURES=push`, set `BULWARK_FCM_*`, and mount
  the service-account key (see the compose file).

See `docs/deployment.md` for the full env-var reference and production checklist.
