# Containerized aegis-server

Runs the **cluster / control-plane tier** (the `aegis-server` gRPC service) plus the
`aegis_admin` provisioning CLI in a container — for a VPS or always-on home server.
The child-device filter (`aegis_proxy`/`aegis_vpn`) and the parent console run on
their own devices, not here.

## Build & run

```sh
# from the repo root
docker compose -f deploy/docker/docker-compose.yml up -d --build
```

This brings up `aegis-server --role all-in-one` on `:8443` with accounts enabled and
durable state on the `aegis-state` volume (`AEGIS_STATE_DIR=/var/lib/aegis`).

## Provision guardians

```sh
docker compose -f deploy/docker/docker-compose.yml exec \
  -e AEGIS_ADMIN_PASSWORD='choose-a-strong-one' \
  aegis-server aegis_admin create-account guardian@home.example "Guardian"
# then `login` to mint a session token (kept off argv via the env vars).
```

## Health, lifecycle, TLS

- **Health:** `grpc.health.v1.Health` is served on `:8443` — point your orchestrator
  / load balancer / `grpc_health_probe` at it.
- **Shutdown:** `docker compose stop` sends `SIGTERM`; the server drains in-flight
  gRPC calls before exiting.
- **TLS / mTLS:** the default image serves plaintext (dev). For production, supply the
  server's cert material (mount certs + configure via `aegis-core` config) or run
  behind a TLS-terminating proxy. See `docs/deployment.md` §4.
- **FCM push:** rebuild with `--build-arg FEATURES=push`, set `AEGIS_FCM_*`, and mount
  the service-account key (see the compose file).

See `docs/deployment.md` for the full env-var reference and production checklist.
