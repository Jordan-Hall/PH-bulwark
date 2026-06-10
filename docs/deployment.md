# Bulwark production deployment runbook

How to stand up Bulwark for a real family/household. For **dev** setup see
`running.md`; this doc is the production procedure + the canonical environment-
variable reference.

> **Honest status.** The architecture and safety logic are implemented and
> CI-green, but several pieces are operator-provisioned rather than automated, and
> a few need a real environment to verify. Each section flags its **Not-yet-wired**
> gaps, collected in §13.
>
> **Trust model** (see `tamper-protection.md`, `on-device-scanning.md`): Bulwark runs
> only on **managed, child-aware, consented** devices — transparent, no covert
> capture, no raw-content exfiltration. Suspected CSAM is blocked + hashed, **never**
> stored, transmitted, previewed, or auto-reported (a human/legal decision).

## 1. Architecture at a glance

```
child device                              home cluster                guardian
┌────────────────────────┐   AlertRelay   ┌───────────────┐  email +  ┌──────────────┐
│ bulwark_proxy / bulwark_vpn │──(redacted)──▶ │ bulwark-server  │── FCM ───▶ │ parent app / │
│  TLS inspection filter + OCR +    │   gRPC         │ relay+accounts│   push     │ UI / phone   │
│  tamper heartbeat       │◀─ offload ────▶│ +Review+Tamper│            └──────────────┘
└────────────────────────┘  (mTLS)        └───────────────┘
```
- **Child** runs `bulwark_proxy` (no admin; per-user system proxy) or `bulwark_vpn`
  (admin; TUN captures all TCP). Both TLS inspection HTTPS with the per-install root CA and
  run the same pipeline; both emit a tamper heartbeat.
- **Cluster** (`bulwark-server`, roles `all-in-one`/`lb`/`worker`) receives redacted
  `AlertEvent`s, scopes per child/guardian, and delivers via email + optional FCM.
- **Guardian** reviews on the desktop parent app or the `bulwark-ui` dashboard.

## 2. Server roles & bring-up
- **All-in-one** (single household): `bulwark-server --role all-in-one` (default),
  `BULWARK_BIND=0.0.0.0:8443` for LAN. Only this role keeps a server-side
  `SegmentStore` for co-located video replay.
- **lb + worker** (multi-node): build `--features gossip,quorum`; one `--role lb`,
  N `--role worker`. Each node's cluster identity comes from env (no code changes):
  `BULWARK_NODE_ID` (unique, e.g. the host IP), `BULWARK_CLUSTER_ID` (same across the
  cluster), `BULWARK_CLUSTER_ADDRESS` (this node's `host:port`), `BULWARK_CLUSTER_SEEDS`
  (comma-separated peers — give every worker the LB's address), and
  `BULWARK_QUORUM_DSN` (shared Postgres for the authoritative lease store). Scale out
  by starting more workers with the LB as their seed (the Ansible playbook in
  `deploy/ansible/` automates this — add a host IP + re-run).
- Server build features: `classifier` (text backstop), `push` (FCM sink). Default
  build is byte-identical without `push`.
- **Lifecycle:** the server shuts down gracefully on `SIGTERM` (systemd/Docker
  stop) or `Ctrl-C`, draining in-flight gRPC calls before exit — so service
  restarts don't cut off alert delivery mid-flight. A malformed `BULWARK_BIND` fails
  fast at startup with a clear error.
- **Health probe:** the server exposes the standard gRPC health service
  (`grpc.health.v1.Health`, status SERVING) on the same port — point a load
  balancer / systemd / k8s / `grpc_health_probe` at it for readiness.
- **Containerized (VPS / home server):** `docker compose -f deploy/docker/docker-compose.yml
  up -d --build` runs the server tier with durable state on a volume; provision
  guardians via `... exec ... bulwark_admin`. See `deploy/docker/README.md`. A CI job
  builds the image so the Dockerfile can't rot.
- **Not-yet-wired:** multi-node gossip/quorum/Postgres is unverified on the Windows
  dev host (`rusqlite`/`bulwark-store` fails, env error 4551).

## 3. Accounts & guardian provisioning
- Enable with `BULWARK_ACCOUNTS=1`. Off ⇒ device-scoped review (empty token; dev/
  single-home).
- Model: parent = email + password (PBKDF2-HMAC-SHA256, 100k iters; never stored
  plaintext); child linked to a `device_id`; guardians assigned per child; alerts
  scoped by session token.
- **Provision with the `bulwark_admin` CLI** (talks to the running server's `Accounts`
  service at `BULWARK_ADMIN_ENDPOINT`, default `http://127.0.0.1:8443`; pins
  `BULWARK_CLUSTER_CA` if set). Secrets come from the environment, never argv (which
  leaks into `ps` output and shell history): the password from
  `$BULWARK_ADMIN_PASSWORD`, the session token from `$BULWARK_GUARDIAN_TOKEN`:
  ```text
  BULWARK_ADMIN_PASSWORD='…' bulwark_admin create-account guardian@home.example "Guardian"
  BULWARK_ADMIN_PASSWORD='…' bulwark_admin login          guardian@home.example  # -> token
  BULWARK_GUARDIAN_TOKEN='…' bulwark_admin add-child       "Kid" kids-tablet-01
  BULWARK_GUARDIAN_TOKEN='…' bulwark_admin assign-guardian <child_id> <other_account_id>
  BULWARK_GUARDIAN_TOKEN='…' bulwark_admin list-children
  BULWARK_GUARDIAN_TOKEN='…' bulwark_admin create-pair-code "Kid"   # -> code
  bulwark_admin redeem-pair-code <code> kids-tablet-01             # child-side flow
  ```
  The `login` token is what you put in `BULWARK_GUARDIAN_TOKEN` (for both this CLI and
  the parent app).
  Tokens expire after `BULWARK_SESSION_TTL_SECS` (default 12h) and are dropped on
  restart, so a leaked token is short-lived — re-`login` to refresh.
- **Brute-force lockout:** after `BULWARK_LOGIN_MAX_FAILS` (default 5) failed logins
  for one email within `BULWARK_LOGIN_WINDOW_SECS` (default 15m), that email is locked
  out until the window elapses; a successful login clears the counter.
- **Durable:** with `BULWARK_STATE_DIR` set, accounts + push targets + pending
  reviews + the approve-allowlist all persist and reload on restart (atomic JSON).
  **Not-yet-wired:** no web admin UI (the `bulwark_admin` CLI covers provisioning);
  no durable DB for multi-node scale (rusqlite won't build here).

## 4. Client ↔ cluster mTLS (heavy-media offload)
- Set **all four** on the child: `BULWARK_CLIENT_CERT`, `BULWARK_CLIENT_KEY`,
  `BULWARK_CLIENT_CA` (PEM paths) and `BULWARK_CLUSTER_DOMAIN` (SNI). `BULWARK_CLUSTER_ENDPOINT`
  must be `https://…`. Any missing ⇒ offload silently off, audio fails **open**.
- The parent app uses `BULWARK_CLUSTER_CA` to pin the cluster server cert for the
  review channel (one-way TLS, no client cert there).
- **Not-yet-wired (honest):** there is **no enrollment PKI**. Client certs are
  operator-issued out-of-band and trusted by the server's `client_ca_pem`; no
  rotation/revocation/auto-distribution yet.

## 5. NSFW model & video
- Build the child `--features onnx` and set `BULWARK_NSFW_MODEL` to an existing model
  file; else the **fail-open stub** scores 0.0 (allows). Tunables:
  `BULWARK_NSFW_MODEL_CLASS` (`vit`|`mobilenet`), `BULWARK_NSFW_NORM`, `BULWARK_NSFW_EP`
  (`auto`|`cpu`|`gpu`), `BULWARK_GPU`.
- Video: build `--features ffmpeg` + install ffmpeg (or `FFMPEG_BINARY`); else the
  NullDemuxer fails open (nothing sampled/stored). Pair `onnx`+`ffmpeg` for real
  frame scoring.
- The parent console passes the model to the filter it spawns via `BULWARK_NSFW_MODEL`
  (unset → the filter's fail-open stub). It locates the filter binaries via
  `BULWARK_PROXY_EXE`/`BULWARK_VPN_EXE`, else beside its own exe (packaged release),
  else a dev `cargo run`.
- **Remote video review:** an all-in-one server retains blocked/borderline clips and
  serves them over `Review.FetchSegment` (streamed, auth-gated in accounts mode), so a
  guardian on a **different device** than the server can pull a clip — not just a
  co-located parent reading `blob://` off local disk. CSAM is never retained, so it is
  never fetchable. (The parent-app *playback* of fetched clips is the remaining wiring.)

## 6. Email (SMTP) alerts
- On-switch **triple** (all or none, else startup error): `BULWARK_SMTP_HOST` +
  `BULWARK_ALERT_FROM` + `BULWARK_ALERT_RECIPIENTS` (CSV). Optional: `BULWARK_SMTP_PORT`
  (default 465 TLS / 587 STARTTLS), `BULWARK_SMTP_TLS` (`tls`|`starttls`|`none`;
  `none` loopback-only), `BULWARK_SMTP_USERNAME`/`BULWARK_SMTP_PASSWORD` (secrets — env/
  keystore only), `BULWARK_ALERT_SUBJECT_PREFIX` (default `[Bulwark]`).

## 7. FCM push alerts
- Build the server `--features push`. On-switch: **both** `BULWARK_FCM_PROJECT_ID`
  and `BULWARK_FCM_SERVICE_ACCOUNT` (path to a GCP service-account JSON; existence
  validated at startup). Email + push compose into one delivery (CompositeSink).
  The fan-out pushes each redacted alert to every guardian token registered via
  `Review.RegisterPushTarget`, read live at raise time.

## 8. Durable state
- `BULWARK_STATE_DIR` (now implemented for accounts, §3) is the base for persisted
  guardian state (atomic JSON, no DB). The segment store + per-install CA still
  derive their path from `LOCALAPPDATA`/`XDG_DATA_HOME`/`HOME` (parent + video keep
  these in sync). Unifying everything under `BULWARK_STATE_DIR` is a follow-up.

## 9. Child platforms
- **Android:** install the APK, then provision **Device Owner** for robust
  tamper-resistance — recipes (dev `dpm`, QR JSON, NFC, zero-touch, FRP limits) in
  **`deploy/android/device-owner-provisioning.md`**.
- **Desktop:** the linchpin is **account separation** — child = Standard non-admin
  user, guardian holds admin. Run `bulwark_proxy`/`bulwark_vpn`; install as a locked
  service: `deploy/windows/install-bulwark-service.ps1` (SCM, DACL-locked) /
  `deploy/macos/co.predatorhunters.bulwark.proxy.plist` / `deploy/linux/bulwark-proxy.service`.
  One-time CA trust (no admin): `certutil -addstore -user Root "<…\Bulwark\bulwark-root-ca.pem>"`.
- **iOS:** no app-enforced prevention — Screen Time (consumer) or MDM/Supervision;
  contributes the tamper heartbeat for detection.

## 10. Code-signing (release blockers)
- **Windows:** unsigned fresh builds trip Smart App Control (os error 4551) — sign
  `bulwark_svc.exe`/`bulwark_proxy.exe`. `wintun.dll` is already WireGuard-signed.
- **Android:** QR/zero-touch needs a release signing key; the provisioning
  signature checksum is that key's cert SHA-256. CI builds only a debug APK.

## 11. Tamper protection & detection backstop
Prevent → detect → re-enroll (`tamper-protection.md`). The cross-platform guarantee
is the **tamper heartbeat**: a stopped/removed filter ⇒ guardian `PROTECTION_DISABLED`
alert. Prevention tiers (Device Admin → always-on-VPN lockdown → Device Owner) are
Android; desktop relies on the standard-account model. Factory reset/recovery
defeats software-only prevention short of zero-touch/ABM — detection still fires.

## 12. Environment-variable reference

| Var | Reader | Purpose | Default | Required when |
|---|---|---|---|---|
| `BULWARK_ROLE` | server | role (lb\|worker\|all-in-one) | all-in-one | never (flag/default) |
| `BULWARK_BIND` | server | gRPC listen host:port | 127.0.0.1:8443 | non-loopback bind |
| `BULWARK_NODE_ID` | server (cluster) | unique node id (e.g. host IP) | node-local | multi-node |
| `BULWARK_CLUSTER_ID` | server (cluster) | shared id across the cluster | bulwark-local | multi-node |
| `BULWARK_CLUSTER_ADDRESS` | server (cluster) | this node's advertised host:port | 127.0.0.1:8443 | multi-node |
| `BULWARK_CLUSTER_SEEDS` | server (cluster) | comma-sep peer host:port to join (workers → LB) | none | multi-node |
| `BULWARK_BACKPRESSURE_DEPTH` | server (cluster) | queue depth above which Enqueue is refused | 512 | tune |
| `BULWARK_QUORUM_DSN` | server (cluster) | Postgres DSN for the lease store | unset | quorum (split-brain safety) |
| `BULWARK_ACCOUNTS` | server | enable guardian accounts | off | provisioning guardians |
| `BULWARK_SESSION_TTL_SECS` | server | guardian session-token lifetime (seconds) | 43200 (12h) | tune session expiry |
| `BULWARK_LOGIN_MAX_FAILS` | server | failed logins per email before lockout | 5 | tune brute-force throttle |
| `BULWARK_LOGIN_WINDOW_SECS` | server | login-throttle / lockout window (seconds) | 900 (15m) | tune brute-force throttle |
| `BULWARK_STATE_DIR` | server | persist guardian state — accounts/push/pending/allowlist (JSON) | unset (in-memory) | durable state |
| `BULWARK_ADMIN_ENDPOINT` | bulwark_admin | Accounts service endpoint for the CLI | `http://127.0.0.1:8443` | remote/TLS provisioning |
| `BULWARK_UI_BIND` | bulwark-ui | dashboard host:port | 127.0.0.1:8080 | non-loopback UI |
| `BULWARK_SMTP_HOST` | bulwark-alert | SMTP host (email on-switch) | unset | with FROM+RECIPIENTS |
| `BULWARK_SMTP_PORT` | bulwark-alert | SMTP port | 465/587 | never |
| `BULWARK_SMTP_TLS` | bulwark-alert | tls\|starttls\|none | tls | never |
| `BULWARK_SMTP_USERNAME`/`_PASSWORD` | bulwark-alert | SMTP auth (secret) | unset | authenticated relay |
| `BULWARK_ALERT_FROM` | bulwark-alert | From: address | unset | email on-switch |
| `BULWARK_ALERT_RECIPIENTS` | bulwark-alert | guardian recipients (CSV) | unset | email on-switch |
| `BULWARK_ALERT_SUBJECT_PREFIX` | bulwark-alert | subject prefix | [Bulwark] | never |
| `BULWARK_FCM_PROJECT_ID` | bulwark-alert (push) | FCM project (push on-switch) | unset | push (with SA) |
| `BULWARK_FCM_SERVICE_ACCOUNT` | bulwark-alert (push) | SA JSON path | unset | push (with project) |
| `BULWARK_CLIENT_CERT`/`_KEY`/`_CA` | client | mTLS material (PEM paths) | unset | cluster offload |
| `BULWARK_CLUSTER_DOMAIN` | client | mTLS SNI / server name | unset | cluster offload |
| `BULWARK_CLUSTER_ENDPOINT` | client/parent | cluster gRPC endpoint (one source of truth: console + spawned filter) | `http://127.0.0.1:8443` | remote cluster (https for mTLS) |
| `BULWARK_CLUSTER_CA` | parent | pin cluster server cert | unset | parent → TLS cluster |
| `BULWARK_GUARDIAN_TOKEN` | parent | guardian session token | empty | accounts mode |
| `BULWARK_PROXY_EXE`/`BULWARK_VPN_EXE` | parent | override the filter binary path | beside the console exe | binaries not beside the console |
| `BULWARK_REPO_ROOT` | parent | cwd for the dev `cargo run` filter fallback | cwd | dev (no bundled binary) |
| `BULWARK_NSFW_MODEL` | vision | ONNX model path | unset (stub) | real scoring (with onnx) |
| `BULWARK_NSFW_MODEL_CLASS`/`_NORM`/`BULWARK_NSFW_EP` | vision | model tunables | vit/derived/auto | non-default |
| `BULWARK_POLICY_*` | bulwark-policy | nested (`__`) threshold overrides | compiled | tuning |
| `FFMPEG_BINARY` | video (ffmpeg) | explicit ffmpeg path | PATH | ffmpeg off PATH |
| `BULWARK_LOG` / `RUST_LOG` | telemetry | tracing filter | crate default | never |

> A unified config loader (`bulwark-core::Config`, figment) exists but is **dormant**
> — no binary wires it. The flat `BULWARK_*` names above (single underscore) are the
> live contract.

## 13. Not-yet-wired / needs real infra (collected)
- No enrollment PKI; cluster mTLS certs are operator-issued (no rotation/revocation).
- All guardian state (accounts, push targets, pending reviews, approve-allowlist)
  persists via `BULWARK_STATE_DIR` as atomic JSON; a real DB is still wanted for
  multi-node scale (rusqlite won't build on the Windows host, error 4551).
- Provisioning is via the `bulwark_admin` CLI (§3); no web admin UI yet.
- Multi-node gossip/quorum/Postgres unverified on the Windows host (rusqlite 4551).
- Android release keystore + QR/zero-touch unverified in CI (debug APK only).
- Remote-parent video review: server-side `Review.FetchSegment` is implemented; the
  parent-app playback of fetched clips is the remaining wiring.
- Desktop transparent VPN data path (smoltcp/boringtun) is fail-closed; proxy mode
  is the shipping path.
- No real NSFW model artifact, FCM creds, SMTP creds, or code-signing keys ship in
  the repo — all operator-supplied.
