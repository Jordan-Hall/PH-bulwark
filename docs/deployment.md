# Aegis production deployment runbook

How to stand up Aegis for a real family/household. For **dev** setup see
`running.md`; this doc is the production procedure + the canonical environment-
variable reference.

> **Honest status.** The architecture and safety logic are implemented and
> CI-green, but several pieces are operator-provisioned rather than automated, and
> a few need a real environment to verify. Each section flags its **Not-yet-wired**
> gaps, collected in §13.
>
> **Trust model** (see `tamper-protection.md`, `on-device-scanning.md`): Aegis runs
> only on **managed, child-aware, consented** devices — transparent, no covert
> capture, no raw-content exfiltration. Suspected CSAM is blocked + hashed, **never**
> stored, transmitted, previewed, or auto-reported (a human/legal decision).

## 1. Architecture at a glance

```
child device                              home cluster                guardian
┌────────────────────────┐   AlertRelay   ┌───────────────┐  email +  ┌──────────────┐
│ aegis_proxy / aegis_vpn │──(redacted)──▶ │ aegis-server  │── FCM ───▶ │ parent app / │
│  MITM filter + OCR +    │   gRPC         │ relay+accounts│   push     │ UI / phone   │
│  tamper heartbeat       │◀─ offload ────▶│ +Review+Tamper│            └──────────────┘
└────────────────────────┘  (mTLS)        └───────────────┘
```
- **Child** runs `aegis_proxy` (no admin; per-user system proxy) or `aegis_vpn`
  (admin; TUN captures all TCP). Both MITM HTTPS with the per-install root CA and
  run the same pipeline; both emit a tamper heartbeat.
- **Cluster** (`aegis-server`, roles `all-in-one`/`lb`/`worker`) receives redacted
  `AlertEvent`s, scopes per child/guardian, and delivers via email + optional FCM.
- **Guardian** reviews on the desktop parent app or the `aegis-ui` dashboard.

## 2. Server roles & bring-up
- **All-in-one** (single household): `aegis-server --role all-in-one` (default),
  `AEGIS_BIND=0.0.0.0:8443` for LAN. Only this role keeps a server-side
  `SegmentStore` for co-located video replay.
- **lb + worker** (multi-node): build `--features gossip,quorum`; one `--role lb`,
  N `--role worker` seeded at the LB, all on one Postgres.
- Server build features: `classifier` (text backstop), `push` (FCM sink). Default
  build is byte-identical without `push`.
- **Not-yet-wired:** multi-node gossip/quorum/Postgres is unverified on the Windows
  dev host (`rusqlite`/`aegis-store` fails, env error 4551).

## 3. Accounts & guardian provisioning
- Enable with `AEGIS_ACCOUNTS=1`. Off ⇒ device-scoped review (empty token; dev/
  single-home).
- Model: parent = email + password (PBKDF2-HMAC-SHA256, 100k iters; never stored
  plaintext); child linked to a `device_id`; guardians assigned per child; alerts
  scoped by session token.
- **Provision with the `aegis_admin` CLI** (talks to the running server's `Accounts`
  service at `AEGIS_ADMIN_ENDPOINT`, default `http://127.0.0.1:8443`; pins
  `AEGIS_CLUSTER_CA` if set):
  ```text
  aegis_admin create-account  guardian@home.example <password> "Guardian"
  aegis_admin login           guardian@home.example <password>   # -> session token
  aegis_admin add-child       <token> "Kid" kids-tablet-01
  aegis_admin assign-guardian <token> <child_id> <other_account_id>
  aegis_admin list-children   <token>
  ```
  The `login` token is what you put in `AEGIS_GUARDIAN_TOKEN` for the parent app.
  Tokens expire after `AEGIS_SESSION_TTL_SECS` (default 12h) and are dropped on
  restart, so a leaked token is short-lived — re-`login` to refresh.
- **Brute-force lockout:** after `AEGIS_LOGIN_MAX_FAILS` (default 5) failed logins
  for one email within `AEGIS_LOGIN_WINDOW_SECS` (default 15m), that email is locked
  out until the window elapses; a successful login clears the counter.
- **Durable now:** set `AEGIS_STATE_DIR=/var/lib/aegis` and accounts/children/
  guardian assignments are persisted (JSON) and reload on restart (session tokens
  are intentionally dropped — guardians re-login). Unset ⇒ in-memory.
- **Durable:** with `AEGIS_STATE_DIR` set, accounts + push targets + pending
  reviews + the approve-allowlist all persist and reload on restart (atomic JSON).
  **Not-yet-wired:** no web admin UI (the `aegis_admin` CLI covers provisioning);
  no durable DB for multi-node scale (rusqlite won't build here).

## 4. Client ↔ cluster mTLS (heavy-media offload)
- Set **all four** on the child: `AEGIS_CLIENT_CERT`, `AEGIS_CLIENT_KEY`,
  `AEGIS_CLIENT_CA` (PEM paths) and `AEGIS_CLUSTER_DOMAIN` (SNI). `AEGIS_CLUSTER_ENDPOINT`
  must be `https://…`. Any missing ⇒ offload silently off, audio fails **open**.
- The parent app uses `AEGIS_CLUSTER_CA` to pin the cluster server cert for the
  review channel (one-way TLS, no client cert there).
- **Not-yet-wired (honest):** there is **no enrollment PKI**. Client certs are
  operator-issued out-of-band and trusted by the server's `client_ca_pem`; no
  rotation/revocation/auto-distribution yet.

## 5. NSFW model & video
- Build the child `--features onnx` and set `AEGIS_NSFW_MODEL` to an existing model
  file; else the **fail-open stub** scores 0.0 (allows). Tunables:
  `AEGIS_NSFW_MODEL_CLASS` (`vit`|`mobilenet`), `AEGIS_NSFW_NORM`, `AEGIS_NSFW_EP`
  (`auto`|`cpu`|`gpu`), `AEGIS_GPU`.
- Video: build `--features ffmpeg` + install ffmpeg (or `FFMPEG_BINARY`); else the
  NullDemuxer fails open (nothing sampled/stored). Pair `onnx`+`ffmpeg` for real
  frame scoring.
- The parent console passes the model to the filter it spawns via `AEGIS_NSFW_MODEL`
  (unset → the filter's fail-open stub). It locates the filter binaries via
  `AEGIS_PROXY_EXE`/`AEGIS_VPN_EXE`, else beside its own exe (packaged release),
  else a dev `cargo run`.

## 6. Email (SMTP) alerts
- On-switch **triple** (all or none, else startup error): `AEGIS_SMTP_HOST` +
  `AEGIS_ALERT_FROM` + `AEGIS_ALERT_RECIPIENTS` (CSV). Optional: `AEGIS_SMTP_PORT`
  (default 465 TLS / 587 STARTTLS), `AEGIS_SMTP_TLS` (`tls`|`starttls`|`none`;
  `none` loopback-only), `AEGIS_SMTP_USERNAME`/`AEGIS_SMTP_PASSWORD` (secrets — env/
  keystore only), `AEGIS_ALERT_SUBJECT_PREFIX` (default `[Aegis]`).

## 7. FCM push alerts
- Build the server `--features push`. On-switch: **both** `AEGIS_FCM_PROJECT_ID`
  and `AEGIS_FCM_SERVICE_ACCOUNT` (path to a GCP service-account JSON; existence
  validated at startup). Email + push compose into one delivery (CompositeSink).
  The fan-out pushes each redacted alert to every guardian token registered via
  `Review.RegisterPushTarget`, read live at raise time.

## 8. Durable state
- `AEGIS_STATE_DIR` (now implemented for accounts, §3) is the base for persisted
  guardian state (atomic JSON, no DB). The segment store + per-install CA still
  derive their path from `LOCALAPPDATA`/`XDG_DATA_HOME`/`HOME` (parent + video keep
  these in sync). Unifying everything under `AEGIS_STATE_DIR` is a follow-up.

## 9. Child platforms
- **Android:** install the APK, then provision **Device Owner** for robust
  tamper-resistance — recipes (dev `dpm`, QR JSON, NFC, zero-touch, FRP limits) in
  **`deploy/android/device-owner-provisioning.md`**.
- **Desktop:** the linchpin is **account separation** — child = Standard non-admin
  user, guardian holds admin. Run `aegis_proxy`/`aegis_vpn`; install as a locked
  service: `deploy/windows/install-aegis-service.ps1` (SCM, DACL-locked) /
  `deploy/macos/co.libertyware.aegis.proxy.plist` / `deploy/linux/aegis-proxy.service`.
  One-time CA trust (no admin): `certutil -addstore -user Root "<…\Aegis\aegis-root-ca.pem>"`.
- **iOS:** no app-enforced prevention — Screen Time (consumer) or MDM/Supervision;
  contributes the tamper heartbeat for detection.

## 10. Code-signing (release blockers)
- **Windows:** unsigned fresh builds trip Smart App Control (os error 4551) — sign
  `aegis_svc.exe`/`aegis_proxy.exe`. `wintun.dll` is already WireGuard-signed.
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
| `AEGIS_ROLE` | server | role (lb\|worker\|all-in-one) | all-in-one | never (flag/default) |
| `AEGIS_BIND` | server | gRPC listen host:port | 127.0.0.1:8443 | non-loopback bind |
| `AEGIS_ACCOUNTS` | server | enable guardian accounts | off | provisioning guardians |
| `AEGIS_SESSION_TTL_SECS` | server | guardian session-token lifetime (seconds) | 43200 (12h) | tune session expiry |
| `AEGIS_LOGIN_MAX_FAILS` | server | failed logins per email before lockout | 5 | tune brute-force throttle |
| `AEGIS_LOGIN_WINDOW_SECS` | server | login-throttle / lockout window (seconds) | 900 (15m) | tune brute-force throttle |
| `AEGIS_STATE_DIR` | server | persist guardian state — accounts/push/pending/allowlist (JSON) | unset (in-memory) | durable state |
| `AEGIS_ADMIN_ENDPOINT` | aegis_admin | Accounts service endpoint for the CLI | `http://127.0.0.1:8443` | remote/TLS provisioning |
| `AEGIS_UI_BIND` | aegis-ui | dashboard host:port | 127.0.0.1:8080 | non-loopback UI |
| `AEGIS_SMTP_HOST` | aegis-alert | SMTP host (email on-switch) | unset | with FROM+RECIPIENTS |
| `AEGIS_SMTP_PORT` | aegis-alert | SMTP port | 465/587 | never |
| `AEGIS_SMTP_TLS` | aegis-alert | tls\|starttls\|none | tls | never |
| `AEGIS_SMTP_USERNAME`/`_PASSWORD` | aegis-alert | SMTP auth (secret) | unset | authenticated relay |
| `AEGIS_ALERT_FROM` | aegis-alert | From: address | unset | email on-switch |
| `AEGIS_ALERT_RECIPIENTS` | aegis-alert | guardian recipients (CSV) | unset | email on-switch |
| `AEGIS_ALERT_SUBJECT_PREFIX` | aegis-alert | subject prefix | [Aegis] | never |
| `AEGIS_FCM_PROJECT_ID` | aegis-alert (push) | FCM project (push on-switch) | unset | push (with SA) |
| `AEGIS_FCM_SERVICE_ACCOUNT` | aegis-alert (push) | SA JSON path | unset | push (with project) |
| `AEGIS_CLIENT_CERT`/`_KEY`/`_CA` | client | mTLS material (PEM paths) | unset | cluster offload |
| `AEGIS_CLUSTER_DOMAIN` | client | mTLS SNI / server name | unset | cluster offload |
| `AEGIS_CLUSTER_ENDPOINT` | client/parent | cluster gRPC endpoint (one source of truth: console + spawned filter) | `http://127.0.0.1:8443` | remote cluster (https for mTLS) |
| `AEGIS_CLUSTER_CA` | parent | pin cluster server cert | unset | parent → TLS cluster |
| `AEGIS_GUARDIAN_TOKEN` | parent | guardian session token | empty | accounts mode |
| `AEGIS_PROXY_EXE`/`AEGIS_VPN_EXE` | parent | override the filter binary path | beside the console exe | binaries not beside the console |
| `AEGIS_REPO_ROOT` | parent | cwd for the dev `cargo run` filter fallback | cwd | dev (no bundled binary) |
| `AEGIS_NSFW_MODEL` | vision | ONNX model path | unset (stub) | real scoring (with onnx) |
| `AEGIS_NSFW_MODEL_CLASS`/`_NORM`/`AEGIS_NSFW_EP` | vision | model tunables | vit/derived/auto | non-default |
| `AEGIS_POLICY_*` | aegis-policy | nested (`__`) threshold overrides | compiled | tuning |
| `FFMPEG_BINARY` | video (ffmpeg) | explicit ffmpeg path | PATH | ffmpeg off PATH |
| `AEGIS_LOG` / `RUST_LOG` | telemetry | tracing filter | crate default | never |

> A unified config loader (`aegis-core::Config`, figment) exists but is **dormant**
> — no binary wires it. The flat `AEGIS_*` names above (single underscore) are the
> live contract.

## 13. Not-yet-wired / needs real infra (collected)
- No enrollment PKI; cluster mTLS certs are operator-issued (no rotation/revocation).
- All guardian state (accounts, push targets, pending reviews, approve-allowlist)
  persists via `AEGIS_STATE_DIR` as atomic JSON; a real DB is still wanted for
  multi-node scale (rusqlite won't build on the Windows host, error 4551).
- Provisioning is via the `aegis_admin` CLI (§3); no web admin UI yet.
- Multi-node gossip/quorum/Postgres unverified on the Windows host (rusqlite 4551).
- Android release keystore + QR/zero-touch unverified in CI (debug APK only).
- Distributed (remote-parent) video review unimplemented — `blob://` is local-only.
- Desktop transparent VPN data path (smoltcp/boringtun) is fail-closed; proxy mode
  is the shipping path.
- No real NSFW model artifact, FCM creds, SMTP creds, or code-signing keys ship in
  the repo — all operator-supplied.
