# Bulwark — Real-Time Child-Safety Filtering VPN (clustered client/server)

**Working name:** Bulwark
**License intent:** Free / open source (permissive deps only — MIT/Apache/BSD/LGPL-with-isolation)
**Status:** Core built & merged; product surface in progress. Live London deployment, DistilBERT detector wired + parity-verified, child + manager apps (Dioxus 0.8) running on a real device. Remaining product work (get-started flow, native grants, features, model release) is tracked as workflows in **[docs/finish-plan.md](docs/finish-plan.md)**.

A cross-platform, Rust **client/server** content-filtering VPN + on-device agent that blocks
non-child-safe content **in real time** (not whole-site blocking), detects signs of grooming
in text, and emails a guardian whenever it intervenes or suspects grooming. Heavy analysis
runs on a **clusterable server backend**; devices run a thin client.

---

## 0. Read this first

> **Framing (read first):** PH Bulwark is a consensual **parental-control,
> child-safety content-filtering VPN** — guardian-installed, on a device the
> guardian owns, for a minor they are the legal guardian of, openly visible and
> switch-off-able. It is **not** offensive security, surveillance, or anything
> biological. The networking technique is standard **on-device TLS inspection**
> (the same approach parental-control / enterprise-DLP products use), applied only
> on the guardian's own device. See **[docs/FRAMING.md](docs/FRAMING.md)** for the
> protective glossary (e.g. "inspection" not "interception") used throughout.

### 0a. What is and isn't possible (drives everything)

| Goal | Network VPN alone? | Reality |
|---|---|---|
| Block adult **websites/pages** | ✅ | guardian host blocklist (CONNECT/Host refused with a block page; pump RSTs listed IPs pre-CONNECT) + TLS-inspected HTML gated on the local text verdict (BLOCK → inline block page; fail-open after 2 s with no verdict). No DNS-level blocking yet |
| Block adult **images** in pages | ✅ | on-device TLS inspect → small NSFW model |
| Block adult **video** (mp4, HLS/DASH) | ✅ (with delay) | Buffer → ffmpeg → classify → block/blur/mute → forward |
| Block adult **live WebRTC** calls | ⚠️ Hard | Realistic option is **block**, not analyze |
| Read ordinary web chat (non-pinned HTTPS) | ✅ | on-device TLS inspect → text rules + classifier |
| Read **E2E** chats (Messenger secret, WhatsApp, Signal, iMessage) | ❌ Never | Plaintext never on the wire → **on-device OCR** |
| Read **cert-pinned** apps | ❌ | App rejects TLS inspection cert → **on-device OCR** |
| Decrypt arbitrary **Android 7+** app traffic | ⚠️ | User CAs ignored unless app opts in → **on-device OCR** |

Consequences: grooming detection = **network text + on-device OCR + platform supervision APIs**, all
feeding one detector. Live video = **buffered delay + frame sampling + block/blur/mute flagged
segments** (full re-encode only when flagged, GPU when present). QUIC/HTTP3 is **downgraded** so
traffic falls back to inspectable TCP — configurable, documented.

### 0b. AI-usage principle (per your steer: *use AI sparingly*)

Bulwark is **rules-first, small-model-second, big-AI-rarely**:

- **Conventional OCR, not AI vision-LLMs** — Tesseract / OS-native engines (`Windows.Media.Ocr`,
  Android Text Recognition, macOS Vision). Deterministic, fast, offline, cheap.
- **Small dedicated task models only** for vision/audio NSFW — quantized single-purpose classifiers
  (a few MB–tens of MB), not general multimodal models.
- **Grooming = deterministic rules + lexicon FIRST**, small text classifier SECOND. The rule engine
  (secrecy asks, "let's move to another app", personal-info/age probing, sexualization, gifts,
  boundary-testing) is explainable, auditable, multilingual-extensible, and needs no GPU. A small
  fine-tuned classifier (DistilBERT/MiniLM class) backs it up for nuance.
- **Large LLM = optional, opt-in, off by default**, never in the hot path — only as a manual
  "explain this flagged thread" escalation in the review UI. Keeps the system cheap, private,
  and predictable.

### 0c. Legal / ethical guardrails (built in)

- Deploy only on devices the guardian **owns/controls**, for **minors** they are legal guardian of.
- Commercial path: consent + disclosure flows, GDPR/COPPA/age-appropriate-design handling.
- **Never persist explicit imagery.** Metadata, hashes, redacted snippets only. Suspected **CSAM** →
  documented legal-reporting path (NCMEC / local authority); the system flags, never archives illegal content.
- Wiretap/two-party-consent laws vary — surfaced in setup docs.

---

## 1. Topology — thin client, clustered server

```
        Devices (thin clients)                       Server cluster (scales horizontally)
 ┌───────────────────────────────┐            ┌──────────────────────────────────────────┐
 │ bulwark-client                  │   gRPC     │  Load balancer / gateway (bulwark-server LB) │
 │  • bulwark-net  (TUN+TLS inspection+CA)   │  (mTLS)    │        │                │                 │
 │  • bulwark-agent (manual OCR)   │ ─────────► │  worker-1        worker-2        worker-N  │
 │  • bulwark-flow (buffer/delay)  │ ◄───────── │  (bulwark-server: vision/audio/video/text)   │
 │  • tiny first-pass models     │  verdicts  │        \________ bulwark-cluster ________/   │
 │  • bulwark-infer (route local/  │            │     membership · health · LB · work queue  │
 │     remote, offload on mobile)│            │              shared state (Postgres)       │
 └───────────────────────────────┘            └──────────────────────────────────────────┘
```

- **Client (every device):** intercepts/captures, runs *tiny* latency-critical first-pass checks
  locally, and for anything heavy (video frames, audio, full classification) calls the server
  cluster. On mobile/low-power, almost everything offloads; on a capable desktop/gateway it can run
  more locally. `bulwark-infer` makes the local-vs-remote decision from detected device capability.
- **Server cluster:** stateless analysis **workers** behind a load balancer, sharing a work queue
  and state. Add nodes → add throughput. `bulwark-cluster` provides node membership (SWIM-style
  gossip), health checks, load balancing, and work distribution; shared state in Postgres; bus via
  gRPC (and optionally NATS for fan-out). A single binary runs as **LB / worker / all-in-one** by
  role flag, so a home user runs one node and a deployment runs many.
- **Transport:** `tonic` gRPC over **mTLS**; `bulwark-proto` holds the shared protobuf contracts so
  client and server never drift. The home gateway can BE the single-node cluster (your "ideally
  on-device, but mobile offloads" answer).

---

## 2. Workspace (Cargo) — crate map

```
bulwark/crates/
  bulwark-proto        # protobuf/gRPC contracts (tonic/prost) — client ⇄ server ⇄ node
  bulwark-core         # shared types, config, device-capability detection, IPC
  bulwark-client       # device orchestrator: wires net + agent + flow + infer
  bulwark-server       # clusterable analysis backend (roles: lb | worker | all-in-one)
  bulwark-cluster      # membership, health, load balancing, work queue, shared state
  bulwark-net          # TUN/VpnService + TLS-inspecting proxy + per-install CA
  bulwark-flow         # protocol/flow classify + stream demux + buffering/delay
  bulwark-vision       # small dedicated NSFW image/frame classifier (ONNX, quantized)
  bulwark-audio        # small dedicated explicit-audio classifier (ONNX)
  bulwark-video        # ffmpeg decode/sample/blur/mute/re-mux pipeline
  bulwark-text         # rules+lexicon engine FIRST, small classifier SECOND (no hot-path LLM)
  bulwark-agent        # on-device CONVENTIONAL OCR + accessibility (Win/Android/macOS)
  bulwark-supervision  # Google/Microsoft/Apple/Meta family-API connectors
  bulwark-policy       # thresholds, age profiles, block/blur/mute/warn/log actions
  bulwark-alert        # email (SMTP/Gmail), rate-limit/digest, redacted evidence
  bulwark-store        # encrypted SQLite (client) + Postgres adapter (server)
  bulwark-infer        # local-vs-cluster routing; mobile offload
  bulwark-ui           # local dashboard + cluster admin (axum + Tauri/web)
```

Heavy/untrusted media parsers run as **sandboxed worker processes** (they ingest hostile input).

### Key per-crate notes
- **bulwark-net:** `wintun` (Win), `tun` (Linux/macOS), Android `VpnService` via JNI; TLS inspection via
  `hudsucker` (hyper+rustls+rcgen); **per-install CA** (never shared/baked-in), key in TPM/keystore;
  QUIC downgrade; pinning detection → flag for on-device.
- **bulwark-vision / bulwark-audio:** runtime `ort` (CPU + CUDA/TensorRT/DirectML/CoreML/NNAPI). Small
  OSS single-purpose models, INT8-quantized for client/mobile, full precision on GPU workers.
- **bulwark-video:** `ffmpeg-sidecar` (shell out → keeps GPL/LGPL out of our binary, OSS-clean license).
  Scene-aware frame sampling; live = ring buffer + delay; WebRTC = block-only.
- **bulwark-text:** deterministic indicator rules + multilingual lexicon → score; small classifier for
  nuance; conversation-level state machine; consumes network text AND on-device OCR text.
- **bulwark-agent:** conventional OCR only — `Windows.Media.Ocr`/Tesseract, Android Text Recognition,
  macOS Vision; accessibility tree read for messaging apps; this is the E2E answer.
- **bulwark-cluster/server:** `tonic` gRPC, SWIM membership (crate TBD by Wave A — e.g. `foca`/`chitchat`),
  Postgres shared state (`sqlx`), role-based single binary, health + graceful drain + horizontal scale.
- **bulwark-alert:** `lettre` SMTP + optional Gmail API; two triggers (*blocker intervened*, *grooming
  suspected*); redacted context, **no explicit media**; rate-limit + digest.

---

## 3. Cross-cutting security

`#![forbid(unsafe_code)]` except audited FFI · **per-install CA** key in TPM/keystore (crown jewel) ·
sandboxed media-parser processes (AppContainer/seccomp) · **mTLS** between all cluster + client nodes ·
`cargo-deny` (license+advisory gate) + `cargo-audit` + pinned deps + model-checksum pinning ·
local-only by default, offload only to the user's own cluster, **no telemetry** · fail-safe defaults.

---

## 4. Phased roadmap

| Phase | Deliverable |
|---|---|
| **0 Foundations** | Workspace, CI, `cargo-deny`/`audit`, threat model, legal/consent docs, per-install CA, policy schema, **`bulwark-proto` contracts + single-node `bulwark-server`/`bulwark-client` skeleton over gRPC**, device-capability detection |
| **1 Web + text** | TLS-inspecting proxy, DNS/SNI/page filtering, **rule+lexicon grooming engine** + small text classifier on web/non-E2E, alerting MVP |
| **2 Images** | Small NSFW image model on web images; blur/block |
| **3 Video + audio** | ffmpeg pipeline (progressive + HLS/DASH); frame sampling + audio muting |
| **4 Live + GPU + cluster scale** | Buffered-delay live filtering, GPU re-encode/blur, **multi-node `bulwark-cluster` (membership/LB/work queue)**, WebRTC block |
| **5 On-device agent** | Windows then Android **conventional OCR**/accessibility → grooming engine on E2E social |
| **6 Supervision APIs** | Family-platform connectors |
| **7 Ship** | Gateway image, Windows MSI, Android app, cluster deploy manifests; hardening; UX; threshold tuning |

---

## 5. Top risks (tracked)

False positives → borderline = log+alert + human review (rules are explainable) · **CSAM** exposure →
in-memory only, redact, report-never-archive · live-video latency → delay budget + sampling + GPU +
offload · coverage gaps (E2E/pinning/QUIC/WebRTC) → honest per-app coverage dashboard · **CA key
compromise** → per-install TPM key, rotation · cluster split-brain → quorum/Postgres source-of-truth ·
grooming model bias/language → multilingual eval set + rule transparency.

---

## 6. Next-phase product workflows

The engine (§2) is built; the next phases turn it into the **product** the family
uses: a maintainable Dioxus app suite, a parent who remotely governs the child's
filtering VPN, the fastest+secure real-time AI filtering with rich attribution, and
a longer-term reach into SMS/calls. Each workflow has a dedicated design doc and is
shippable in reviewable increments. Status as of **2026-06-10**.

### Just shipped (foundation for these workflows)
- **Cluster on a real domain + public TLS, public-trust clients, Android CA install
  (2026-06-12)** — the cluster is live at `https://api.predatorhunters.co.uk:8443`
  (+ `vpn.` SAN) behind an auto-issued **Let's Encrypt** cert (acme.sh DNS-01 via
  Cloudflare on the box; self-signed cluster CA as the fallback). Clients moved to
  **public-trust-by-default, pin-optional** (parent console `tls-webpki-roots`;
  child/relay JNI trust public roots when no CA is pinned), so a CA-less pairing
  payload pairs cleanly while private-CA pinning stays for self-hosted. And the
  per-install **TLS-inspection CA now installs into the device trust store** —
  `bulwark-net::vpn::inspection_ca_pem` exports the public root over JNI
  (`inspectionCaPem`) and `CaTrust` installs it via `DevicePolicyManager.installCaCert`
  when Device Owner (fixes "connection not private"; non-managed devices fall back to
  the OCR path). → [`docs/design/server-vpn-mode-and-ca-trust.md`](docs/design/server-vpn-mode-and-ca-trust.md).
- **Transparent VPN pump, wired end-to-end** — `bulwark-net::vpn::run_netstack`
  (fd-driven smoltcp pump: per-flow TCP terminate → TLS inspection `CONNECT` → splice; DNS
  forward; QUIC drop) is now driven by `vpn::run_android_data_path`, which starts
  the in-process TLS-inspecting proxy + the pump over the VpnService fd. The Android
  `startVpn`/`stopVpn` JNI run/cancel it on a tokio runtime. Host-tested + the full
  bridge cross-compiles for Android. Remaining: on-device validation (CA-trust
  limits on Android 7+ are covered by the OCR path). See
  [`docs/design/vpn-data-path-plan.md`](docs/design/vpn-data-path-plan.md).
- **Parent-controlled VPN (Workflow B)** — server `ChildControl`
  (`SetChildConfig`/`Get`/`Stream`/`GetChildStatus` in `bulwark-server`:
  guardian-scoped, monotonic version, watch-stream, JSON persist; 6 unit + 1 e2e
  green), the parent UI (per-child VPN-control row → `SetChildConfig`, then
  polls `GetChildStatus` until "Applied on the child's device ✓"), **and the
  child apply-loop (2026-06-10)**: a `fetchChildConfig` JNI (one-shot
  `GetChildConfig`; its `have_version` doubles as the applied-version ack the
  server records) + Kotlin `ChildConfigSync` reconciler — `filtering_enabled`
  starts/stops the VPN service, strictly-older configs rejected (replay
  defense), applied version + strictness band persisted, and the fetched
  `profile` live-updates the on-device `AgeProfile` used by `analyzeText`;
  polled every 60s + on app foreground. **Pairing delivers trust + devices
  authenticate (2026-06-11, PR #104):** the console's "Setup code" panel
  copies/QRs the pairing payload v2 carrying the pinned cluster CA (the child
  pins `cluster_ca.pem` BEFORE its first TLS call — the on-device pairing
  blocker is closed), redeem mints a once-shown `device_token` (sha256 digest
  at rest) verified on `Tamper.Heartbeat` + `Get/StreamChildConfig`, and
  redemption shares the sign-in rate limit. Remaining: stream push,
  `server_endpoint` reconcile, child QR-scanner + NFC (paste path works
  today), device-removal/re-pair flow (tightens the legacy-token grace).
- **Dioxus app suite on `dioxus-router`, BOTH apps (Workflow A)** — child: six
  modules (typed `Route`, `Outlet`, `JourneyLayout`). Parent (2026-06-10):
  2974-line main.rs → eleven modules (`router`/`theme`/`state`/`servers`/`api`/
  `config`/`process`/`media`/`components`/`screens`/`tests`) **with full router
  adoption**: typed `Route` + `ConsoleLayout` + six routed screens + a shared
  `Console` context (form state survives tab switches); 12/12 tests green incl.
  the loopback FakeReview e2e.
- **Real-time path engine items (Workflow C, 2026-06-10)** — pinning detection
  is LIVE (`should_intercept` 3-strike heuristic → pinned → OCR route /
  fail-open passthrough; strikes decay on successful decrypt);
  `bulwark-infer::OnnxAnalyzer` really `session.run()`s (shared bulwark-vision
  pre/postprocess, hash-only evidence, inconclusive→offload on anything it
  can't judge); and the guardian dashboard's `/api/coverage` derives live rows
  from the pinning registry (`bulwark_proxy` embeds it on 127.0.0.1:8081).
- **Midscene UI-test harness** — `tools/ui-tests/` drives the apps' web target
  cross-platform (no device); optional Android path.
- **Native Android onboarding** — guided one-permission-at-a-time setup journey +
  proper VpnService-consent flow (the model the Dioxus child mirrors).

### Workflow A — Dioxus console + child design preview (code-split + router)
**`apps/parent` (the guardian console) is the shipped Dioxus app.** `apps/child` is a
Dioxus **design preview** of the child onboarding journey (desktop/web), NOT the shipped
child — the child ships **native** (`platform/android`: VpnService/Accessibility/DeviceAdmin
+ Rust JNI core), because those OS services can't be a webview.
Split each single-file app into a maintainable module tree (lib+bin, `screens/`,
`components/`, `state/`, `api/`, `theme`), share a theme-parameterised
`bulwark-ui-kit`, and adopt **`dioxus-router`** (typed `Route` enum, `Outlet`,
`Link`) + `dioxus-stores` for all navigation/state — no hand-rolled enum-dispatch.
Incremental, `cargo check`-verifiable at every step. → **[`docs/design/dioxus-app-architecture.md`](docs/design/dioxus-app-architecture.md)**

### Workflow B — Parent-controlled VPN + easier pairing (QR · NFC · code)
The child device runs like a normal always-on VPN app, but **the parent owns the
switch**: from the parent app the guardian picks the region/server, toggles
filtering on/off, and sets strictness — pushed to the child via a new content-free
`ChildControl` gRPC contract (config_version-monotonic, guardian-scoped). First-run
is QR-scan / NFC-tap / short-code, so a child is paired + protected in seconds.
Honest enforcement tiers (advisory-but-detected → Device-Owner always-on lockdown).
→ **[`docs/design/parent-controlled-vpn.md`](docs/design/parent-controlled-vpn.md)**,
**[`docs/design/app-pairing-and-regions.md`](docs/design/app-pairing-and-regions.md)**

### Workflow C — Real-time AI filtering + rich attribution (fastest + secure)
Make the real-time path production-grade: tiered latency budget (text rules always
local sub-ms; small NSFW image gated fail-closed; audio/video offload-preferred),
runtime accelerator detection (NNAPI/ML Kit/CoreML/DirectML → bundled CPU floor, so
ALL phones are covered), and one policy merging NSFW image + grooming text + OCR.
Plus **rich OCR attribution** — every on-device capture says *which app* and *who
said it* (child vs other party, thread, timestamp) while staying content-free and
never storing raw messages/CSAM. → **[`docs/design/realtime-filtering-and-attribution.md`](docs/design/realtime-filtering-and-attribution.md)**

### Workflow D — SMS & call safety (long-term)
Extend the same detector to the channels an abuser falls back to: Bulwark as the
default **SMS app** (Android — feasible) routing message bodies through the grooming
engine, and **call screening** (default dialer) for caller identity; call-**audio**
transcription is managed-device/R&D only (modern OSes block it) and gated by
per-region consent. Honest about iOS limits. → **[`docs/design/sms-call-monitoring.md`](docs/design/sms-call-monitoring.md)**

These slot onto the §4 roadmap as the product-surface phases (post-Phase-5 on-device
agent), and the per-step execution tasks are tracked in
[`docs/finish-plan.md`](docs/finish-plan.md).
