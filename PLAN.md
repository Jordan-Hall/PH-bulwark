# Aegis — Real-Time Child-Safety Filtering VPN (clustered client/server)

**Working name:** Aegis
**License intent:** Free / open source (permissive deps only — MIT/Apache/BSD/LGPL-with-isolation)
**Status:** Core built & merged; product surface in progress. Live London deployment, DistilBERT detector wired + parity-verified, child + manager apps (Dioxus 0.8) running on a real device. Remaining product work (get-started flow, native grants, features, model release) is tracked as workflows in **[docs/finish-plan.md](docs/finish-plan.md)**.

A cross-platform, Rust **client/server** content-filtering VPN + on-device agent that blocks
non-child-safe content **in real time** (not whole-site blocking), detects signs of grooming
in text, and emails a guardian whenever it intervenes or suspects grooming. Heavy analysis
runs on a **clusterable server backend**; devices run a thin client.

---

## 0. Read this first

### 0a. What is and isn't possible (drives everything)

| Goal | Network VPN alone? | Reality |
|---|---|---|
| Block adult **websites/pages** | ✅ | DNS + SNI + MITM HTTPS |
| Block adult **images** in pages | ✅ | MITM decrypt → small NSFW model |
| Block adult **video** (mp4, HLS/DASH) | ✅ (with delay) | Buffer → ffmpeg → classify → block/blur/mute → forward |
| Block adult **live WebRTC** calls | ⚠️ Hard | Realistic option is **block**, not analyze |
| Read ordinary web chat (non-pinned HTTPS) | ✅ | MITM → text rules + classifier |
| Read **E2E** chats (Messenger secret, WhatsApp, Signal, iMessage) | ❌ Never | Plaintext never on the wire → **on-device OCR** |
| Read **cert-pinned** apps | ❌ | App rejects MITM cert → **on-device OCR** |
| Decrypt arbitrary **Android 7+** app traffic | ⚠️ | User CAs ignored unless app opts in → **on-device OCR** |

Consequences: grooming detection = **network text + on-device OCR + platform supervision APIs**, all
feeding one detector. Live video = **buffered delay + frame sampling + block/blur/mute flagged
segments** (full re-encode only when flagged, GPU when present). QUIC/HTTP3 is **downgraded** so
traffic falls back to inspectable TCP — configurable, documented.

### 0b. AI-usage principle (per your steer: *use AI sparingly*)

Aegis is **rules-first, small-model-second, big-AI-rarely**:

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
 │ aegis-client                  │   gRPC     │  Load balancer / gateway (aegis-server LB) │
 │  • aegis-net  (TUN+MITM+CA)   │  (mTLS)    │        │                │                 │
 │  • aegis-agent (manual OCR)   │ ─────────► │  worker-1        worker-2        worker-N  │
 │  • aegis-flow (buffer/delay)  │ ◄───────── │  (aegis-server: vision/audio/video/text)   │
 │  • tiny first-pass models     │  verdicts  │        \________ aegis-cluster ________/   │
 │  • aegis-infer (route local/  │            │     membership · health · LB · work queue  │
 │     remote, offload on mobile)│            │              shared state (Postgres)       │
 └───────────────────────────────┘            └──────────────────────────────────────────┘
```

- **Client (every device):** intercepts/captures, runs *tiny* latency-critical first-pass checks
  locally, and for anything heavy (video frames, audio, full classification) calls the server
  cluster. On mobile/low-power, almost everything offloads; on a capable desktop/gateway it can run
  more locally. `aegis-infer` makes the local-vs-remote decision from detected device capability.
- **Server cluster:** stateless analysis **workers** behind a load balancer, sharing a work queue
  and state. Add nodes → add throughput. `aegis-cluster` provides node membership (SWIM-style
  gossip), health checks, load balancing, and work distribution; shared state in Postgres; bus via
  gRPC (and optionally NATS for fan-out). A single binary runs as **LB / worker / all-in-one** by
  role flag, so a home user runs one node and a deployment runs many.
- **Transport:** `tonic` gRPC over **mTLS**; `aegis-proto` holds the shared protobuf contracts so
  client and server never drift. The home gateway can BE the single-node cluster (your "ideally
  on-device, but mobile offloads" answer).

---

## 2. Workspace (Cargo) — crate map

```
aegis/crates/
  aegis-proto        # protobuf/gRPC contracts (tonic/prost) — client ⇄ server ⇄ node
  aegis-core         # shared types, config, device-capability detection, IPC
  aegis-client       # device orchestrator: wires net + agent + flow + infer
  aegis-server       # clusterable analysis backend (roles: lb | worker | all-in-one)
  aegis-cluster      # membership, health, load balancing, work queue, shared state
  aegis-net          # TUN/VpnService + MITM proxy + per-install CA
  aegis-flow         # protocol/flow classify + stream demux + buffering/delay
  aegis-vision       # small dedicated NSFW image/frame classifier (ONNX, quantized)
  aegis-audio        # small dedicated explicit-audio classifier (ONNX)
  aegis-video        # ffmpeg decode/sample/blur/mute/re-mux pipeline
  aegis-text         # rules+lexicon engine FIRST, small classifier SECOND (no hot-path LLM)
  aegis-agent        # on-device CONVENTIONAL OCR + accessibility (Win/Android/macOS)
  aegis-supervision  # Google/Microsoft/Apple/Meta family-API connectors
  aegis-policy       # thresholds, age profiles, block/blur/mute/warn/log actions
  aegis-alert        # email (SMTP/Gmail), rate-limit/digest, redacted evidence
  aegis-store        # encrypted SQLite (client) + Postgres adapter (server)
  aegis-infer        # local-vs-cluster routing; mobile offload
  aegis-ui           # local dashboard + cluster admin (axum + Tauri/web)
```

Heavy/untrusted media parsers run as **sandboxed worker processes** (they ingest hostile input).

### Key per-crate notes
- **aegis-net:** `wintun` (Win), `tun` (Linux/macOS), Android `VpnService` via JNI; MITM via
  `hudsucker` (hyper+rustls+rcgen); **per-install CA** (never shared/baked-in), key in TPM/keystore;
  QUIC downgrade; pinning detection → flag for on-device.
- **aegis-vision / aegis-audio:** runtime `ort` (CPU + CUDA/TensorRT/DirectML/CoreML/NNAPI). Small
  OSS single-purpose models, INT8-quantized for client/mobile, full precision on GPU workers.
- **aegis-video:** `ffmpeg-sidecar` (shell out → keeps GPL/LGPL out of our binary, OSS-clean license).
  Scene-aware frame sampling; live = ring buffer + delay; WebRTC = block-only.
- **aegis-text:** deterministic indicator rules + multilingual lexicon → score; small classifier for
  nuance; conversation-level state machine; consumes network text AND on-device OCR text.
- **aegis-agent:** conventional OCR only — `Windows.Media.Ocr`/Tesseract, Android Text Recognition,
  macOS Vision; accessibility tree read for messaging apps; this is the E2E answer.
- **aegis-cluster/server:** `tonic` gRPC, SWIM membership (crate TBD by Wave A — e.g. `foca`/`chitchat`),
  Postgres shared state (`sqlx`), role-based single binary, health + graceful drain + horizontal scale.
- **aegis-alert:** `lettre` SMTP + optional Gmail API; two triggers (*blocker intervened*, *grooming
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
| **0 Foundations** | Workspace, CI, `cargo-deny`/`audit`, threat model, legal/consent docs, per-install CA, policy schema, **`aegis-proto` contracts + single-node `aegis-server`/`aegis-client` skeleton over gRPC**, device-capability detection |
| **1 Web + text** | MITM proxy, DNS/SNI/page filtering, **rule+lexicon grooming engine** + small text classifier on web/non-E2E, alerting MVP |
| **2 Images** | Small NSFW image model on web images; blur/block |
| **3 Video + audio** | ffmpeg pipeline (progressive + HLS/DASH); frame sampling + audio muting |
| **4 Live + GPU + cluster scale** | Buffered-delay live filtering, GPU re-encode/blur, **multi-node `aegis-cluster` (membership/LB/work queue)**, WebRTC block |
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
