# Predator Hunters Bulwark

> **Names.** The product is **Predator Hunters Bulwark**. The **child's app is
> simply "PH Bulwark"** (the on-device shield); the **guardian/parent console is
> "PH Bulwark Manager"**. `bulwark` / `bulwark-*` is the internal engineering
> codename used throughout the crates, binaries (`bulwark_proxy`/`bulwark_vpn`/
> `bulwark_svc`), `BULWARK_*` env vars, and the `co.predatorhunters.bulwark` package — that
> stays as-is (a codename ≠ the marketing name).

Free / open-source, Rust **client/server** child-safety system. It blocks
non-child-safe content **in real time** (not whole-site blocking), detects signs of
grooming in text, retains blocked clips for guardian review, raises tamper alerts if
protection is disabled, and notifies a guardian (email + push) whenever it intervenes
or suspects grooming. Thin device clients; a horizontally-scalable analysis backend.

> **Status (2026-06):** all crates **implemented + compile-verified in CI**
> (`.github/workflows/ci.yml`: clippy + build + test + feature builds + windows-gated
> + cargo-deny, all required-green on `master`). The **server is deployed live** on a
> single EC2 in London (`deploy/aws/`), with CI redeploy via AWS SSM. SQLite-backed
> crates build on CI/Linux (a local Windows SAC quirk blocks only the local
> build-script binary). **Remaining:** the cross-platform transparent-VPN data path
> on Linux/macOS/Android (`docs/design/vpn-data-path-plan.md`) — Windows VPN + proxy
> mode work today; plus model/ffmpeg provisioning + a `/security-review`.

---

## What it does (and the honest limits)

| Goal | How | Reachable by the network VPN? |
|---|---|---|
| Block adult **web pages/images** | MITM HTTPS via a per-install CA → small NSFW model / text rules | ✅ |
| Block adult **video** (mp4 / HLS / DASH) | broadcast-delay buffer → ffmpeg sample → classify → blur/mute/block | ✅ (with delay) |
| Block adult **live streams** | bounded delay + frame/audio sampling | ✅ (WebRTC = block-only) |
| Detect **grooming** in chat | deterministic 8-category rule+lexicon engine (+ optional small classifier) | ✅ on readable text |
| Read **E2E-encrypted** chats (WhatsApp/Signal/Messenger secret/iMessage) | **on-device conventional OCR** (`bulwark-agent`) — the network *cannot* read these | ❌ network · ✅ on-device |
| **Email alerts** | on every block and every suspected-grooming event, redacted | ✅ |

The hard truth, by design: a VPN **cannot** decrypt end-to-end-encrypted or
certificate-pinned apps. Those are handled on-device (OCR of what the app already
rendered). See [`PLAN.md`](PLAN.md) §0a for the full coverage matrix.

**Design principles:** rules-first & small *dedicated* models (minimal AI — **no LLM in
any hot path**), **conventional OCR** (Tesseract / OS-native, never a vision-LLM),
**per-install CA** (never shared/baked-in), **mTLS** between all nodes, and **never
persist explicit media** (evidence is hashes / safe thumbnails / redacted snippets only).

---

## Architecture (18-crate Cargo workspace)

Thin **client** on each device ↔ a clusterable **server** backend (gRPC over mTLS):

| Crate | Role |
|---|---|
| `bulwark-proto` | gRPC/protobuf contract (Analysis / Offload / AlertRelay / ClusterControl) |
| `bulwark-core` | shared config, error type, device detection, **canonical flow types** |
| `bulwark-client` | device orchestrator: intercept → classify → analyze → policy → act/alert/store |
| `bulwark-server` | role-based backend (`lb` \| `worker` \| `all-in-one`); dispatches analyzers |
| `bulwark-cluster` | SWIM membership, work queue, health, graceful drain |
| `bulwark-net` | **(security-critical)** Wintun TUN + MITM proxy + per-install CA (DPAPI) |
| `bulwark-flow` | flow classification + HLS/DASH live-vs-VOD + broadcast-delay buffer |
| `bulwark-vision` | small NSFW image/frame classifier (ONNX, `onnx` feature) |
| `bulwark-audio` | small explicit-audio classifier (ONNX, `onnx` feature) |
| `bulwark-video` | ffmpeg-sidecar decode → sample → vision+audio → blur/mute/block |
| `bulwark-text` | **deterministic grooming rule+lexicon engine** + optional small classifier |
| `bulwark-agent` | on-device conventional OCR / accessibility (the E2E-chat path) |
| `bulwark-supervision` | coarse family-platform API connectors (opt-in, limited) |
| `bulwark-policy` | Verdict → Action + alert decision; score bands; CSAM-critical |
| `bulwark-alert` | guardian email (SMTP); INTERVENTION + GROOMING_SUSPECTED; redacted |
| `bulwark-store` | encrypted SQLite (client) / Postgres (server); hash-chain audit |
| `bulwark-infer` | local-vs-cluster offload routing (mobile offloads heavy media) |
| `bulwark-ui` | local dashboard + honest coverage matrix (axum) |

End-to-end loop: `bulwark-net` captures → `bulwark-flow` classifies → `bulwark-infer` routes
(text local, heavy media to the cluster) → analyzer returns a `Verdict` → `bulwark-policy`
picks an `Action` → `bulwark-net` applies it (forward/blur/mute/drop) → `bulwark-alert` emails
the guardian → `bulwark-store` records redacted audit.

## Repository layout
```
PLAN.md                     architecture, coverage limits, roadmap, risks
deny.toml                   cargo-deny license/advisory/source gate
Cargo.toml                  workspace + pinned dependencies
crates/bulwark-*              the 18 crates above
docs/design/                architecture.md, interfaces.md (trait contracts)
docs/security/              threat-model.md, data-handling.md, legal-consent.md
docs/research/              crate / model / platform feasibility research (Wave A)
docs/integration-todo.md    Wave D punch list (the remaining work)
docs/running.md             build + run + setup guide
```

## Build & run
See **[`docs/running.md`](docs/running.md)** for the full sequence. In short, on a machine
with Rust stable + network:
```bash
cargo build --workspace          # (expect integration fixups first — see integration-todo)
cargo deny check                 # license + advisory gate
cargo test  --workspace
# single-node:
cargo run -p bulwark-server --  --role all-in-one      # backend
cargo run -p bulwark-client                            # interception loop (needs admin for the CA/TUN)
cargo run -p bulwark-ui                                # dashboard on http://127.0.0.1:8080
```
Optional features: `bulwark-text/classifier`, `bulwark-vision|bulwark-audio/onnx`,
`bulwark-video/ffmpeg`, `bulwark-ui/llm-explain` (all off by default).

## Status & roadmap
- **Done:** research (Wave A) · contract + security/design docs (Wave B) · all crate
  implementations (Wave C) · integration — shared-type hoist, `Analyzer` unification,
  tonic 0.14 codegen, cargo-deny (Wave D) · **green CI build** · **live AWS deployment
  + SSM continuous deploy** · Android APK + desktop/server release builds.
- **Next:** the cross-platform transparent-VPN data path on Linux/macOS/Android
  ([`docs/design/vpn-data-path-plan.md`](docs/design/vpn-data-path-plan.md)) ·
  model/ffmpeg provisioning · `/security-review` · app-store submission (Play wired;
  MS Store/iOS pending).

## Legal & ethical
For **guardians monitoring their own minor children on devices they own/control.** On-device
OCR of E2E chats can implicate wiretap / two-party-consent law — read
[`docs/security/legal-consent.md`](docs/security/legal-consent.md) and get a per-jurisdiction
legal review before deploying. Suspected CSAM is **flagged and reported, never archived**
([`docs/security/data-handling.md`](docs/security/data-handling.md)).

## License
`Apache-2.0 OR MIT`. ffmpeg is invoked as a separate process (sidecar), never linked, to
keep this license clean.
