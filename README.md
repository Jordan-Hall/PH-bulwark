# Predator Hunters Bulwark

> **Names.** The product is **Predator Hunters Bulwark** (short: **PH Bulwark**) —
> the on-device child-safety shield. The guardian/parent console is **Predator
> Hunters HQ** (**PH HQ**). `aegis` / `aegis-*` is the internal engineering
> codename used throughout the crates, binaries (`aegis_proxy`/`aegis_vpn`/
> `aegis_svc`), `AEGIS_*` env vars, and the `co.libertyware.aegis` package — that
> stays as-is (a codename ≠ the marketing name).

Free / open-source, Rust **client/server** child-safety system. It blocks
non-child-safe content **in real time** (not whole-site blocking), detects signs of
grooming in text, retains blocked clips for guardian review, raises tamper alerts if
protection is disabled, and notifies a guardian (email + push) whenever it intervenes
or suspects grooming. Thin device clients; a horizontally-scalable analysis backend.

> **Status (2026-06):** all 14 crates are **implemented** (~16.5k lines) against the
> `aegis-proto` contract, but the tree has **not been compile-verified yet** (it was
> developed in an environment without network access to crates.io). The remaining work
> is a first `cargo build`/`test` + integration pass — see
> [`docs/integration-todo.md`](docs/integration-todo.md). **Not yet runnable.**

---

## What it does (and the honest limits)

| Goal | How | Reachable by the network VPN? |
|---|---|---|
| Block adult **web pages/images** | MITM HTTPS via a per-install CA → small NSFW model / text rules | ✅ |
| Block adult **video** (mp4 / HLS / DASH) | broadcast-delay buffer → ffmpeg sample → classify → blur/mute/block | ✅ (with delay) |
| Block adult **live streams** | bounded delay + frame/audio sampling | ✅ (WebRTC = block-only) |
| Detect **grooming** in chat | deterministic 8-category rule+lexicon engine (+ optional small classifier) | ✅ on readable text |
| Read **E2E-encrypted** chats (WhatsApp/Signal/Messenger secret/iMessage) | **on-device conventional OCR** (`aegis-agent`) — the network *cannot* read these | ❌ network · ✅ on-device |
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
| `aegis-proto` | gRPC/protobuf contract (Analysis / Offload / AlertRelay / ClusterControl) |
| `aegis-core` | shared config, error type, device detection, **canonical flow types** |
| `aegis-client` | device orchestrator: intercept → classify → analyze → policy → act/alert/store |
| `aegis-server` | role-based backend (`lb` \| `worker` \| `all-in-one`); dispatches analyzers |
| `aegis-cluster` | SWIM membership, work queue, health, graceful drain |
| `aegis-net` | **(security-critical)** Wintun TUN + MITM proxy + per-install CA (DPAPI) |
| `aegis-flow` | flow classification + HLS/DASH live-vs-VOD + broadcast-delay buffer |
| `aegis-vision` | small NSFW image/frame classifier (ONNX, `onnx` feature) |
| `aegis-audio` | small explicit-audio classifier (ONNX, `onnx` feature) |
| `aegis-video` | ffmpeg-sidecar decode → sample → vision+audio → blur/mute/block |
| `aegis-text` | **deterministic grooming rule+lexicon engine** + optional small classifier |
| `aegis-agent` | on-device conventional OCR / accessibility (the E2E-chat path) |
| `aegis-supervision` | coarse family-platform API connectors (opt-in, limited) |
| `aegis-policy` | Verdict → Action + alert decision; score bands; CSAM-critical |
| `aegis-alert` | guardian email (SMTP); INTERVENTION + GROOMING_SUSPECTED; redacted |
| `aegis-store` | encrypted SQLite (client) / Postgres (server); hash-chain audit |
| `aegis-infer` | local-vs-cluster offload routing (mobile offloads heavy media) |
| `aegis-ui` | local dashboard + honest coverage matrix (axum) |

End-to-end loop: `aegis-net` captures → `aegis-flow` classifies → `aegis-infer` routes
(text local, heavy media to the cluster) → analyzer returns a `Verdict` → `aegis-policy`
picks an `Action` → `aegis-net` applies it (forward/blur/mute/drop) → `aegis-alert` emails
the guardian → `aegis-store` records redacted audit.

## Repository layout
```
PLAN.md                     architecture, coverage limits, roadmap, risks
deny.toml                   cargo-deny license/advisory/source gate
Cargo.toml                  workspace + pinned dependencies
crates/aegis-*              the 18 crates above
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
cargo run -p aegis-server --  --role all-in-one      # backend
cargo run -p aegis-client                            # interception loop (needs admin for the CA/TUN)
cargo run -p aegis-ui                                # dashboard on http://127.0.0.1:8080
```
Optional features: `aegis-text/classifier`, `aegis-vision|aegis-audio/onnx`,
`aegis-video/ffmpeg`, `aegis-ui/llm-explain` (all off by default).

## Status & roadmap
- **Done:** research (Wave A) · contract + security/design docs (Wave B) · all 14 crate
  implementations (Wave C) · started integration (shared-type hoist, cargo-deny).
- **Next (Wave D):** first green build + `Analyzer`-trait unification + tonic codegen
  reconciliation + `/security-review` + model/ffmpeg provisioning. See
  [`docs/integration-todo.md`](docs/integration-todo.md).

## Legal & ethical
For **guardians monitoring their own minor children on devices they own/control.** On-device
OCR of E2E chats can implicate wiretap / two-party-consent law — read
[`docs/security/legal-consent.md`](docs/security/legal-consent.md) and get a per-jurisdiction
legal review before deploying. Suspected CSAM is **flagged and reported, never archived**
([`docs/security/data-handling.md`](docs/security/data-handling.md)).

## License
`Apache-2.0 OR MIT`. ffmpeg is invoked as a separate process (sidecar), never linked, to
keep this license clean.
