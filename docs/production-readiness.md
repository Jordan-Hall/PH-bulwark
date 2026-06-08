# PH Bulwark — Production-Readiness Audit (authoritative gap map)

Source-read audit (not grep) of every in-scope crate, 2026-06-08. Drives the
"no stubs, no simplification, full production" work. Pairs with [PLAN.md](../PLAN.md)
(phased roadmap) and supersedes the optimistic "all crates implemented" note in
[integration-todo.md](integration-todo.md) — that is true for *compilation*, false
for *functional completeness* of the perception/on-device/supervision/VPN layers.

## TL;DR
- **Production-grade today:** `bulwark-text` (rules+lexicon + bundled sklearn ONNX), `bulwark-policy`, `bulwark-store`, `bulwark-alert` (SMTP+FCM), `bulwark-core`, `bulwark-proto`, `bulwark-flow`. The **explicit-proxy** path (`bulwark_proxy`) on Windows works end-to-end.
- **Not production:** the **transparent VPN** data path (dead on all platforms), and **all media perception** (image/audio/video) + **on-device OCR** + **family-supervision** are stubs / fail-open / feature-gated-off.
- **⚠️ Safety-critical:** media analyzers **fail OPEN** (no model/feature → score 0.0 → SAFE/Allow), and the shipping `bulwark-client`/`bulwark-server` **don't enable `onnx`/`ffmpeg`/`classifier`** by default. **A default production build silently does no image/audio/video NSFW detection.** This must become ship-with-model + fail-CLOSED before any real deployment.

Legend: 🔴 P0 (core non-functional/stubbed) · 🟠 P1 (works but simplified/incomplete) · 🟡 P2 (polish) · 🧪 needs real-device/model/credential validation (can't be CI-verified)

---

## 🔴 P0 — core function stubbed / non-functional

| Area | Location | Gap | Production needs |
|---|---|---|---|
| **Transparent VPN pump** 🧪 | `bulwark-net/src/vpn/netstack.rs:54` | `run_netstack` hard-returns `unsupported`; the smoltcp TCP socket pump doesn't exist (parser/`decide()` are real). | Rebuild the smoltcp `Device` over `TunDevice`; per SYN open a socket, dial `127.0.0.1:8080`, `CONNECT host:port`, splice both ways w/ half-close; NAT UDP; drop QUIC/443; cancel-token loop. (The removed GPL `tun2proxy` netstack.) **Validate on real Linux/macOS/Android.** |
| **VPN binary fatal-exits** | `bulwark-client/src/bin/bulwark_vpn.rs:136` | `run_vpn`→`run_netstack` errors → `select!` exits(1) at startup. | Falls out once the pump lands; until then `bulwark_vpn` is unusable (only `bulwark_proxy` works). |
| **Windows TUN no addressing** 🧪 | `bulwark-net/src/tun/windows.rs:55` | `up()` creates the adapter but assigns no IP/netmask/MTU/route → can't capture system traffic. | Assign `TunConfig` addr/prefix/MTU + default route (wintun API or `netsh`); remove on teardown. |
| **Audio NSFW scorer stub** | `bulwark-audio/src/lib.rs:128` | `OnnxScorer` is a stub **even with `--features onnx`**: `load()` ignores path/sha, `score()` returns 0.0. No model/preprocess. → **all audio = SAFE.** | Real YAMNet/PANNs + explicit-sound head: decode → log-mel → `session.run()` (mirror `bulwark-vision/src/onnx.rs`). Pin a model. |
| **On-device OCR no-op** 🧪 | `bulwark-agent/src/lib.rs:77` | `OcrAgent::start` logs + returns Ok — no Windows.Media.Ocr/Tesseract/UIAutomation/Android Accessibility. Captures nothing. Also **`bulwark-client` doesn't depend on `bulwark-agent`** → dead in the shipping binary. | Per-platform OCR + accessibility capture → `TextSpan`s into the queue; wire into the client. This is the entire E2E/pinned-app (WhatsApp/Signal/iMessage) coverage story (PLAN §0a). |
| **Supervision connectors stubs** 🧪 | `bulwark-supervision/src/lib.rs:64` | All 4 connectors (Google/Microsoft/Apple/Meta) are no-op stubs (`poll`→empty). No OAuth/HTTP. Crate referenced by nothing. | Real per-platform OAuth + family-API polling; wire `SupervisionHub` into the client/server (PLAN Phase 6). |
| **Video remediation absent** | `bulwark-video/src/lib.rs` | No blur/mute/re-encode anywhere (only in comments). Detects but can't act. Audio windows always empty (`:393`). **Frame-format mismatch** (`:357` emits raw RGB24, vision decodes `image/jpeg` `bulwark-vision/src/preprocess.rs:133`) → every frame errors → fails open. | ffmpeg drawbox/boxblur on flagged ranges + `volume=0` on flagged spans + GPU re-mux; emit a decodable frame format (or a raw-RGB24 vision entry); implement audio extraction. |

## 🟠 P1 — simplified / incomplete / real-impl-gated-off

| Area | Location | Gap | Production needs |
|---|---|---|---|
| Image NSFW gated off | `bulwark-vision/src/lib.rs:58` | Real `OnnxScorer` is genuinely good but behind `onnx` (off in client/server defaults); no model bundled → fails OPEN. | Ship with `onnx` + a SHA-pinned model; **fail-CLOSED** posture for child safety. |
| Local ONNX never runs | `bulwark-infer/src/analyzer.rs:168` | `OnnxAnalyzer::analyze` builds the session but never `run()`s; returns inconclusive. | Preprocess→`session.run()`→post-process to a `Verdict`. |
| Server skips image/audio | `bulwark-server/src/lib.rs:115` | `AnalyzerRegistry` registers only TEXT (+VIDEO); IMAGE/AUDIO never registered → fail open. | Register `bulwark-vision`/`bulwark-audio` analyzers (once they're real). |
| Pinning never detected | `bulwark-net/src/proxy.rs:449`, `pinning.rs:82` | `on_pinned`/`record_pinned` only called from tests → pinned/E2E apps never flagged → OCR route never triggers. | Detect leaf-rejection at the hudsucker handshake; call `on_pinned(host)`; surface to coverage. |
| Linux/macOS routing unwired | `bulwark-net/src/tun/stub.rs:93`, `tun/routing.rs` | `install_routing`→`unsupported`; the real `*_install_plan`+`execute_plan` exist + are tested but never called. 🧪 | Call the plans from `install_routing`/`teardown_routing` (v4+v6, idempotent). Root-validate. Gated behind the pump. |
| Non-Windows truststore/keystore | `bulwark-net/src/truststore.rs:67`, `ca/mod.rs:255` | Linux/macOS/Android CA install + keystore are `Unsupported`; only Windows DPAPI. 🧪 | Per-OS trust install/uninstall + keystore backends; uninstall is a release-blocker. |
| Multi-node cluster | `bulwark-cluster/src/lib.rs:148,42,97` | `run_gossip` is a logging placeholder; `quorum`(Postgres) unused; queue is in-process, non-durable, no dequeue lease. 🧪 | `foca` SWIM; Postgres-backed queue/leases; visibility-timeout requeue (PLAN Phase 4). Single-node `all-in-one` works. |
| Offload refresh hardcoded | `bulwark-server/src/service.rs:123` | `refresh_offload` returns a fixed policy, ignores the fresh RTT/battery. | Re-derive from the request (reuse the negotiate heuristic). **← fixing now.** |
| GPU detection env-only | `bulwark-core/src/device.rs:174` | `detect_gpu` only reads `BULWARK_GPU`; no DXGI/Metal/NVML probe → GPU silently unused. | Real per-platform GPU enumeration. |
| UI coverage fake | `bulwark-ui/src/lib.rs:104` | Coverage matrix returns 2 hardcoded sample rows. | Derive live from the pinning registry + active apps ("honest coverage dashboard", PLAN §5). |
| Classifier off in client | `bulwark-text/Cargo.toml`, client | DistilBERT/sklearn backstop off by default (by design — confirm-only). | Enable on workers via `bulwark-server --features classifier`. |

## 🟡 P2 — polish / planned
- Client parent-approved allowlist is an in-process seam (`bulwark-client/src/lib.rs:421`) — persist cross-process.
- `NetInterceptor::start` doesn't drive the netstack yet (`interceptor.rs:262`); only `start_proxy_only` is wired.
- Hardware-non-exportable keystore tier (`bulwark-net/src/ca/keystore.rs:34`) — in-keystore signing.
- wintun.dll Authenticode verify before load (`tun/windows.rs:34`).
- Gmail-API mail transport (`bulwark-alert/src/transport.rs`) — SMTP works.
- SQLCipher at-rest off by default (`bulwark-store`) — enable `sqlcipher` for client.
- LLM "explain" client unwired (`bulwark-ui`, `llm-explain` feature) — opt-in, off.

---

## Honest sequencing (by child-safety impact)
1. **Fail-CLOSED + ship models** — make the default build *not* silently allow all media (config + pinned model artifacts). Highest safety leverage; partly CI-doable (the fail-closed policy), partly needs model artifacts.
2. **On-device OCR** (`bulwark-agent`) — the E2E coverage story; needs per-platform native work + device validation. 🧪
3. **Audio ONNX** + **video remediation/frame-fix** — real perception. Needs models + ffmpeg validation. 🧪
4. **Transparent VPN pump** — the big P0; rebuild + real-device validate. 🧪 (gates Linux/macOS routing)
5. **Supervision OAuth connectors** — needs external app credentials. 🧪
6. **CI-verifiable now (no devices/models):** `refresh_offload` re-derive, `bulwark-infer` run(), pinning-detect hook, GPU detect, cluster leases, UI live coverage.

**Reality check:** items marked 🧪 need real devices, pinned model artifacts, or external OAuth credentials — they cannot be "implemented + verified" purely in CI/this environment. They are real engineering deliverables, not one-pass fills. The CI-verifiable set (step 6) is what can be done + tested here directly.
