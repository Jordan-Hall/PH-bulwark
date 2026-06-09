# PH Bulwark — Production-Readiness Audit (authoritative gap map)

Refreshed **2026-06-09** to match shipped reality (was a 2026-06-08 source audit; much
of the perception/VPN layer has since landed + deployed). Pairs with [PLAN.md](../PLAN.md).
Legend: 🔴 P0 · 🟠 P1 · 🟡 P2 · ✅ done · 🧪 needs real-device / model / credential / deploy
validation (can't be fully CI-verified here).

## TL;DR
- **Live in production** (London EC2, `--features onnx,whisper,ffmpeg`, fail-CLOSED): **image** NSFW (bundled ViT), **audio** (whisper transcribe → `bulwark-text` grooming/adult), **video** (ffmpeg demux → frame NSFW + speech transcription → blur/mute remediation by timecode, same-format). Plus `bulwark-text`/`-policy`/`-store`/`-alert`/`-flow`/`-core`/`-proto`.
- **Fail-CLOSED is in:** uncovered media → `Category::Unspecified` → policy `fail_closed_uncovered` → Block+alert. The deploy ships the models, so the old "default build silently allows all media" hole is closed **for the deployed server**. (A bare `cargo build` with no features still no-ops media — keep deploys on the feature set.)
- **Not yet functional:** the **transparent-VPN data path** (foundations built + tested; the smoltcp poll-loop integration + real-device validation remain), **on-device OCR/agent**, **family-supervision**, and **WebRTC** video remediation.

---

## 🔴 P0 — core function

| Area | Status | Notes |
|---|---|---|
| Image NSFW | ✅ live | onnx + bundled model, fail-closed; `loaded bundled NSFW model` on the box. |
| Audio | ✅ live | Redesigned: **transcribe (whisper) → `bulwark-text`** (lighter than a dedicated model); `whisper_model_load 31.57 MB` on the box. |
| Video detect + remediate | ✅ live | RGB24→JPEG frame fix, audio-window extraction + whisper, blur/mute by timecode in the same container (`-copyts`), carried as `Verdict.remediated_media`. |
| **VPN pump** 🧪 | 🟠 in progress | Parser, `decide()`, proxy-bridge (CONNECT+splice), smoltcp `Device`-over-TUN — **all built + unit-tested**. Remaining: the poll-loop integration (architecture spike) + **real-device validation**. `run_netstack` still fail-closed. |
| VPN binary fatal-exit | ⏳ | Falls out when the pump lands; `bulwark_proxy` (explicit proxy) works today. |
| Windows TUN addressing 🧪 | ⏳ | `up()` needs addr/MTU/route; part of the device-validated pump pass. |
| **On-device OCR/agent** 🧪 | ❌ | `bulwark-agent` OCR is a no-op + not depended on by the client. The E2E/pinned-app (WhatsApp/Signal) story. Plan: **capability-detect ML Kit / on-device STT / NNAPI, fall back to Tesseract/whisper/CPU** (support all phones); needs the Pixel. |
| **Supervision connectors** 🧪 | ❌ | 4 connectors are no-op stubs; need per-platform **OAuth app credentials**. (Arguably subsumed by the on-device agent.) |

## 🟠 P1 — simplified / incomplete

| Area | Status | Notes |
|---|---|---|
| Server registers image/audio/video | ✅ | `with_text_and_video` registers vision (onnx), audio (whisper), video (ffmpeg) under their features. |
| `refresh_offload` re-derive | ✅ | Re-derives from the live request (RTT/battery). |
| GPU detection | ✅ | `detect_gpu_native` per-OS (Linux /proc + /dev/dri, macOS metal, Windows directml). |
| Cluster queue leases | ✅ | Lease + visibility-timeout requeue + `complete` ack. **gossip/quorum still placeholders** (foca/Postgres — Phase 4). |
| Secrecy > age-probing | ✅ | `SecrecyIsolation` +2.5 lone bonus; test `isolation_secrecy_outranks_age_probing`. (ML model still needs the same training-data fix.) |
| HLS/DASH proxy gating | ✅ | Proxy gates video segments like images; `Rewrite` swaps the cleaned segment. **Serve-chain** (carry `video_body` → core flow → consumer runs analyzer → `apply`) remains. |
| **Local ONNX never runs** | ⏳ CI-doable | `bulwark-infer::OnnxAnalyzer::analyze` builds the session but never `run()`s. (bulwark-vision's onnx is the live path; this crate is the generic seam.) |
| **Pinning never detected** | ⏳ CI-doable | `on_pinned` only called from tests → pinned/E2E apps never flagged → OCR route never triggers. Hook the hudsucker handshake leaf-rejection. |
| **UI coverage fake** | ⏳ CI-doable | `bulwark-ui` returns 2 hardcoded rows; derive live from the pinning registry. |
| Linux/macOS routing unwired 🧪 | ⏳ | Tested route-plans exist but `install_routing` isn't wired; gated behind the pump. |
| Non-Windows truststore/keystore 🧪 | ⏳ | Only Windows DPAPI; Linux/macOS/Android CA install + keystore needed. |

## 🟡 P2 — polish / planned
- WebRTC remediation (DTLS-SRTP terminate + real-time transcode + re-encrypt) — weeks; the file/segment remediation engine is the reusable core.
- ML full-corpus model: apply the secrecy>age-probing fix in training data (rules engine already correct).
- Parent-allowlist cross-process persistence; wintun Authenticode verify; Gmail-API transport; SQLCipher-at-rest; LLM-explain client.

---

## Honest sequencing (by child-safety impact)
1. ✅ **Fail-CLOSED + ship models** — done (deploy ships onnx/whisper/ffmpeg, fail-closed).
2. ✅ **Real perception** — image/audio/video detect + video remediate — done + live.
3. **Transparent VPN pump integration** — the big remaining P0; needs the architecture spike + **Pixel** (gates Linux/macOS routing + the proxy serve-chain). 🧪
4. **On-device OCR/agent** — E2E coverage; capability-detect + fallback; needs the **Pixel**. 🧪
5. **Supervision OAuth** — needs **external app credentials**. 🧪
6. **Still CI-doable here, no devices:** `bulwark-infer` run(), pinning-detect hook, UI live coverage, cluster gossip/quorum.

**Reality check:** the CI-verifiable perception layer is **done and deployed**. What remains is dominated by 🧪 items (real device, OAuth credentials, model retraining, or a multi-week WebRTC build) plus the small step-6 set that can still be done here.
