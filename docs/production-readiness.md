# PH Bulwark — Production-Readiness Audit (authoritative gap map)

Refreshed **2026-06-12** to match shipped reality (domain/TLS cutover + Android
CA-trust install since the 2026-06-09 pass; perception/VPN layer landed earlier).
Pairs with [PLAN.md](../PLAN.md).
Legend: 🔴 P0 · 🟠 P1 · 🟡 P2 · ✅ done · 🧪 needs real-device / model / credential / deploy
validation (can't be fully CI-verified here).

## TL;DR
- **Live in production** (London EC2, `--features onnx,whisper,ffmpeg`, fail-CLOSED): **image** NSFW (bundled ViT), **audio** (whisper transcribe → `bulwark-text` grooming/adult), **video** (ffmpeg demux → frame NSFW + speech transcription → blur/mute remediation by timecode, same-format). Plus `bulwark-text`/`-policy`/`-store`/`-alert`/`-flow`/`-core`/`-proto`.
- **Fail-CLOSED is in:** uncovered media → `Category::Unspecified` → policy `fail_closed_uncovered` → Block+alert. The deploy ships the models, so the old "default build silently allows all media" hole is closed **for the deployed server**. (A bare `cargo build` with no features still no-ops media — keep deploys on the feature set.)
- **Not yet device-validated:** the **transparent-VPN data path** (fd-driven smoltcp pump + Android startVpn wiring implemented + host-tested 2026-06-10; Pixel validation remains). **Not yet functional:** **on-device OCR/agent**, **family-supervision**, and **WebRTC** video remediation.

---

## 🔴 P0 — core function

| Area | Status | Notes |
|---|---|---|
| Image NSFW | ✅ live | onnx + bundled model, fail-closed; `loaded bundled NSFW model` on the box. |
| Audio | ✅ live | Redesigned: **transcribe (whisper) → `bulwark-text`** (lighter than a dedicated model); `whisper_model_load 31.57 MB` on the box. |
| Video detect + remediate | ✅ live | RGB24→JPEG frame fix, audio-window extraction + whisper, blur/mute by timecode in the same container (`-copyts`), carried as `Verdict.remediated_media`. |
| **VPN pump** 🧪 | 🟠 implemented, device validation pending | fd-driven `run_netstack` poll-loop **live on unix/Android** (per-flow TCP terminate → CONNECT → splice; DNS forward; QUIC drop) and `run_android_data_path` wires the JNI `startVpn` (in-process TLS-inspecting proxy + pump over the VpnService fd). Host-tested + Android cross-compile. Remaining: **Pixel on-device validation**; Windows/wintun pump still fail-closed by design. |
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
| HLS/DASH proxy gating | ✅ | Proxy gates video segments like images; `Rewrite` swaps the cleaned segment. Serve-chain shipped 2026-06-09: segments carried through the flow convert (#98) and the remediated segment served back via Rewrite (#99). |
| **Local ONNX never runs** | ✅ live (2026-06-10) | `OnnxAnalyzer::analyze` now preprocesses (shared `bulwark_vision::preprocess`), really `session.run()`s, and maps score → Verdict with vision's exact conventions (`bulwark_vision::postprocess`, hash-only evidence, threshold → Blur). Image-only by honest contract; other kinds/errors stay inconclusive → offload. Model-gated self-skipping test; CI runs `cargo test -p bulwark-infer --features onnx`. |
| **Pinning detection** | ✅ live (2026-06-10) | `HttpHandler::should_intercept` now drives `record_intercept_attempt` → `record_pinned`: hudsucker swallows the leaf-rejection internally, so pinning is inferred via a 3-strike heuristic (CONNECTs that never decrypt), with strikes reset on any successful decrypt. Pinned hosts tunnel through under fail-open (→ OCR route + honest coverage gap) or stay blocked under fail-closed. 6 new unit tests. |
| **UI coverage fake** | ✅ live (2026-06-10) | `/api/coverage` now derives one row per LEARNED host from the injected `CoverageSource`; `PinningRegistry::snapshot()` + `NetInterceptor::pinning_snapshot()` feed it; `bulwark_proxy` embeds the dashboard (`BULWARK_UI_BIND`, default 127.0.0.1:8081). Hardcoded rows deleted. |
| Linux/macOS routing unwired 🧪 | ⏳ | Tested route-plans exist but `install_routing` isn't wired; gated behind the pump. |
| **Cluster TLS: real domain + public cert** | ✅ live (2026-06-12) | Cluster reachable at `https://api.predatorhunters.co.uk:8443` (+ `vpn.` SAN) with a **Let's Encrypt** cert auto-issued on the box via acme.sh DNS-01 (Cloudflare), self-signed cluster CA as the fallback. Clients are **public-trust-by-default, pin-optional**: parent console (`tls-webpki-roots`) + child/relay JNI trust public roots when no CA is pinned, so a CA-less pairing payload pairs cleanly; private-CA pinning stays for self-hosted. |
| **Android inspection-CA install** | ✅ shipped (2026-06-12) | `bulwark-net::vpn::inspection_ca_pem` exports the per-install root (public cert only) over JNI (`inspectionCaPem`); `CaTrust` installs it into the **system** trust store via `DevicePolicyManager.installCaCert` when Device Owner (idempotent), fixing "connection not private". Honest limit: a non-managed device can't make apps trust a user CA (Android 7+), so transparent HTTPS needs a managed device; the OCR path is the fallback. → [`docs/design/server-vpn-mode-and-ca-trust.md`](design/server-vpn-mode-and-ca-trust.md) Phase 1. |
| Linux/macOS desktop truststore/keystore 🧪 | ⏳ | Windows DPAPI + `certutil` install ship; the **Android** CA install now ships (above); Linux/macOS desktop CA install + non-Windows keystore still pending (desktop child filter is Windows-gated). |

## 🟡 P2 — polish / planned
- WebRTC remediation (DTLS-SRTP terminate + real-time transcode + re-encrypt) — weeks; the file/segment remediation engine is the reusable core.
- ML full-corpus model: apply the secrecy>age-probing fix in training data (rules engine already correct).
- Parent-allowlist cross-process persistence; wintun Authenticode verify; Gmail-API transport; SQLCipher-at-rest; LLM-explain client.

---

## Honest sequencing (by child-safety impact)
1. ✅ **Fail-CLOSED + ship models** — done (deploy ships onnx/whisper/ffmpeg, fail-closed).
2. ✅ **Real perception** — image/audio/video detect + video remediate — done + live.
3. **Transparent VPN pump on-device validation** — pump + Android wiring implemented + host-tested (2026-06-10); needs the **Pixel** (gates Linux/macOS routing). 🧪
4. **On-device OCR/agent** — E2E coverage; capability-detect + fallback; needs the **Pixel**. 🧪
5. **Supervision OAuth** — needs **external app credentials**. 🧪
6. **Still CI-doable here, no devices:** `bulwark-infer` run(), UI live coverage, cluster gossip/quorum (pinning-detect hook shipped 2026-06-10).

**Reality check:** the CI-verifiable perception layer is **done and deployed**. What remains is dominated by 🧪 items (real device, OAuth credentials, model retraining, or a multi-week WebRTC build) plus the small step-6 set that can still be done here.
