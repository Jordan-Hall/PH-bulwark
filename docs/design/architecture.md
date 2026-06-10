# Bulwark — Architecture (B1)

Refined per-crate responsibilities, client/server/cluster boundaries, end-to-end
data flow, and the latency-budget table. Authoritative companion to `PLAN.md`
(§1 topology, §2 crate map) and `docs/design/interfaces.md` (the Rust traits).

The shared wire contract is `bulwark-proto` (`crates/bulwark-proto/proto/bulwark.proto`,
package `bulwark.v1`). **All** cross-crate boundaries that cross a process or a
network link speak it; in-process boundaries speak the Rust traits in
`interfaces.md`, which are themselves expressed in `bulwark-proto` types.

Design principles carried from PLAN: **rules-first, small-model-second,
big-AI-rarely**; **mTLS on every node link**; **never persist explicit media**;
`#![forbid(unsafe_code)]` except audited FFI; **no telemetry**; fail-safe defaults.

---

## 1. Three planes

```
 ┌───────────────────────── CLIENT (every device) ─────────────────────────┐
 │ DATA PLANE                                CONTROL PLANE                   │
 │  bulwark-net  TUN/VpnService + TLS inspection + CA      bulwark-core  config, caps,     │
 │  bulwark-flow buffer / delay / demux                       device profile   │
 │  bulwark-agent OCR + accessibility (E2E)      bulwark-infer  local-vs-cluster  │
 │  tiny first-pass local models                            routing, offload  │
 │  bulwark-policy action decision               bulwark-store  encrypted SQLite  │
 │  bulwark-alert local alert origination        bulwark-ui     local dashboard   │
 └──────────────────────────────┬───────────────────────────────────────────┘
                                 │ gRPC / mTLS (bulwark-proto)
                ┌────────────────┴───────────────────────────────────┐
                │                  SERVER CLUSTER                      │
                │  bulwark-server (role: lb | worker | all-in-one)       │
                │    hosts analyzers: bulwark-vision / -audio / -video / │
                │                     -text  + bulwark-supervision        │
                │  bulwark-cluster  membership · health · LB · work queue │
                │  bulwark-store (Postgres adapter)   shared state        │
                └───────────────────────────────────────────────────────┘
```

A home user runs **one `all-in-one` node** (the gateway *is* the cluster). A
deployment runs an `lb` plus many `worker`s. The client never assumes more than
one reachable node.

---

## 2. Per-crate responsibilities (refined)

### Contract & shared
| Crate | Responsibility | Boundary it owns |
|---|---|---|
| **bulwark-proto** | The `bulwark.v1` gRPC/protobuf contract + helper newtypes (`DeviceId`, `NodeId`, `GroomingRule`, `severity_for_score`). Generated server+client stubs. | Every network boundary. |
| **bulwark-core** | Shared Rust types not on the wire, config loading (`figment`), **device-capability detection** (CPU/RAM/GPU/exec-providers/battery → `DeviceProfile`), local IPC, model-checksum registry (SHA256 pins), error types. | In-process glue; produces `DeviceProfile`. |

### Client data plane
| Crate | Responsibility | Implements (see interfaces.md) |
|---|---|---|
| **bulwark-net** | TUN (`wintun`/`tun-rs`/Android `VpnService`), `hudsucker` TLS inspection, **per-install CA** (`rcgen`, key in DPAPI/TPM/Keystore), QUIC downgrade, pinning detection → mark flow for OCR fallback. | `Interceptor` |
| **bulwark-flow** | Protocol/flow classification, stream demux (HLS/DASH/progressive), ring-buffer + bounded delay for video/live, hands segments/frames/text up. | `FlowClassifier` |
| **bulwark-agent** | On-device **conventional OCR** (`Windows.Media.Ocr`/`leptess`/ML Kit/macOS Vision) + accessibility-tree + notification capture — the E2E/pinned-app answer. Emits `TextSpan`. | `OcrSource` |
| **bulwark-client** | Device orchestrator: wires net + flow + agent + infer + policy + alert; owns the per-device gRPC channel + client cert. | (composition root) |

### Routing / decision
| Crate | Responsibility | Implements |
|---|---|---|
| **bulwark-infer** | Local-vs-cluster decision from `DeviceProfile` + measured RTT + cluster backpressure; runs tiny local models when policy says local; calls `Analysis`/`Offload` otherwise. Honours `OffloadPolicy`. | `OffloadRouter`, `Analyzer` (local impl) |
| **bulwark-policy** | Thresholds, age profiles, maps `Verdict` → `Action` (ALLOW/BLOCK/BLUR/MUTE/WARN/LOG); decides when an `AlertEvent` fires. | `PolicyEngine` |
| **bulwark-alert** | Originates `AlertEvent`s, **rate-limit + digest**, redacted evidence only, SMTP/Gmail via `lettre`. Hosts `AlertRelay` on server; client calls it. | `AlertSink` |
| **bulwark-store** | Encrypted SQLite client side (`rusqlite`+`age`/SQLCipher), Postgres adapter server side (`sqlx`). Never stores explicit media. | `Store` |

### Server analyzers (run inside `bulwark-server` workers)
| Crate | Responsibility | Implements |
|---|---|---|
| **bulwark-vision** | Small dedicated ONNX NSFW image/frame classifier (NudeNet/Falconsai) via `ort`, INT8 on client tier / FP on GPU workers. | `Analyzer` |
| **bulwark-audio** | Small explicit-audio classifier (PANNs/YAMNet backbone + trained head) via `ort`. | `Analyzer` |
| **bulwark-video** | `ffmpeg-sidecar` decode/sample/blur/mute/re-mux; scene-aware sampling; calls vision+audio per frame/segment; flagged-only re-encode. | `Analyzer` |
| **bulwark-text** | **Rules+lexicon FIRST** (eight grooming indicators), small classifier SECOND; conversation-level state machine; consumes network text AND OCR text. **No hot-path LLM.** | `Analyzer` |
| **bulwark-supervision** | Google/Microsoft/Apple/Meta family-API connectors; another text/event source feeding the detector. | `Analyzer` (event source) |

### Cluster & server core
| Crate | Responsibility | Implements |
|---|---|---|
| **bulwark-cluster** | `foca` SWIM membership, health, `ginepro` LB, work queue, Postgres quorum source-of-truth (stop accepting work if heartbeat lost → no split-brain), graceful drain. Hosts `ClusterControl`. | `ClusterMember` |
| **bulwark-server** | Role-based single binary (`--role lb\|worker\|all-in-one`). Hosts `Analysis`/`Offload`/`AlertRelay` (+`ClusterControl` via bulwark-cluster). Dispatches `AnalysisRequest` to the right analyzer by `MediaKind`. Runs hostile media parsers as **sandboxed worker processes**. | hosts services |
| **bulwark-ui** | `axum` dashboard + cluster admin; per-app coverage matrix; **optional, opt-in, off-by-default** LLM "explain this thread" escalation (never hot-path). | — |

---

## 3. End-to-end data flow

### 3a. Web image (TLS inspection-able HTTPS page)
1. `bulwark-net` inspection-decrypts the response; `bulwark-flow` classifies it as an image.
2. `bulwark-infer` consults the cached `OffloadPolicy`. Capable desktop → run
   `bulwark-vision` locally; mobile/low-power → `Analysis.Analyze` to the cluster
   (`AnalysisRequest{ media_kind=IMAGE, inline_media | media_ref }`).
3. Worker runs the NSFW model → `Verdict{ category, score, evidence(hash + safe
   thumbnail only) }`.
4. `bulwark-policy` maps `Verdict` → `Action`. BLOCK/BLUR → `bulwark-net` rewrites
   the response (blurred image / interstitial); ALLOW → forward.
5. If `Action` intervened, `bulwark-alert` raises `AlertEvent{ kind=INTERVENTION }`.
6. `bulwark-store` records the redacted event for the dashboard.

### 3b. Web / app chat text (network-visible or E2E via OCR)
1. Source is either `bulwark-net` (network text) or `bulwark-agent` (OCR/accessibility
   for E2E/pinned apps) → both emit a `TextSpan`.
2. **Grooming rules run locally** (cheap, explainable) in `bulwark-text`/`bulwark-infer`;
   the small classifier backs them up — locally if capable, else offloaded.
3. `GroomingSignal{ fired_categories, score, excerpt }` → `Verdict{ category=
   GROOMING | CSAM_SUSPECTED }`.
4. `bulwark-policy` thresholds (≥0.7 alert+review, ≥0.5 flag+log, ≥0.3 log).
5. `bulwark-alert` raises `AlertEvent{ kind=GROOMING_SUSPECTED, redacted_context }`.
   CSAM-suspected → documented legal-reporting path; flag, never archive.

### 3c. Video segment (progressive / HLS / DASH — delay acceptable)
1. `bulwark-flow` buffers the segment in a ring buffer (bounded delay budget).
2. Offloaded to a worker; `bulwark-video` (`ffmpeg-sidecar`) scene-samples frames →
   `Analysis.AnalyzeBatch` over the sampled frames + audio span.
3. If any frame/audio flags, `bulwark-video` re-encodes **only the flagged region**
   (blur/mute), GPU when present; otherwise the original is forwarded.
4. `bulwark-flow` releases the (possibly modified) segment after the delay window.

### 3d. Live stream (bounded delay)
As 3c but with a **hard delay budget** and `Analysis.AnalyzeStream` (bidi). The
client keeps the play-out buffer at least one analysis window behind live. On
deadline miss the fail-safe default applies (per policy: block or warn).

### 3e. WebRTC live call
Not analyzed. `bulwark-net` detects it and `bulwark-policy` **blocks** (PLAN §0a).

---

## 4. Latency-budget table

End-to-end "content available → action applied", assuming a one-hop LAN cluster
(home gateway) and the small/quantized models from `model-research.md`. RTT row
is client⇄cluster; "+offload" budgets add network + queue. These are **targets**
for E2 (`/verify`) to measure, not guarantees.

| Path | Stage breakdown (target ms) | Total budget | Mode |
|---|---|---|---|
| **Web text** | OCR/extract 5 · rules 1 · classifier 8 (local) | **≤ 25 ms** | local-first; rules alone <2 ms |
| **Web image** | TLS inspection 5 · resize 3 · NSFW INT8 local 15 / offload (RTT 10 + queue 5 + infer 12) 27 | **≤ 40 ms** | local on desktop, offload on mobile |
| **Video segment (VOD)** | buffer fill (segment) + sample 10 · batch infer 40 · flagged re-encode 60 · re-mux 15 | **≤ 250 ms over segment** (hidden by buffering) | offload; delay acceptable |
| **Live stream (delayed)** | play-out delay window **2–5 s** holds sample 10 · infer 40 · blur/mute 60 within budget | **delay window 2–5 s**, per-frame infer ≤ 120 ms | offload; client stays ≥1 window behind live |
| **Mobile, offloaded (any heavy)** | capture 3 · RTT 10–40 · queue (backpressure-bounded) ≤ 30 · infer 12–40 · RTT back | **≤ 150 ms** typical; force-offload below `min_battery_pct` | `bulwark-infer` chooses offload from `DeviceProfile` |

Guard rails:
- `AnalysisRequest.deadline_ms` lets a worker fast-path/shed under a live budget.
- `bulwark-infer` prefers **local** when `rtt_ms > max_local_rtt_ms` or cluster
  `queue_depth > cluster_queue_backpressure`; prefers **offload** when
  `battery_pct < min_battery_pct` or the device lacks a capable exec provider.
- Grooming **rules** are always cheap enough to run locally even on mobile; only
  the backing classifier is a candidate for offload.

---

## 5. Trust & security boundaries

- **mTLS everywhere.** Per-device client cert (`rcgen`, key in DPAPI/Keystore/
  Keychain) authenticates client⇄cluster; a cluster CA signs worker⇄worker.
- **Crown-jewel CA key** (the per-install TLS inspection CA) lives in TPM/keystore, never on
  the wire, never in `bulwark-proto`.
- **Cluster sees plaintext analysis intermediates** → in-memory only, owned
  hardware, audit logs. `Evidence` on the wire is hashes / safe-thumbnail /
  redacted-snippet ONLY — enforced by the proto shape, not just by policy.
- **Hostile input isolation:** media parsers (ffmpeg, image/audio decoders) run as
  **sandboxed worker processes** (AppContainer/seccomp).
- **Split-brain avoidance:** Postgres is quorum source-of-truth; a node that loses
  its heartbeat sets `accepting_work=false` (see `HealthStatus`).
- **CSAM:** `Category.CSAM_SUSPECTED` + `Severity.CRITICAL` → report-never-archive
  legal path. The system flags; it never stores illegal content.

See `docs/security/` (B2) for the full threat model.
