# Real-time AI filtering pipeline + rich OCR attribution

Status: design. Codename "aegis"/"bulwark" (product: PH Bulwark / PH Bulwark Manager).
This doc covers (A) the fastest+secure real-time AI content-filtering path, and
(B) rich attribution of an on-device capture ("which app, who said it, where").
It is grounded in the crates as they exist on `feat/vpn-netstack-iface`; every
cited type/function is real. Stubs are flagged explicitly.

Companion docs: `on-device-scanning.md`, `vpn-data-path-plan.md`,
`architecture.md` §3–§5, `interfaces.md`, `parent-notifications.md`.

---

## Part A — Real-time AI filtering pipeline (fastest + secure)

### A.0 What we filter, and with which engine

| Signal | Engine (crate) | Real today? |
|---|---|---|
| Grooming / adult **text** (chat, page text, OCR'd on-screen text) | `bulwark-text` `GroomingRuleEngine` + adult lexicon | **Real, always hot-path** |
| **NSFW image** / sampled video frame | `bulwark-vision` `VisionAnalyzer` (ONNX `vit-base-nsfw-detector`) | Real behind `--features onnx`; stub otherwise |
| Explicit/grooming **audio** | `bulwark-audio` (whisper STT → `bulwark-text`) | Real behind `--features whisper` |
| **Video** segment | `bulwark-video` (ffmpeg decode → vision/audio → blur/mute) | Real behind `--features ffmpeg` |
| `Verdict → Action` + alerts | `bulwark-policy` `Policy::evaluate` | **Real** |
| Where each unit runs | `bulwark-infer` `policy::decide` | **Real (routing only)** |

Design rule (PLAN §0b, encoded in code): **rules-first, minimal-AI, no LLM**. The
grooming rules are deterministic, explainable, and feasible on any phone, so they
are *never* offloaded (`bulwark-infer::policy::decide`: `kind == Text → Route::Local`).
Only heavy media (image/audio/video) is a candidate for cluster offload.

### A.1 The two capture front-ends feeding one brain

There are two independent capture paths that converge on the same analyzers and
the same policy:

1. **Network path (TLS inspection).** `bulwark-net` terminates TLS in `proxy.rs`
   (`FlowHandler`), emits a `CapturedFlow` per request/response onto a bounded
   channel, and `bulwark-flow` classifies it into `AnalysisUnit`s. On the
   transparent VPN, `vpn/netstack.rs` (unix/Android) captures L3 packets, opens a
   smoltcp `any_ip` listener bound to the original destination, `CONNECT`s to the
   in-process proxy, and splices — so every inspectable TCP flow is decrypted.
   QUIC/UDP-443 is dropped (`QUIC_UDP_PORT`) to force HTTP/3 down onto
   inspectable TCP/443.

2. **On-device path (accessibility/OCR).** For E2E/cert-pinned apps the network
   can't read (`MONITORED` set: WhatsApp, Signal, Messenger, Instagram, Snapchat,
   Telegram), `BulwarkAccessibilityService` reads already-decrypted on-screen
   text and notification text and calls `RustBridge.analyzeText(pkg, thread, text)`
   → `bulwark-android` JNI → `bulwark-text` + `bulwark-policy`, all on-device.

Both paths yield a `Verdict` (`bulwark-proto`) and run it through the SAME
`bulwark-policy` engine. This single-brain design means a grooming rule that
fires on a inspected web chat and one that fires on an OCR'd WhatsApp message escalate
identically (and share thread state shape, keyed by `thread_id`).

### A.2 Hot path & latency budget

The governing constraint is the owner directive **"block instantly by default"**:
a scorable image/video is decision-gated and a *timeout or missing decision fails
CLOSED (Drop)* — see `proxy.rs::DECISION_TIMEOUT` (5 s) and the `gated_image_*_fails_closed_to_drop`
tests. Bounded **text/html documents** are decision-gated too but fail **OPEN**
(Forward) after `HTML_DECISION_TIMEOUT` (2 s) — every page is text/html, so a
stalled classifier must not white-screen all browsing (`gate_policy`); a BLOCK
verdict landing inside the window swaps the page for the inline block page
(`blocked_page_response`). Before any gating, the guardian **host blocklist**
(`bulwark-net::blocklist`, `NetConfig.blocklist_path` / `BULWARK_BLOCKLIST`)
refuses a listed host at CONNECT/request time (no tunnel, 403 block page) and
the VPN pump RSTs listed literal-IP destinations pre-CONNECT. Page-structural
subresources (js/css/json/event-streams, icons, tiny/oversized images, >2 MiB
HTML) are **never gated** and forward with zero added latency (`image_body_for`,
`video_segment_body_for`, `is_gatable_html`).

**Latency tiers (fastest → heaviest):**

| Tier | What runs | Where | Budget | Gating |
|---|---|---|---|---|
| 0 — text rules | `GroomingRuleEngine` + adult lexicon | always **local** (any phone) | sub-millisecond, pure CPU/in-memory | text/html pages **gated fail-open** (2 s window; BLOCK → inline block page); other text emit-only |
| 1 — small NSFW image | `VisionAnalyzer` ONNX (CPU/NNAPI/DirectML) | local first; cluster on mobile/low-power | tens of ms/frame on int8 ViT | **gated** in proxy (fail-closed) |
| 2 — audio | whisper STT → text rules | offload-preferred on mobile | STT-bound (windowed) | via flow buffer |
| 3 — video segment | ffmpeg decode → sample frames + audio windows → tiers 1–2 | offload-preferred | broadcast-delay buffer (2–5 s live; relaxed VOD) | via `DelayBuffer` |

**Keeping it real-time:**
- **Frame sampling, not every frame.** `bulwark-video` `VideoConfig::sample_fps`
  (default 2.0) samples frames scene-coarsely; only flagged timecodes are
  re-encoded (`remediate` does `-c:v copy` where no NSFW frame fired).
- **Streaming/buffering budget.** `bulwark-flow::DelayBuffer` holds video/live
  segments behind a bounded broadcast delay (`LIVE_DELAY_MS` within
  architecture §4's 2–5 s window) so a verdict can land before play-out, exerts
  back-pressure when full (`Admission::BackPressure`), and surfaces overdue
  segments for the fail-safe shed path (`due_segments`).
- **Bounded plaintext.** The proxy ships only a `BODY_PEEK_CAP` (64 KiB) peek up
  the flow channel for classification; whole image bodies are surfaced only when
  scorable (`[MIN_SCORABLE_IMAGE_BYTES 16 KiB, IMAGE_BODY_CAP 8 MiB]`), video
  segments only up to `VIDEO_SEGMENT_CAP` (16 MiB). Larger = skipped (fail-open
  on size, never buffered).
- **Backpressure as a real-time tool.** `FlowHandler::emit` uses `try_send` and
  *sheds* a flow if the bounded channel is full (logs metadata only) — never
  blocks the data path, never unbounded-buffers plaintext.

**On-device vs desktop placement** (`bulwark-infer::policy::decide`, priority order):
`Text → Local` always; `RTT > max_local_rtt_ms → Local`; `queue_depth >
cluster_queue_backpressure → Local`; heavy + on-battery below `min_battery_pct →
Cluster`; else per negotiated `run_*_local` hint. Net effect: a capable desktop
runs image/audio locally and may offload video; a phone keeps text local and
offloads heavy media to the guardian's own cluster over mTLS — but a slow link or
a backpressured cluster *pulls work back local* because a missed deadline is worse
than a slightly weaker local verdict.

### A.3 On-device AI — capability-detect, fall back, support ALL phones

Intent (memory: on-device-ai-fallback): detect the best accelerator at runtime
and degrade gracefully so *every* phone is covered, never just flagship NNAPI
devices.

- **Detection ladder (per device, negotiated once via `OffloadRouter::negotiate`
  from `detect_device_profile()`):**
  1. Android: ML Kit on-device / **NNAPI** (`ExecutionProvider::Nnapi`) → GPU →
     **CPU/oneDNN** (`ExecutionProvider::Cpu`, always available).
  2. Desktop Windows: **DirectML** (`ExecutionProvider::Directml`) → CPU.
  3. macOS/iOS-class: CoreML → CPU.
- **`ort` execution provider** is selected from `OffloadPolicy.preferred_local_providers`
  (already carried in the proto and `PolicySnapshot`). The provider list is a
  *preference*; `ort` falls through to CPU if a provider can't initialise.
- **Bundled CPU fallback is the floor.** `bulwark-vision` compiles the int8 ViT
  NSFW model in (`BUNDLED_NSFW_MODEL`, `include_bytes!`) so an `onnx` build always
  has a working CPU scorer with no external file. Audio's whisper tiny.en (~30 MB)
  is provisioned at deploy. If the runtime itself is unavailable, the analyzer
  emits `Category::Unspecified` → **policy fail-CLOSES** (never a false "safe").
- **STT fallback** mirrors this: ML Kit/on-device STT where present, else bundled
  whisper.cpp CPU (`bulwark-audio::whisper`, MIT) — robust linear resample to
  16 kHz keeps it dependency-light.

> **Gap to close:** the runtime provider *detection* and the bundled-vs-accelerated
> selection are described by `OffloadPolicy`/`ExecutionProvider` and consumed by the
> router, but the Android NNAPI/ML-Kit probe and the iOS CoreML probe are not yet
> implemented; today `from_env` either loads the bundled CPU ONNX model (onnx build)
> or fails closed. Wiring the probe is ordered work (A.6).

### A.4 Security model

- **Per-install CA, in-memory leaf minting.** `proxy.rs::build_authority` builds an
  `rcgen::Issuer` from the stored root DER + DPAPI-unwrapped key; leaves are minted
  and cached per host (`LEAF_CACHE_SIZE`). The private key never leaves the host;
  on uninstall the root is removed (`set_remove_root_on_shutdown` → `uninstall_ca`)
  so no orphaned-root TLS inspection backdoor is left behind (threat-model Asset 1).
- **Sandboxed media parsers.** ffmpeg is **shelled out** via `ffmpeg-sidecar`
  (child process, never linked) so its GPL/LGPL and its C attack surface stay out
  of our address space (`bulwark-video::ffmpeg`). Image decode is the memory-safe
  Rust `image` crate. `#![forbid(unsafe_code)]` across `bulwark-text`,
  `-vision`, `-audio`, `-video`, `-policy`, `-flow`; the JNI bridge is the only
  `allow(unsafe_code)` crate and keeps every unsafe block pointer-validated.
- **Content-free verdicts, no raw content stored.** Plaintext bodies are in-memory
  intermediates only — never logged, never `Debug`-printed, never persisted
  (`proxy.rs` privacy note). `Evidence` carries sha256 / perceptual hash /
  optional SAFE-only thumbnail / redacted text snippet — never raw media (proto
  `Evidence` invariant; `bulwark-vision` test `flags_nsfw_and_blurs_with_hash_only`).
  Suspected **CSAM is never previewed, stored, or remediated** — only blocked +
  hashed (`bulwark-video` skips remediation/store for `CsamSuspected`;
  `SegmentStore::store_if_safe` refuses it; `redact.rs::redacted_excerpt` withholds
  the text).
- **Fail-open vs fail-closed (deliberate per signal):**
  - **Fail-CLOSED** (block) when we *could not score* media we should have:
    `Category::Unspecified` from a stub vision/audio/video analyzer → `Policy`
    blocks + alerts the coverage gap (`fail_closed_uncovered`, default on). The
    image decision gate also fails closed on timeout/dropped sender (Drop), and
    a configured-but-unreadable guardian blocklist file fails CLOSED at start
    (the list must never silently vanish).
  - **Fail-OPEN** (forward) where blocking would harm usability with no safety
    win: page-structural resources, sub-16 KiB images, oversized images/segments
    (size guard), the text/html page gate on a missed verdict window (a stalled
    classifier must not white-screen all browsing — the host blocklist still
    hard-blocks known-bad sites with no verdict at all), pinned hosts that
    reject our leaf (`on_pinned` → `failed_open`
    per policy; those flows route to the OCR path instead), and the JNI bridge on
    bad input (a filter must never take down the host app).
- **mTLS to cluster.** `bulwark-infer::OffloadClient` is the only outbound door and
  fails closed: no client identity / CA root → no connection. No telemetry; the
  sole connection is to the user's own cluster.

### A.5 Merging NSFW image + grooming text + OCR into one decision

Every analyzer emits a `bulwark_proto::Verdict` (category, score, severity,
evidence, optional `GroomingSignal`). They converge as follows:

1. **Per-unit verdict.** Image → `AdultImage` (blur-preferred) or `Safe`/`Unspecified`;
   text/OCR → `Safe`/`AdultText`/`Grooming`/`CsamSuspected`; audio → `AdultAudio`/
   `Grooming`; video → the **worst** child verdict (`bulwark-video` keeps the
   highest-score frame/audio verdict and accumulates blur/mute timecodes).
2. **Policy is the single authority** (`Policy::evaluate`, ignores the analyzer's
   recommended action except honouring `CsamSuspected` unconditionally):
   - `CsamSuspected` → **BLOCK**, CRITICAL, INTERVENTION alert, `report` flag set
     (report-never-archive; engine only flags).
   - `Unspecified` → **BLOCK** (fail-closed coverage gap) + alert.
   - Score bands per age profile: `<log` allow; `[log,flag)` LOG; `[flag,block)`
     soft (image→BLUR, audio→MUTE, adult-text→BLOCK for young / WARN for teen,
     violence/self-harm/hate→WARN) + INTERVENTION alert; `>=block` enforce.
   - **Grooming is special** (false-positive minimisation): even high-confidence
     grooming defaults to **LOG + `GroomingSuspected` alert, NOT block** — it does
     not silently censor a child's whole conversation (only image-request/CSAM does).
3. **Action → data plane.** `Action` is applied where the bytes live:
   - TLS inspection image/video/html: `InterceptDecision` via the `DecisionGate` — `Forward` /
     `Rewrite(new_bytes)` (the remediated blurred/muted segment) / `Drop`
     (media: `blocked_response` 403; html: `blocked_page_response` inline block
     page — original bytes never leak downstream). Blocklisted hosts never reach
     the gate at all: refused at CONNECT/request (`is_request_blocked`) or RST'd
     pre-CONNECT in the pump.
   - Video segments: `DelayBuffer::apply` — ALLOW/WARN/LOG forward, BLUR/MUTE
     forward rewritten bytes, BLOCK drop.
   - On-device (accessibility): high-confidence/CSAM → disruptive overlay +
     HOME bounce + audible alert (`blockContent`); borderline non-safe → guardian
     notification, and **fail-safe block** if the alert can't be delivered.
4. **Allowlist bypass** (`decide_with_allowlist`): a guardian-approved host/hash
   short-circuits to ALLOW — **except CSAM, which is never bypassed**.

Conflict resolution across simultaneous signals is "worst wins": video already
implements it; for a page that has both flagged text and a flagged image, each
unit is gated independently and the strictest action governs its own bytes
(text drives the overlay/log; the image is blurred/dropped at its own gate).

### A.6 Current state vs gaps — ordered work to production-grade

Real and wired: the text rules + thread state, the policy engine,
the hudsucker TLS inspection + decision gate, the unix/Android transparent pump, the flow
classifier + delay buffer, the infer routing table, the Android accessibility
capture + JNI bridge, and ffmpeg/whisper behind features.

Ordered gaps:
1. **Ship a real NSFW model build.** Make `--features onnx` (with the bundled
   `vit-base-nsfw-detector`) the default for the client binaries on platforms
   where ONNX Runtime loads; keep the fail-closed stub only where SAC blocks the
   native lib. Without this, every image is `Unspecified` → blocked.
2. **Runtime accelerator probe.** Implement the NNAPI/ML-Kit (Android), CoreML
   (Apple), DirectML (Windows) capability detection feeding
   `OffloadPolicy.preferred_local_providers`; fall back to bundled CPU.
3. **Provision whisper + ffmpeg on the child device / cluster** and default the
   `whisper`/`ffmpeg` features on for audio/video coverage (else those kinds
   fail-closed-block, hurting usability).
4. **Windows transparent-VPN pump.** Replace the fail-closed `#[cfg(not(unix))]`
   `run_netstack` with a wintun pump (desktop currently relies on explicit-proxy
   mode). Device-validated, never compile-only (vpn-data-path-plan §sequencing).
5. **Wire the live-loop verdict queue into the Android alert path.** `nextAlert`
   currently drains only tamper events; queue content verdicts from the filtering
   loop so guardian content alerts surface on-device, and relay them to the
   cluster. Wire `submitReviewDecision` into the `bulwark-store` allowlist.
6. **IPv6 + non-DNS UDP on the pump** (today IPv4-only, v6 dropped so apps fall
   back; non-DNS/non-QUIC UDP dropped).

---

## Part B — OCR / on-device capture attribution

Goal: turn an on-device capture into a guardian-facing alert that states **which
app**, **who said it** (child vs other party, with display name/handle), the
**thread/conversation**, **when**, and surrounding context — while never storing
raw messages and never storing/echoing CSAM.

### B.1 What the Android accessibility tree actually exposes

`AccessibilityEvent` + `AccessibilityNodeInfo` give us, per node:
- `event.packageName` — the **package id** (e.g. `com.whatsapp`). Authoritative
  source of "which app".
- `node.text` — the visible text of a view (message bubbles, names, timestamps).
- `node.contentDescription` — accessibility label (often the richest attribution
  source: e.g. WhatsApp labels a message bubble "You, 14:32" or
  "Alice, 14:31, message text"; the date/sender is in the content-description even
  when the bubble text is just the message).
- `node.viewIdResourceName` — the app's resource id (e.g.
  `com.whatsapp:id/conversation_text`, `:id/conversation_contact_name`,
  `:id/date_divider`). **This is the key to per-app extraction** — view ids are
  stable enough per app version to map sender/message/header roles.
- `root.window?.title` — often the conversation title (the chat header / contact
  name) for the active window.
- Geometry (`getBoundsInScreen`) and `isVisibleToUser` — to order messages
  top-to-bottom and distinguish the on-screen header from bubbles.

Today the service only does `collectText(root)` (concatenate all `node.text`) and
`threadIdFor = "$pkg:${window.title ?? hashCode}"`. That is enough to *detect*,
but throws away the structure needed to *attribute*.

**Per-app extraction strategy (sender vs recipient).** Inbound vs outbound is
distinguishable because chat apps render the child's own (outbound) messages and
the other party's (inbound) messages with different view ids / alignment /
content-description prefixes:

| App (package) | Sender/recipient signal in the tree |
|---|---|
| **WhatsApp** (`com.whatsapp`) | Bubble `viewId` `conversation_text`; content-description begins "You, …" (outbound) vs "<Name>, …" (inbound). Header name: `conversation_contact_name`. Group sender: a `:id/...name_in_group` label on the bubble. |
| **Signal** (`org.thoughtcrime.securesms`) | Outbound vs inbound by bubble alignment + `viewId` (`message_body`); sender name view in groups; toolbar title = thread name. (Signal disables a11y on some screens — degrade to header + bubble text.) |
| **Messenger** (`com.facebook.orca`) | Row content-description encodes "Sent/Received … by <Name> at <time>"; thread title in the toolbar. |
| **Instagram DMs** (`com.instagram.android`) | Bubble rows with username avatars; content-description "Message from <handle>"; header = `:id/thread_title` / username. |
| **Telegram** (`org.telegram.messenger`) | Bubbles carry sender name views in groups; outbound vs inbound by alignment; header = chat title. |
| **Snapchat** (`com.snapchat.android`) | Sparse a11y; rely on header + visible text; attribution weakest here (honest limit). |
| **SMS/RCS** (Google Messages `com.google.android.apps.messaging`) | Standard list rows; content-description "Received/Sent at <time>"; header = contact/number. |

General algorithm (a small per-package extractor table, keyed by `viewIdResourceName`
suffix + content-description prefixes, with a generic fallback):
1. `app` = friendly name from `packageName` (B.3 mapping).
2. Walk the tree, classify each text node by role: **header/title** (window title
   or header view id), **sender label**, **message bubble**, **timestamp/date
   divider**.
3. For the bubble that changed (the event source / newest visible), derive
   `direction = child|other` from its view id / content-description prefix; set
   `from_minor = (direction == child)`.
4. `thread_id` = stable per-conversation key (B.2).
5. `sender_display` = the header contact name (1:1) or the group bubble's sender
   label (group); `counterparty` = header name; `timestamp` from the bubble's
   content-description if present, else capture time.

> The same role table answers attribution for the Windows UIA path (UIA exposes
> `Name`/`AutomationId`/`ControlType`, analogous to text/viewId/role) and the
> macOS/Linux OCR path (no tree — attribution falls back to window title + spatial
> heuristics; honest weaker limit, B.5).

### B.2 Stable thread id

Replace the current `hashCode`-prone key with a stable composite:
`thread_id = "<pkg>:<normalized-conversation-key>"`, where the conversation key
is, in preference order: the header contact/group title (normalised, lowercased,
diacritics-stripped) → a per-app conversation view id → window title. This keeps
`bulwark-text`'s cross-message thread state correlating correctly
(secrecy→platform-switch→image-request escalation depends on a stable
`thread_id`). The key is a *non-reversible label*, not message content.

### B.3 Friendly app name

`packageName → display name` via a bundled static map for the `MONITORED` set
(e.g. `com.whatsapp → "WhatsApp"`, `org.thoughtcrime.securesms → "Signal"`,
`com.facebook.orca → "Messenger"`, `com.instagram.android → "Instagram"`,
`org.telegram.messenger → "Telegram"`, `com.snapchat.android → "Snapchat"`),
with `PackageManager.getApplicationLabel` as a runtime fallback for anything else.
The raw package id is retained for audit but the guardian sees the friendly name.

### B.4 The attributed-alert data model and its privacy-preserving flow

**Capture-time attribution struct (Kotlin side, on-device, transient):**
```
AttributedCapture {
  packageName: String          // com.whatsapp
  appName: String              // "WhatsApp" (friendly, B.3)
  threadId: String             // stable conversation key (B.2)
  direction: Direction         // CHILD (outbound) | OTHER (inbound) | UNKNOWN
  senderDisplay: String?       // header name or group sender label (NOT the child's PII beyond display)
  counterparty: String?        // the other party in the thread
  capturedAtEpochMs: Long
  // raw text is passed to the bridge for analysis but NEVER stored/forwarded
}
```

**Mapping onto the existing wire types (no new proto needed for the core):**
- `TextSpan` already carries `app` (set to `packageName`/appName), `thread_id`,
  and **`from_minor`** (set from `direction == CHILD` — today hard-coded false; this
  is the wiring to do). The raw text goes only into `TextSpan.text`, consumed
  in-process by `bulwark-text` and dropped.
- The bridge call `analyzeText(app, threadId, text)` should be extended (or a
  sibling `analyzeMessage`) to also pass `direction`/`senderDisplay`/`counterparty`/
  `ts`, so the JNI bridge can populate `TextSpan.from_minor` and stamp the alert.
- The verdict the bridge returns to Kotlin stays **content-free**
  (`verdict_json`): `category`, `action`, `score`, `report`, `fired_categories`,
  and `redacted_context` (the policy `reason`, never the analyzer's raw excerpt).
  Attribution is *metadata*, so it can ride the content-free path safely.

**Alert shape (`bulwark_proto::AlertEvent`) — attribution fields already present:**
- `app` ← friendly app name. `device_id`, `child_id`, `family_id` route it to the
  right guardian. `ts` ← capture time. `category`/`severity`/`kind` from policy.
  `redacted_context` ← content-free policy `reason` (+ a content-free attribution
  summary like "WhatsApp · from the other party · thread 'Alice'"). `evidence`
  stays hash/thumbnail-only.
- **Suggested additive proto fields** (optional, content-free) so the guardian sees
  full attribution without leaking text: `sender_role` ("child"|"other"|"unknown"),
  `sender_display`, `thread_label`. These are labels, not message content; they
  obey the same "no raw content" invariant.

**Privacy invariants preserved end-to-end:**
- Raw message text is analysed on-device and **never stored, never sent** — only a
  redacted/content-free verdict + attribution metadata leaves the device.
- CSAM stays redacted: `redact.rs::redacted_excerpt` withholds the text; the
  bridge already refuses to forward the analyzer's text excerpt for any rule.
- The fired-rule names ("secrecy", "platform_switching", "image_request") explain
  *what* tripped without reproducing *what was said*. Digits are masked for the
  adult-text excerpt path.
- `from_minor`/`direction` is a coarse child-vs-other flag, not identity capture of
  third parties beyond the display name the app already renders on the child's
  screen (consented, transparent — `on-device-scanning.md` boundary).

### B.5 iOS / Windows / macOS equivalents and honest limits

| Platform | Mechanism | Attribution quality | Limit |
|---|---|---|---|
| **Android** | AccessibilityService tree | **High** — package + view ids + content-description give app, sender role, thread, time | Some apps (Signal/Snapchat) sparsely label; group sender mapping is per-app-version |
| **Windows** | UI Automation (`Name`/`AutomationId`/`ControlType`) + OCR fallback | Medium-high — UIA mirrors the a11y tree for native/Electron apps | Some Electron/canvas apps expose only OCR → header+spatial heuristics |
| **macOS** | Vision OCR (needs Screen-Recording permission) | Medium — window title + spatial layout; no structured tree | Visible permission required; attribution is heuristic |
| **Linux (X11)** | OCR of foreground window | Medium — window title + spatial | No structured tree |
| **iOS** | — | **None** | Apple forbids 3rd-party screen/message reading. Falls back to the network content filter only; attribution limited to what TLS inspection reveals (host/app from SNI, never E2E content) |
| **ChromeOS** | — | **None** | Sandbox forbids it; network filter only |

`SourceChannel::OcrOnscreen` / `Notification` already model the on-device input in
the proto. iOS/ChromeOS coverage limits must be stated plainly in the parent
console's coverage matrix (as `on-device-scanning.md` already commits to).

### B.6 Attribution gaps — ordered work

1. **Per-app extractor table** keyed by `viewIdResourceName` + content-description
   prefixes; replace `collectText`-everything with role-classified extraction
   (header / sender / bubble / timestamp).
2. **Direction → `from_minor`.** Derive child-vs-other and set `TextSpan.from_minor`
   (today always false); pass `direction`/`senderDisplay`/`ts` across the JNI
   bridge.
3. **Stable `thread_id`** (B.2) replacing the `hashCode` fallback.
4. **Friendly app-name map** + `PackageManager` fallback (B.3).
5. **Additive content-free `AlertEvent` fields** (`sender_role`, `sender_display`,
   `thread_label`) and surface them in the guardian alert.
6. **Wire the verdict→alert queue** (shared with A.6 item 5) so attributed alerts
   actually reach the guardian app, locally and via the cluster.

All of the above keep the non-negotiable boundary: transparent, consented,
on-device safety classification — no covert capture, no raw-content exfiltration,
CSAM blocked-and-hashed-only.
