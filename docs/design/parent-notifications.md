# Parent notifications & approve/deny review

The guardian is notified whenever Bulwark steps in or suspects grooming, with the
evidence appropriate to the category, and can (roadmap) **approve** or **deny**
the item.

## Delivery paths
1. **Email** — `bulwark-alert` (SMTP), redacted, exists today (INTERVENTION + GROOMING_SUSPECTED).
2. **On-device notification** — Android `AlertNotifier`: `BulwarkVpnService` polls the
   Rust core (`RustBridge.nextAlert()`) and posts a system notification with the
   evidence + Approve / "Keep blocked" actions. This is the **same-device** path
   (guardian reviews on the child's device, or a shared/family device).
3. **Remote push** — when the guardian is on a *separate* device, the server
   cluster relays the alert via **self-hosted UnifiedPush** (FOSS; no
   Google/Apple) to the parent's registered endpoint URL. The device's
   UnifiedPush distributor (e.g. ntfy) supplies the endpoint URL; the server just
   HTTP-POSTs the redacted payload to it — no service account, no project id, no
   OAuth. The Manager (`apps/parent`) and the child app share the SAME approach.

## Manager (PH Bulwark Manager) remote push — status

The guardian console registers and receives the same way as the child app.

**Implemented but GATED OFF until per-guardian routing (#140):**
- `apps/parent/src/api.rs` — `register_push_target()` is written to call
  `Review.RegisterPushTarget(PushTarget{ device_id, push_endpoint, platform })`,
  authenticated with the guardian's session token as `authorization: Bearer …`
  (the generic `with_bearer<T>` helper, shared with the approve/deny RPC); the
  server REQUIRES it in accounts mode and validates the endpoint (https + public
  host, SSRF guard) — never weakened. **BUT** it is gated behind a compile-time
  `NATIVE_PUSH_ENABLED = false` and does NOT call the RPC yet: today the server's
  `UnifiedPushFanoutSink` POSTs every alert to EVERY registered endpoint
  (`AlertHub::push_tokens`), so enrolling a guardian device would leak other
  families' redacted alerts cross-tenant. The #140 PR adds scoped per-guardian
  fan-out and flips that const — registration then activates with no other change.
- `apps/parent/src/servers.rs` — a per-install **guardian device id** (minted once
  with `ring`'s CSPRNG, persisted; the server keys its push-target map by it so a
  re-registration overwrites rather than accumulates) and a persisted
  `push_endpoint` (per-user, not per-server).
- UI: the Region screen's **Notifications** card (`NotificationsPanel`) lets the
  guardian paste/save their distributor endpoint **on this device**; it does NOT
  auto-register on login and surfaces that remote delivery activates with #140.
  (The signed-APK **distribution** half — `android-release.yml` + fdroid — is
  fully landed and independent of this gate.)

**Deferred (native receive) — the precise gap:**
The Manager is a **`dx`-built Dioxus app**: a thin Android shell that dx
*generates at build time* (from `Dioxus.toml`) around the Rust/wry webview. The
UnifiedPush Android **connector library is Kotlin** and works through a
`BroadcastReceiver` that (a) receives the distributor-supplied endpoint URL via
an Intent (`NEW_ENDPOINT`) and (b) receives each incoming push (`MESSAGE`), then
posts a system notification. Wiring that requires committing custom Kotlin +
manifest `<receiver>`/`<service>` entries into the Android project — but dx
0.8-alpha **regenerates the whole Android scaffold under `target/dx/…` (which is
gitignored) and exposes no source-overlay / custom-manifest-merge hook**. There
is no clean seam to inject the receiver without forking dx's mobile bundler or
post-processing its output, so it is **deliberately deferred** rather than hacked.

Until that lands, the endpoint URL is entered **by hand** in the Notifications
card (the guardian pastes their ntfy topic URL); registration and server-side
relay are fully functional with a manually-supplied endpoint.

**Recommended approach (when picked up):**
1. Preferred — add a dx mobile **Android source-overlay** capability (upstream or
   a local patch) so an `apps/parent/android/` Kotlin dir + a manifest fragment
   merge into the generated project; add the UnifiedPush connector dependency and
   a `BroadcastReceiver` that calls a Rust JNI export to hand the endpoint URL to
   `register_push_target()` and to surface `MESSAGE` pushes as notifications.
2. Alternative — ship the guardian console on Android as a **native shell**
   (mirroring `platform/android`) hosting the Rust core over JNI, where the
   Kotlin receiver lives in committed source — the same pattern the child app
   already uses for its `AlertNotifier`.

Either way the Rust registration/redaction code above is unchanged; only the
endpoint-acquisition + notification-display layer is added.

## Evidence shown — and the hard rules
Driven by `Verdict.category` + `Evidence` (which already carries **only** hashes,
a SAFE thumbnail, or a redacted snippet — never raw media; see
`docs/security/data-handling.md`):

| Category | What the parent sees |
|---|---|
| ADULT_IMAGE / (sampled) VIDEO frame | the **SAFE (blurred/cropped) thumbnail** only (`evidence.safe_thumbnail`) |
| ADULT_AUDIO | category + context (no media) |
| GROOMING | the **redacted text snippet** (`redacted_context`) |
| **CSAM_SUSPECTED** | **NO image, ever.** "Blocked & flagged for reporting." Transmitting it — even to the guardian — is unlawful; it goes to the NCMEC/local report path, not a notification. |

`AlertNotifier` enforces this: it attaches a picture only for non-CSAM categories
and only from `evidence.safe_thumbnail`.

## Approve / deny (roadmap)
Notification actions (and a future Review screen) call
`RustBridge.submitReviewDecision(alertId, approve)` →
`ReviewActionReceiver` → the Rust core → **`bulwark-policy`**, which records the
decision and may allowlist the host / content-hash for this child so the same
item isn't re-blocked. "Deny" confirms the block (and can tighten policy).

### Work to wire it end-to-end
- **proto** (`bulwark-proto`): add a `Review` service —
  `SubmitDecision(ReviewDecision{alert_id, decision: APPROVE|DENY, scope}) -> Ack`,
  `StreamPendingReviews(DeviceFilter) -> stream AlertEvent`, and
  `RegisterPushTarget(PushTarget{device_id, push_endpoint})`.
- **bulwark-policy**: consume `ReviewDecision` → per-child allowlist (host/hash) +
  audit (every override is logged, tamper-evident).
- **bulwark-alert**: add a self-hosted UnifiedPush channel alongside email
  (`UnifiedPushFanoutSink`, behind the `push` feature); redaction unchanged.
- **Android**: JNI exports for `nextAlert` / `submitReviewDecision` /
  `registerParentPushToken` on `bulwark-client` (the `android` feature), a
  UnifiedPush receiver (the distributor hands the app an endpoint URL), and a
  Review screen listing pending items.

## Privacy invariant (unchanged)
No raw message text or explicit media is ever persisted or transmitted. The
parent receives metadata + redacted snippets + safe thumbnails only; overrides
are audited; CSAM is reported, never shown.
