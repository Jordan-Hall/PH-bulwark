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

**Native receive (Android) — LANDED (#151, 2026-06-13):**
The earlier pass deferred this on the belief that dx 0.8-alpha "exposes no
source-overlay / custom-manifest hook." That was **wrong for the pinned
`dioxus-cli-0.8.0-alpha.0`**, which DOES expose committed-source seams (verified
against the CLI source — `src/build/android.rs` + `src/config/app.rs`):

- `[application].android_manifest` → dx uses our `AndroidManifest.xml` **verbatim**
  (android.rs:264-271; the doc-comment's "merge" is aspirational — it's used as-is).
- `[application].android_main_activity` → dx writes our `MainActivity.kt` **verbatim**
  into `dev.dioxus.main/` and compiles it every build (android.rs:279-291). A Kotlin
  file may hold several top-level classes, so the receive side rides along in it.
- `[android].gradle_dependencies` → rendered into the app `dependencies {}` block.

So no dx fork and no post-build manifest hack are needed. The implementation
(`apps/parent/android/` + `Dioxus.toml`):

1. **`gradle_dependencies = ["org.unifiedpush.android:connector:3.0.10"]`** — the
   FOSS **Apache-2.0** UnifiedPush Android connector (no Google/Apple). NOTE: the
   modern 3.x connector delivers via a bound **`PushService`** — the old
   `MessagingReceiver` BroadcastReceiver is **deprecated upstream** (the library
   embeds its own exported receiver that forwards distributor intents to your
   service via `org.unifiedpush.android.connector.PUSH_EVENT`). The AAR's library
   manifest also contributes the package-visibility `<queries>` + that internal
   receiver, which AGP merges at build, so our verbatim manifest only declares OUR
   `<service>` + `POST_NOTIFICATIONS`.
2. **`MainActivity.kt`** (custom) — extends `WryActivity`, and in `onCreate`
   creates the alert `NotificationChannel`, requests the `POST_NOTIFICATIONS`
   runtime grant (API 33+), and calls `UnifiedPush.tryUseDefaultDistributor` →
   `register` so a `NEW_ENDPOINT` is actually delivered (graceful no-op when no
   distributor is installed). A second top-level class `BulwarkPushService :
   PushService()` handles the events:
   - **onNewEndpoint** → writes the endpoint URL to `filesDir/bulwark/push_endpoint.txt`
     — the SAME app-private path the Rust side's `app_config_dir()` resolves over
     JNI. No JNI callback into the (often-dead) Rust process is needed; the
     Notifications panel's `saved_push_endpoint()` reads it on mount.
   - **onMessage** → posts a **content-free** system notification (a fixed generic
     line, never a field from the payload), honouring the privacy invariant.
3. **`AndroidManifest.xml`** (custom) — the dx-rendered template (captured from a
   real `dx build` under `target/dx/…`) plus exactly `POST_NOTIFICATIONS` and the
   `<service android:name="dev.dioxus.main.BulwarkPushService" android:exported="false">`
   with the `PUSH_EVENT` intent-filter (fully-qualified name — the namespace
   `co.predatorhunters.bulwark.manager` differs from the `dev.dioxus.main` package).

**Guardian-auth is unchanged.** Acquiring an endpoint only writes the handoff file;
the token-gated `Review.RegisterPushTarget` RPC stays behind `NATIVE_PUSH_ENABLED`
(#140). The Rust registration/redaction code above is untouched — only the
endpoint-acquisition + notification-display layer was added, in committed Kotlin.

Desktop has no UnifiedPush distributor concept, so there the endpoint URL is still
pasted by hand in the Notifications card; registration + server relay work the same
with a manually-supplied endpoint.

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
