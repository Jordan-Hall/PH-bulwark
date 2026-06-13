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
3. **Remote push (roadmap)** — when the guardian is on a *separate* device, the
   server cluster relays the alert via **self-hosted UnifiedPush** (FOSS; no
   Google/Apple) to the parent's registered endpoint URL
   (`RustBridge.registerParentPushToken`). The device's UnifiedPush distributor
   (e.g. ntfy) supplies the endpoint URL; the server just HTTP-POSTs the redacted
   payload to it — no service account, no project id, no OAuth.

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
