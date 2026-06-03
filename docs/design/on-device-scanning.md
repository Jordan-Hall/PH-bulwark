# On-device scanning (E2E / pinned-app coverage)

The network filter (proxy/VPN) can't see inside end-to-end-encrypted or
certificate-pinned apps. To cover that gap, Aegis can scan content **on the
device, after decryption, on screen** — transparently and with the child's
awareness. This is content-safety scanning, **not** covert surveillance.

## Boundary (non-negotiable)

- **Transparent + consented + child-aware.** The child's device shows that Aegis
  is active. No hidden capture, no keylogging, no exfiltration of raw content.
- Only **safety classification** runs locally (grooming rules / NSFW); the same
  no-raw-media + redaction invariants apply. Suspected **CSAM is never previewed,
  transmitted, or stored** — blocked + hashed only.
- **No auto-reporting.** Flagged content (including CSAM) is blocked and surfaced
  to the guardian; the tool does **not** report to any authority — that is a human
  / legal decision. The `report` policy flag is inert by design.

## Per-platform feasibility (honest)

| Platform           | Mechanism                              | Viable? |
|--------------------|----------------------------------------|---------|
| Android            | AccessibilityService (on-screen text)  | Yes     |
| Windows            | UI Automation / OCR of foreground text | Yes     |
| Linux (X11)        | OCR of foreground window               | Yes     |
| macOS              | Vision OCR — needs Screen-Recording permission | Yes (visible permission) |
| iOS                | —                                      | No (Apple forbids 3rd-party screen/message reading) |
| ChromeOS           | —                                      | No (sandbox forbids it) |

`SourceChannel::OcrOnscreen` / `Notification` already model this input in the
proto; `aegis-agent` holds the conventional OCR/accessibility seam. iOS/ChromeOS
fall back to the network content filter only — stated plainly in the parent
console's coverage matrix.

## Status

Not built this wave. It is powerful + dual-use, so it ships only behind explicit,
visible consent and platform permission prompts — never silently enabled.

---

# Appendix: video-segment review

A related capability that **is** wired (`aegis-video::SegmentStore`): when a video
segment is blocked or borderline (BLUR/MUTE/WARN/LOG), the clip is retained
**locally on the guardian's node**, content-addressed by SHA-256
(`blob://<hex>`), so the guardian can play it back in the parent console to
double-check the decision. Constraints enforced at the storage boundary:

- **Suspected CSAM is never stored** — `store_if_safe` rejects
  `Category::CsamSuspected` before any hashing or I/O.
- **Benign `ALLOW` traffic is not archived** — only decisions worth reviewing.
- **Raw clips never ride the alert channel** — the proto `AlertEvent` carries
  only the local `blob://` URI (`local_segment_uri`); `Evidence` stays
  hash/thumbnail-only. The parent app loads the bytes from the local store.
- **Retention/TTL** — confirmed blocks kept ~7 days, borderline ~2 days, then
  `purge_expired()` deletes them.
