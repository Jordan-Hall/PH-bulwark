# SMS & Call Safety (long-term)

**Status: vision / research phase.** The goal: extend Bulwark beyond apps and the web
to the two oldest channels an abuser can still use — **SMS/MMS** and **phone calls** —
so "is what's being said safe?" is answered there too. The same grooming/abuse detector
(`bulwark-text`) that reads chat and OCR'd text would read SMS text and call
transcripts, and raise the same **redacted, attributed** guardian alerts.

This is deliberately staged and **honest about platform limits**: SMS on Android is
achievable; live call **audio** is heavily restricted on modern OSes and is the hard
part. Nothing here changes the privacy invariants — content-free verdicts, redacted
excerpts, never store raw messages, CSAM reported-never-stored.

---

## Why this matters

Grooming and abuse don't stay inside chat apps. An abuser who senses monitoring moves to
**plain SMS** ("text me on my number") or **voice calls**, exactly the channels parents
assume are "just the phone." Making Bulwark the device's **default messaging and phone
experience** lets the same safety engine cover them — and detects the classic
platform-switching grooming signal (`bulwark-text`'s `platform_switching` rule) when it
points *off* the monitored apps toward SMS/calls.

---

## Channel A — SMS / MMS (achievable on Android)

Android lets an app become the **default SMS app** (`RoleManager.ROLE_SMS`), a deliberate,
visible user choice that grants full send/receive of SMS/MMS. As the default SMS app,
Bulwark would:

- Render a normal, pleasant SMS inbox (so the child uses it as their texting app — it
  must be a *good* SMS app, not a spy shell).
- Run each inbound/outbound message body through the existing on-device `analyzeText`
  path (`bulwark-text` rules + policy) — **same engine, new source channel**. Add a
  `SourceChannel.SMS` to [`bulwark.proto`](../../crates/bulwark-proto/proto/bulwark.proto).
- Attribute alerts the same way as chat (see
  [`realtime-filtering-and-attribution.md`](realtime-filtering-and-attribution.md)):
  **which number/contact**, child-vs-other-party, timestamp, redacted excerpt only.
- Detect grooming patterns that arrive by text (secrecy asks, image requests, "don't
  tell your parents", a stranger number probing age/location).

Honest limits:

- Being the default SMS app is a **user/guardian choice** at setup (transparent, not
  covert). On a managed (Device Owner) device the guardian can set it during
  provisioning; otherwise the child grants it.
- **RCS** (carrier "chat") is largely Google-Messages/Jibe-controlled and **not**
  available to third-party default SMS apps — so RCS threads fall back to the on-device
  OCR/accessibility path, not this channel. Document the gap honestly.
- **iOS: not possible.** Apple exposes no API to read SMS/iMessage content; the only
  hook is the **Message Filter** extension for *unknown senders* (scam/spam
  categorisation), which never sees known-contact message text. iOS SMS safety is
  therefore limited to unknown-sender scam filtering — state this plainly.

## Channel B — Phone calls (hard; mostly research)

Two layers, very different feasibility:

**B1. Call metadata + screening (feasible).** As the **default dialer / Call Screening**
app (`RoleManager.ROLE_DIALER`, `CallScreeningService`) Bulwark can see caller
number/identity, screen/flag calls from unknown or blocked numbers, and read call logs
(`READ_CALL_LOG`). This catches *who* is calling and unknown-number patterns — useful,
and shippable — but **not what is said**.

**B2. Call content (the hard part).** Understanding *what is said* needs the call audio →
on-device speech-to-text → `bulwark-text`. This is where the OS fights back:

- **Modern Android (10+) blocks third-party call-audio recording.** The old
  `VOICE_CALL`/accessibility recording routes were deliberately closed. So general call
  transcription is **not available** to a normal app.
- Realistic routes, all constrained:
  - **Speakerphone ambient capture** via the mic during a call — low quality, fragile,
    and ethically/legally loaded (two-party-consent law varies — see
    [`../security/legal-consent.md`](../security/legal-consent.md)). Weak.
  - **OEM / managed-device telephony APIs** (Device Owner, specific OEM call-recording
    where the region permits) — the only clean path, device/region-dependent.
  - **Carrier / RCS-side** integration — out of scope for an on-device app.
- Where audio *is* obtainable, the pipeline is: capture → **on-device STT** (capability-
  detect; bundled Whisper-class fallback per the on-device-AI-fallback intent) →
  `bulwark-text` → redacted, attributed alert. The transcript is processed **on-device**,
  scored, and **discarded**; only a content-free verdict + redacted excerpt is kept.

Honest stance: **call-content monitoring is aspirational and platform-gated.** Ship B1
(screening/metadata) generally; treat B2 (transcription) as managed-device-only / R&D,
and never pretend stock phones can do it.

iOS: call content is entirely closed; CallKit gives call lifecycle/identity only.

---

## Privacy, consent, legality (non-negotiable)

- **Transparent + consented**, on a guardian-owned device for a minor they guard — same
  rule as the rest of Bulwark. The child can see SMS/calls are covered.
- **Two-party-consent / wiretap laws vary by jurisdiction** and are stricter for voice
  than text. Call-content features must surface a clear legal-consent gate per region
  (see [`../security/legal-consent.md`](../security/legal-consent.md)); default **off**.
- Same data invariants: **no raw message/transcript stored**, content-free verdicts,
  redacted excerpts only, CSAM flagged-never-stored.

---

## Staged plan

1. **SMS read-path (Android):** `SourceChannel.SMS`; default-SMS-app shell with a real
   inbox; route message bodies through `analyzeText`; attributed redacted alerts.
2. **Call screening (Android):** default-dialer/`CallScreeningService` for caller
   identity + unknown-number flagging + call-log signals (metadata only).
3. **Call transcription (managed/R&D):** on-device STT on call audio **only** where the
   platform/region permits (Device Owner / OEM), behind an explicit legal-consent gate;
   transcript scored on-device and discarded.
4. **iOS honesty pass:** ship the Message Filter unknown-sender scam categorisation;
   document that known-contact SMS and call content are not accessible.

See [`../../PLAN.md`](../../PLAN.md) for where these phases sit, and
[`realtime-filtering-and-attribution.md`](realtime-filtering-and-attribution.md) for the
shared detector + attribution model these channels feed.
