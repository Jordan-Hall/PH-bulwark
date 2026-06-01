# Aegis — Legal Basis, Consent & Disclosure

> Author: agent **B2** (Wave B). Inputs: `PLAN.md` §0c, §5; `docs/research/platform-feasibility.md`
> §3/§"Unresolved"; `docs/research/model-research.md`. Companion docs: `threat-model.md`,
> `data-handling.md`.
>
> ## ⚠️ NOT LEGAL ADVICE
> This document is engineering/product guidance written by a software agent. It is **not legal advice**.
> Surveillance, wiretap, child-data, and CSAM laws **vary enormously by jurisdiction and change over
> time**. **A qualified lawyer must review deployment for each target jurisdiction before any release or
> commercial offering.** Where this doc and a lawyer disagree, the lawyer wins. Several items below are
> **open questions routed to per-jurisdiction legal review** (`platform-feasibility.md`).

---

## 1. Intended lawful basis

Aegis's intended, defensible use:

> **A legal guardian monitoring their own minor child, on devices the guardian owns or lawfully
> controls, for the child's safety.**

This is the basis on which mainstream parental-control products (Bark, Net Nanny, Qustodio, Apple/Google
Family) operate. Aegis is built to stay within it (`PLAN.md` §0c):

- **Guardian + minor + owned/controlled device** — all three required. Remove any one and the lawful
  basis is in doubt.
- **Safety purpose only** — not general surveillance, not profiling, not data resale (Aegis has no
  telemetry/analytics path — `data-handling.md`).
- Built-in guardrails enforce the posture: minimization, local-only-by-default, short retention,
  redaction, no archival of explicit content.

**Out of scope / disallowed uses** (the build, docs, and consent flow must discourage and not facilitate):
monitoring **adults** (partners/employees) without their consent; monitoring a child the deployer is **not**
guardian of; deployment on devices the deployer does **not** own/control; covert stalkerware. These uses can
be **criminal** (wiretap, computer-misuse, stalking laws). Aegis is not a stalkerware toolkit.

---

## 2. Wiretap / two-party-consent caveats (the sharp edge)

The hardest legal exposure is **interception of communications**, and it is sharpest exactly where the
product is most novel: **on-device OCR / accessibility capture of E2E plaintext** (Signal, WhatsApp,
iMessage, Messenger secret) — the answer to E2E from `platform-feasibility.md` §3.

Key tensions for legal review:

- **Wiretap / interception statutes** (US federal ECPA + **state two-party-consent** regimes — CA, FL, IL,
  WA, etc.; UK Investigatory Powers / RIPA; EU ePrivacy + national wiretap law) regulate intercepting
  communications. A child's chat involves a **second party** (the other person) who is **not** the
  guardian and has **not** consented.
- **Parental-consent / vicarious-consent doctrine** (US) has been used to justify a guardian consenting on
  behalf of a young minor, but it is **fact-specific, not uniform across states, and weaker for older
  minors**. It is **not** a guaranteed shield, and its reach over the **other party's** communications is
  contested.
- **OCR/accessibility capture is still interception of content** for this analysis even though it reads
  the screen *after* decryption rather than cracking the wire. Reading plaintext off-screen does **not**
  automatically sidestep wiretap law — **legal review must confirm per region.** (Flagged in
  `platform-feasibility.md` §"Unresolved".)
- **Two-party-consent jurisdictions** may require the **other** party's consent — generally impossible for
  inbound messages from third parties. This is a **genuine unresolved legal risk**, not an engineering one.

**Engineering consequences (what the build does about it):**
- **Region-aware configuration**: capture scope (esp. E2E OCR/accessibility) is **configurable and
  documented per region**; setup surfaces the wiretap/two-party-consent warning prominently before
  enabling on-device capture (`PLAN.md` §0c — "surfaced in setup docs").
- **Minimize the third-party footprint**: analyze for safety signals, store **derived evidence only**
  (hashes/snippets/redacted), never archive full third-party message content (`data-handling.md`).
- **Honest coverage dashboard** rather than covert capture — transparency is also a legal-posture asset.

---

## 3. Transparency & disclosure

- **To the guardian:** clear documentation of exactly what Aegis captures, what it cannot (E2E/pinned/QUIC
  gaps, coverage dashboard), where data goes (local / owner cluster only, no telemetry), and retention.
- **To the child (age-appropriate):** transparency is both an ethical duty and, under **age-appropriate
  design** regimes (UK AADC / "Children's Code", EU), a likely legal expectation. Covert monitoring of
  one's own child sits in a grayer legal/ethical zone than disclosed monitoring; **disclosed** monitoring
  is the safer and recommended default, scaled to the child's age and maturity. Where covert operation is
  configurable, the documentation must spell out the legal/ethical implications and that some
  jurisdictions may not permit it.
- **CA-install disclosure:** installing a root CA to decrypt HTTPS is a significant act; the installer must
  explain it, and uninstall must remove it (`threat-model.md` Asset 1).

---

## 4. Commercial path — consent flows & app-store compliance

The OSS self-host posture (a parent on their own hardware) is the lowest-risk use. A **commercial offering**
adds duties (`PLAN.md` §0c):

**Consent flows (commercial):**
- **Verifiable guardian identity / consent** at onboarding; attestation that the user is the legal guardian
  and owns/controls the device, with the lawful-basis and jurisdiction caveats shown **before** activation.
- **Disclosure & (age-appropriate) child-facing notice** configuration.
- **GDPR**: identify controller/processor roles, lawful basis (likely consent + legitimate interests of
  child safeguarding, with the special-category/child considerations), DPIA for high-risk child-data
  processing, data-subject rights (access/erasure — hooks in `data-handling.md`), records of processing.
- **COPPA** (US under-13): verifiable parental consent, minimization, no behavioral ads, no data sale
  (Aegis has none of those paths by design), and a clear privacy policy.
- **Age-appropriate design** (UK AADC and analogues): privacy by default, minimization, no profiling beyond
  the safety purpose, transparency, best-interests-of-the-child assessment.

**Android Play Store (the gating one — `platform-feasibility.md` §3):** parental-control VPNs are
**allowed** but require:
- **VPN disclosure** and use of `VpnService` for its stated purpose.
- **Data Safety** declaration consistent with behavior — and crucially **no plaintext exfiltration** off
  the device beyond the owner's control (Aegis: local/owner-cluster only, no telemetry — supports this).
- **AccessibilityService** use justified for the disclosed safety purpose (Google scrutinizes accessibility
  use heavily; misuse → removal).
- A **MASA Level 2** (Mobile Application Security Assessment) by an authorized lab — budget **~12 weeks +
  fee**. This is a **product/commercial gate**, routed here from `platform-feasibility.md` §3/§"Unresolved";
  it is a timeline and cost item for the commercial roadmap, not an engineering blocker for the OSS build.
- **Apple/macOS/iOS** note: network-extension/content-filter entitlements and App Store review impose
  parallel constraints; iOS device-wide MITM is far more restricted than Android/desktop — treat as a
  separate per-platform legal+policy review.

---

## 5. CSAM — legal handling (cross-ref `data-handling.md` §5)

- Suspected CSAM → **flag + redact + documented reporting path (NCMEC CyberTipline / local authority such
  as IWF/NCA in the UK)**; **never archive** explicit bytes (C0 — `data-handling.md`).
- **Mandatory-reporting** duties may attach in some jurisdictions/roles — **legal review required.**
- **PhotoDNA is proprietary/NCMEC-licensed and not usable**; known-hash matching uses **Google CSAI
  Match** (`model-research.md`). Software **flags**; the **CSAM determination and any report is a
  legal/human action**, not an automated one.

---

## 6. Per-jurisdiction review gate (required before deployment)

Before any release / commercial launch in a region, legal review **must** confirm:
1. Lawful basis for guardian monitoring of a minor in that jurisdiction (incl. age thresholds).
2. **Wiretap / two-party-consent** treatment of **on-device OCR/accessibility capture of E2E plaintext**,
   including the **other party's** communications. *(Open question — `platform-feasibility.md`.)*
3. CSAM detection/handling/reporting duties and the legality of momentary handling of such material.
4. Child-data law (GDPR/COPPA/AADC + local), DPIA expectations, and data-subject rights.
5. App-store / platform policy (Play MASA L2, Apple entitlements) for the commercial path.
6. Covert-vs-disclosed monitoring legality and the required child-facing notice.

Until that review passes for a region, **do not deploy there.** This gate is referenced from
`threat-model.md`, `data-handling.md`, and the Wave-A feasibility report.

---

> **Reminder: NOT LEGAL ADVICE.** Engineering guidance only; qualified per-jurisdiction legal counsel
> is required before deployment or commercial offering.
