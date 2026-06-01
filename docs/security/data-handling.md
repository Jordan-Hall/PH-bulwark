# Aegis — Data Handling & Classification

> Author: agent **B2** (Wave B). Inputs: `PLAN.md` §0b, §0c, §5; `docs/research/model-research.md`;
> `docs/research/platform-feasibility.md`. Companion docs: `threat-model.md`, `legal-consent.md`.
>
> Defines **what data Aegis touches, how it's classified, how it's handled, retained, encrypted, and
> reported**. Binding rules use **MUST / MUST NOT** and are enforceable review-checklist items.
>
> **Not legal advice.** CSAM/PII obligations are jurisdiction-specific — see `legal-consent.md`.

---

## 1. Core principles (non-negotiable)

1. **Never persist explicit imagery.** Decoded frames / explicit images / intimate media exist **in
   memory only**, are analyzed, then **zeroized**. They are **never** written to disk, swap, logs,
   crash dumps, backups, or transmitted off the owner's hardware. (`PLAN.md` §0c, §5.)
2. **Evidence = derived artifacts only** — content hashes, **safe redacted thumbnails**, short text
   snippets, verdict + reason code + model version. **Never the raw artifact.**
3. **Local-only by default.** Analysis runs on-device or on the **owner's own cluster**. Offload goes
   **only** to hardware the owner controls. **No telemetry. No vendor backhaul. No third-party SaaS** in
   the default OSS posture. (`PLAN.md` §3.)
4. **PII minimization & purpose limitation.** Collect the **minimum** needed to produce a verdict and an
   actionable alert. Data flows only to alerting + the guardian review UI — **never** to analytics or
   profiling.
5. **Encryption at rest** for everything persisted (evidence, audit log, config secrets).
6. **Report-never-archive** for suspected CSAM (§5).

---

## 2. Data classification

| Class | Examples | Persist? | Encrypt at rest | Leave device/cluster? | Retention |
|---|---|---|---|---|---|
| **C0 — Forbidden to persist** | Decoded explicit frames; intimate/explicit imagery; **suspected CSAM bytes**; raw decrypted HTTPS bodies; raw OCR plaintext buffers; full decoded audio/video | **NEVER** | n/a (in-mem only) | **NEVER** | Zeroized immediately after analysis |
| **C1 — Highly sensitive (derived)** | Safe redacted thumbnails; short flagged text snippets; child PII (name, age/profile); grooming-thread context; perceptual/crypto hashes of flagged media | Yes, minimal | **Yes (required)** | Only to owner's own cluster / guardian | Short, auto-purge (§4) |
| **C2 — Operational secrets** | Per-install CA key; client mTLS key; cluster CA; SMTP/Gmail creds | Key material in **OS keystore only**, never plaintext config | Keystore-protected | **CA key NEVER leaves host**; others scoped | Lifetime of install / rotation |
| **C3 — Metadata / audit** | Audit log (hashes, verdicts, reason codes, model versions, event timestamps); coverage dashboard stats; config | Yes | **Yes** | Owner-controlled only | Bounded, rotated |
| **C4 — Non-sensitive** | App version, model registry checksums, public config defaults | Yes | Optional | n/a | n/a |

**Hard rule:** if data is **C0**, no code path may write it anywhere persistent or send it anywhere.
This is reviewed in every crate that touches media or decrypted content (`aegis-net`, `aegis-flow`,
`aegis-vision`, `aegis-audio`, `aegis-video`, `aegis-agent`, `aegis-store`, `aegis-alert`).

---

## 3. Handling rules by lifecycle stage

### Capture / decode (C0 created here)
- Decoded frames, demuxed audio, decrypted bodies, OCR plaintext live in bounded in-memory buffers.
- Hold pages out of swap where the OS permits (`mlock`); disable/scrub core dumps so media can't leak
  via a crash file (cross-ref `threat-model.md` Asset 3).
- Parse hostile media in **sandboxed, network-isolated, secret-less worker processes** (`threat-model.md`
  Asset 7). The parser never has access to C2 secrets.

### Analyze
- Models/rules consume C0 in memory and emit a **verdict** (block / blur / mute / warn / log) + score +
  reason code + the **content hash** + model id/version. The verdict is C1/C3; the input stays C0.

### Redact / derive evidence (C0 → C1)
- **Imagery:** never store the original. If visual evidence is needed, store a **safe thumbnail** that is
  **blurred/pixelated/redacted so it is not itself explicit** (e.g. heavily downscaled + blurred, or a
  bounding-box-only crop of non-explicit context). When in doubt, store **hash + label only**, no pixels.
- **Text:** store a **short snippet** with PII reduced where feasible (e.g. partial redaction of addresses,
  names of third parties), enough for a guardian to act, not a full transcript dump.
- **Hashes:** crypto hash (identity/dedupe) + perceptual hash (near-dupe / known-bad matching, §5).

### Transmit (offload / verdict return)
- Only over **mTLS** to the **owner's own cluster** (`threat-model.md` Asset 2). C0 may transit in-memory
  to an owner-controlled worker for analysis but is **never persisted** there.
- **No telemetry, no analytics, no third-party endpoints.** The only outbound is: verdicts → owner's
  devices, alerts → guardian (§`aegis-alert`), model fetch (checksum-pinned, TLS).

### Persist (C1/C3 only)
- Client: **encrypted SQLite via SQLCipher** (`aegis-store`). Cluster shared state: **Postgres with
  at-rest encryption** + restricted access. Exports/backups: **`age`-encrypted**, keys in the owner's
  control.
- Encryption keys in the **OS keystore** (DPAPI / Keychain / Android Keystore / TPM where present),
  never alongside the data.

### Purge
- Auto-purge on the retention clock (§4) and on uninstall: wipe C1/C3 stores, remove C2 keys from the
  keystore, **and remove the per-install CA root from the OS trust store** (`threat-model.md` Asset 1 —
  release-blocker).

---

## 4. Retention

- **Default short retention** with **auto-purge**; guardian-configurable within sane bounds. Suggested
  defaults (tunable, to be confirmed against `legal-consent.md` per-region review):
  - C1 flagged evidence (thumbnails/snippets/hashes): **30 days** then auto-delete, unless the guardian
    explicitly pins an item under review.
  - C3 audit/metadata: bounded ring (size + age cap), rotated.
- **Minimization over retention:** if a verdict doesn't need it, don't keep it.
- **Right to erasure** (GDPR-style) supported: a documented purge that removes a subject's C1 data and
  records the purge event in the audit log (`legal-consent.md`).

---

## 5. CSAM policy (critical)

Aegis may encounter child sexual abuse material. **Mishandling it is both a child-safety failure and a
serious crime.** Rules:

1. **Detect → flag, do NOT archive.** On suspected CSAM, Aegis **blocks/redacts** and records **derived
   evidence only** (hash, redacted/blurred non-explicit thumbnail or hash-only, reason code). The
   **explicit bytes are C0 — never persisted, never transmitted off owner hardware, zeroized after
   analysis.** (`PLAN.md` §0c, §5.)
2. **Documented legal-reporting path.** The system **flags to the guardian** and surfaces a **documented
   reporting path** to the appropriate authority — **NCMEC CyberTipline** (US) or the **local/national
   authority** for the jurisdiction (e.g. IWF/NCA in the UK, national hotlines elsewhere). Aegis provides
   the **path and the derived evidence**; the **reporting decision/action is the guardian's / the
   appropriate authority's**, per jurisdiction. Aegis does not silently transmit content to third parties.
3. **Known-hash matching = Google CSAI Match.** For matching against **known** CSAM, use the **Google
   CSAI Match API** (the redistributable/licensable option per `model-research.md`). Hash matching, not
   content storage.
4. **PhotoDNA is NOT usable.** Microsoft **PhotoDNA is proprietary and NCMEC-licensed — not
   redistributable** and not compatible with a free/OSS project. **Do not integrate or imply PhotoDNA.**
   (`model-research.md` ⚠️ table.) This is a hard constraint for the build team.
5. **Unknown / novel material:** perceptual-hash + the NSFW/age signals can **flag** for human review but
   MUST NOT be treated as a positive CSAM identification by the software — that determination is legal,
   not algorithmic. Flag, redact, route to the documented reporting path.
6. **Legal review required.** CSAM detection, the duty to report, and the legality of even momentarily
   handling such material vary by jurisdiction and may impose mandatory-reporting duties. **Per-region
   legal review is required before deployment** (`legal-consent.md`; `model-research.md`;
   `platform-feasibility.md` §"Unresolved").

---

## 6. Regulatory alignment (engineering hooks; see `legal-consent.md` for the legal layer)

- **GDPR** (where applicable): lawful basis + minimization + storage limitation + integrity/confidentiality
  + right to erasure. Engineering hooks: C-class minimization, short retention/auto-purge, encryption at
  rest, documented erasure, audit log of processing categories. Special-category/child data → highest care.
- **COPPA** (US, under-13): in the commercial path, verifiable parental consent and minimization; no
  behavioral advertising; no selling data (Aegis has **no** ad/analytics/telemetry path by design).
- **Age-appropriate design** (UK AADC / "Children's Code" and analogues): data minimization, privacy by
  default, no profiling/nudging beyond the safety purpose, transparency appropriate to the child's age,
  data-protection-impact-assessment expectation for high-risk child-data processing.

These are **enforced structurally**: no telemetry, local-only-by-default, minimization, short retention,
encryption — so the default posture is the privacy-protective one. Per-jurisdiction specifics and the
DPIA are a `legal-consent.md` / product responsibility.

---

## 7. Build-team checklist (data handling)

- [ ] No code path writes **C0** (explicit media / raw decrypted / raw OCR) to disk, swap, log, crash dump, backup, or network.
- [ ] Intermediate buffers zeroized (`zeroize`); no `Debug`/`Display` prints content; swap/core-dump handled.
- [ ] Evidence emitted is hash / redacted thumbnail / short snippet only.
- [ ] At-rest encryption wired: SQLCipher (client), Postgres at-rest (cluster), `age` (exports); keys in OS keystore.
- [ ] Retention clock + auto-purge + uninstall wipe (incl. CA-root removal from trust store) implemented and tested.
- [ ] **No telemetry / analytics / third-party endpoint** anywhere. Only outbound: owner cluster, guardian alert, checksum-pinned model fetch.
- [ ] CSAM path: flag + redact + documented NCMEC/local report path + CSAI Match for known hashes; **no PhotoDNA**; no archival of explicit bytes.
- [ ] Per-region legal review gate referenced before any deployment (`legal-consent.md`).
