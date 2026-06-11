# Bulwark — Threat Model

> Author: agent **B2** (Wave B). Inputs: `PLAN.md` §0c, §3, §5; `docs/research/platform-feasibility.md`;
> `docs/research/model-research.md`. Companion docs: `data-handling.md`, `legal-consent.md`.
>
> **Scope.** Bulwark is a free/OSS Rust client/server child-safety filtering VPN. Thin clients on
> owned/controlled devices intercept traffic and capture on-device text (OCR/accessibility); a
> clusterable backend (LB / worker / all-in-one over gRPC + mTLS, Postgres shared state) runs heavy
> analysis. This model enumerates the **assets**, then per-asset **STRIDE** threats and **concrete
> mitigations**, then the cross-cutting topics called out in the charter.
>
> **STRIDE** = Spoofing · Tampering · Repudiation · Information disclosure · Denial of service ·
> Elevation of privilege.
>
> **This is an engineering threat model, not legal advice.** See `legal-consent.md`.

---

## 0. Trust boundaries & adversaries

```
 [hostile media/network input] ─► bulwark-net (TLS inspection, holds CA key) ─► bulwark-flow ─► sandboxed parsers
                                          │                                            │
 [on-device apps / E2E plaintext] ─► bulwark-agent (OCR/accessibility) ───────────────────┤
                                          │                                            ▼
                                  bulwark-client (mTLS client cert) ══ gRPC/mTLS ══► bulwark-server cluster
                                                                                   (LB ↔ workers, node↔node mTLS)
                                                                                          │
                                                                                   Postgres (shared state, quorum)
                                                                                          │
                                                                                   bulwark-alert (SMTP creds) ─► guardian
```

**Trust boundaries crossed:** (a) hostile network/media input → parsers; (b) device → cluster (network);
(c) node → node within cluster; (d) cluster → Postgres; (e) system → guardian (email); (f) at-rest
storage on every host.

**Adversary classes:**
- **A1 — Network attacker / TLS inspection-on-TLS inspection:** intercepts client↔cluster or node↔node links, or impersonates a node.
- **A2 — Malicious / compromised content:** crafted images, video, audio, fonts, archives designed to exploit a parser. *Bulwark ingests hostile input by design — this is the highest-likelihood code-exec vector.*
- **A3 — Local attacker on a device:** malware/another user trying to steal the CA key, client cert, or plaintext intermediates.
- **A4 — Compromised cluster node / insider:** a worker or operator turning the analysis backend into an exfiltration surface for child PII / plaintext.
- **A5 — Supply-chain attacker:** poisoned crate, poisoned model artifact, typosquat, malicious build.
- **A6 — The monitored minor:** a technically capable child attempting to disable, bypass, or discredit the agent (in scope for evasion/repudiation, **not** for hostile pentest of their own privacy — see legal doc).
- **A7 — Bulwark itself misbehaving:** false negatives that leave a child exposed, or false positives / over-collection that harm the family. Treated as a first-class threat ("the tool is the threat").

---

## Asset 1 — Per-install root CA private key (CROWN JEWEL)

The TLS-inspecting proxy (`bulwark-net`, `hudsucker` + `rcgen`) mints a per-install root CA and installs it into the
device trust store so HTTPS can be decrypted. **Whoever holds this key can transparently impersonate any
website to this device.** It is the single most dangerous secret in the system.

| STRIDE | Threat | Mitigation |
|---|---|---|
| **S** | Attacker forges a cert chaining to our CA → TLS inspections the child's banking/everything. | Key never leaves the host. **No network egress of the key, ever** (not even to the owner's cluster — leaf certs are minted locally). One CA per install (see §"No shared CA"). |
| **T** | Malware tampers with the trust store to add its own root alongside ours. | Out of Bulwark's control once OS trust store is writable by admin, but: log CA fingerprint at startup, surface installed-root inventory in the UI, alert on unexpected roots. |
| **R** | No record of who/when the CA was created or rotated. | Append CA create/rotate/revoke events to the **audit log** (Asset 6) with timestamp + host identity. |
| **I** | **Key exfiltrated from disk.** Primary loss scenario. | Store the private key **wrapped by a hardware/OS keystore**, never as a plaintext file: <br>• **Windows:** DPAPI (`CryptProtectData`, machine+user scope), **TPM-backed where a TPM is present** (CNG `Microsoft Platform Crypto Provider`, key non-exportable). <br>• **Android:** **Android Keystore** (StrongBox/TEE when available), key flagged non-exportable, optionally `setUserAuthenticationRequired`. <br>• **macOS:** **Keychain** as a non-exportable key, Secure Enclave when available. <br>• **Linux gateway:** TPM 2.0 via `tpm2-tss` if present; else kernel keyring + root-only file `0600`, documented as a weaker tier. <br>Key marked **non-exportable**; signing happens inside the keystore, the raw key bytes never enter Bulwark address space. |
| **D** | Keystore unavailable (TPM cleared, profile reset) → proxy can't sign → no filtering. | **Fail-closed** for new TLS interception (don't silently pass traffic unfiltered); see §Fail-open/closed. Detect missing key → block + alert + prompt re-provision. |
| **E** | Stolen CA used to escalate: phishing, credential capture, code-signing-trust abuse. | Same as **I** mitigations + **rotation** + scoped lifetime (below). Treat any suspected key exposure as full re-provision (revoke + regenerate + re-install). |

**Rotation & lifecycle (charter requirement):**
- Generate CA at install with a **bounded validity** (e.g. ≤ 2 years) and a documented rotation procedure.
- **Rotation = generate new CA in keystore → install new root → re-sign leaf cache → remove old root from trust store → wipe old key from keystore.** Overlap window kept short; rotation is logged.
- **Revocation/uninstall MUST remove the root from the OS trust store.** Orphaned roots left in a trust store after uninstall are a latent TLS inspection backdoor — this is a release-blocker test case.
- On **suspected compromise**: immediate revoke + regenerate + re-install + audit-log entry + guardian notification.

**Why NO shared / baked-in CA (non-negotiable):**
- A single CA embedded in the OSS binary would mean **every Bulwark install on Earth shares one private key**. The key is in the public repo or trivially extracted from any binary → anyone could TLS inspection **any** Bulwark user.
- It would also let one compromised install pivot to all others.
- Therefore the CA is **generated locally, per install, stored only in that host's keystore, never transmitted**. This is stated in `PLAN.md` §3 and is a hard invariant. Reviewers must reject any code path that ships, bakes in, or transmits a CA private key.

---

## Asset 2 — Per-device client mTLS certificate (+ cluster CA)

Each device gets its own client cert (`rcgen`, key in DPAPI/Keystore/Keychain) to authenticate to the
cluster over mTLS; nodes authenticate to each other with a **separate cluster CA**. (Distinct from Asset 1
— that CA signs *website* leaf certs for interception; this PKI authenticates *cluster membership*.)

| STRIDE | Threat | Mitigation |
|---|---|---|
| **S** | Rogue device/node joins the cluster and pulls work (= plaintext intermediates + PII). | **Mutual** TLS — both sides verify. Workers/LB require a valid client cert signed by the deployment's cluster CA; node↔node certs signed by the cluster CA. No anonymous joins. SWIM gossip (`foca`) members must also present valid mTLS — gossip is not a trust bypass. |
| **T** | Downgrade / weak-cipher negotiation. | `rustls` only, **TLS 1.3** floor, modern cipher suites, no plaintext fallback. Pin the cluster CA (not public WebPKI) for node/client verification. |
| **R** | Can't tell which device produced a given request. | Bind each request's identity to the client-cert subject; record it in the audit log. |
| **I** | Client-cert key stolen from a device → attacker submits captures / receives verdicts as that device. | Key non-exportable in keystore (as Asset 1). Short-lived certs + renewal. **Revocation list / short TTL** so a lost device is cut off. |
| **D** | Flood of handshakes / connection exhaustion on LB. | Connection limits, rate-limit per client identity, `tonic` concurrency caps, health-gated admission. |
| **E** | Compromised low-trust client tries to act as a worker or admin. | **Role-scoped certs** (client vs worker vs lb vs admin); authorization checks per RPC, not just authentication. A client cert cannot invoke worker/admin RPCs. |

---

## Asset 3 — Plaintext analysis intermediates (OCR text, decoded frames, decoded audio, demuxed video)

To filter, Bulwark necessarily produces **plaintext**: decrypted HTTPS bodies, decoded image/video frames,
demuxed audio, and **OCR'd text of E2E chats** (the on-device answer for Signal/WhatsApp/iMessage). The
cluster *sees these by design* (`platform-feasibility.md` §6). **This is both the product and the biggest
privacy/liability surface.**

| STRIDE | Threat | Mitigation |
|---|---|---|
| **S** | — | (covered by Asset 2 mTLS — only authenticated devices submit/receive). |
| **T** | Intermediate altered in flight → wrong verdict. | mTLS integrity on the wire; verdicts carry the analyzed-content hash. |
| **R** | Dispute over what was analyzed. | Audit log records **hashes + verdict + model id/version**, never the plaintext itself (see Asset 6 + `data-handling.md`). |
| **I** | **Plaintext persisted or leaked** → catastrophic (could include CSAM, intimate images, a child's private messages). | **In-memory only.** Hard rules (enforced in `bulwark-store` and reviewed everywhere): <br>• Never write decoded frames / explicit imagery / raw OCR plaintext to disk, swap, or logs. <br>• Zeroize buffers after analysis (`zeroize` crate); avoid `Debug`/`Display` that prints content. <br>• **Disable swap / lock pages** for buffers holding intermediates where the OS allows (`mlock`), or run on swap-encrypted hosts. <br>• Crash dumps disabled / scrubbed (no core dumps containing media). <br>• Evidence emitted downstream = **hashes, safe redacted thumbnails, short text snippets only** — never the raw artifact (`data-handling.md`). |
| **D** | Backpressure: heavy media stalls workers, latency-critical filtering misses. | Bounded queues, drop-to-fail-safe policy, offload heuristics in `bulwark-infer` (device caps + RTT + queue depth). |
| **E** | A hostile media parser (see Asset 7) escapes and reads other flows' plaintext in shared worker memory. | **Sandbox + process isolation per parse** (§Sandboxing). One tenant's plaintext must not be reachable from a compromised parser. |

---

## Asset 4 — Alert email credentials (SMTP / Gmail OAuth)

`bulwark-alert` emails the guardian on intervention / suspected grooming (`lettre` SMTP, optional Gmail API).
Credentials let an attacker read sent-alert metadata, send spoofed alerts, or pivot into the guardian's mailbox.

| STRIDE | Threat | Mitigation |
|---|---|---|
| **S** | Attacker sends fake "all clear" / fake alerts to the guardian. | Alerts sent only by the local `bulwark-alert` instance; consider signing alert bodies / a per-install shared secret the guardian can verify. |
| **T** | Tamper with alert content (suppress a real grooming alert). | Rate-limit + **digest with sequence numbers** so a gap is detectable; missing-heartbeat alert. |
| **R** | — | Log alert-send events (metadata only) in the audit log. |
| **I** | **SMTP password / OAuth token stolen.** | Store in the **OS keystore** (DPAPI/Keychain/Keystore), never plaintext config. Prefer **OAuth with narrow scope** (Gmail send-only) over a stored password; prefer app-passwords over primary creds. No creds in logs, env dumps, or telemetry (there is no telemetry). |
| **D** | Alert channel flooded → guardian tunes out / provider rate-limits. | Rate-limit + coalesce into digests; severity tiers; local fallback (UI badge) if email fails. |
| **E** | Token reused to access the full mailbox. | Least-privilege scope; short token TTL + refresh; revoke on uninstall. |

---

## Asset 5 — Child PII (identity, message content, browsing, location-ish metadata, evidence)

The whole point is observing a minor — so Bulwark aggregates an unusually sensitive corpus about a child.
**Over-collection is itself a harm** (legal + ethical). See `data-handling.md` for classification/retention
and `legal-consent.md` for lawful basis.

| STRIDE | Threat | Mitigation |
|---|---|---|
| **S** | Wrong child's data attributed (multi-child household). | Per-device / per-profile identity; never cross-attribute. |
| **T** | Evidence altered → false accusation. | Evidence = content-addressed (hash) + audit-logged + signed where feasible. |
| **R** | Guardian or system disputes what was collected. | Audit log of *what categories* were collected and *why* (which rule/threshold fired). |
| **I** | **PII leaked / exfiltrated / subpoenaed beyond intent.** | **Data minimization** (collect only what a verdict needs), **local-only by default**, offload only to **the owner's own cluster**, **no telemetry, no vendor backhaul** (`PLAN.md` §3). Encryption at rest (Asset 6). Short retention + auto-purge (`data-handling.md`). |
| **D** | Store fills / corrupts → loses legitimate evidence. | Bounded retention, integrity checks, encrypted backups under guardian control only. |
| **E** | Aggregated child profile used to *profile/track* the child beyond safety scope ("the tool is the threat"). | Purpose limitation enforced in code (PII only flows to alerting/review, not analytics); **no behavioral profiling**; age-appropriate-design (`legal-consent.md`). |

---

## Asset 6 — Audit log

Records security-relevant events: CA create/rotate/revoke, cert issue/revoke, node join/leave, config
changes, verdicts (hashes + model version), alert sends, data-purge events. **Both** a defense (forensics,
non-repudiation) **and** a target (tampering hides an attack; over-logging leaks PII).

| STRIDE | Threat | Mitigation |
|---|---|---|
| **S** | Forged log entries. | Entries written only by trusted components, identity-bound. |
| **T** | Attacker edits/deletes log to cover tracks. | **Append-only**, hash-chained / tamper-evident (each entry includes hash of prior). Optional off-host write to a second store the worker can't rewrite. |
| **R** | "It wasn't logged." | Log all security-relevant events listed above; chain makes gaps detectable. |
| **I** | **Audit log itself leaks PII** (e.g. someone logs OCR plaintext "for debugging"). | **Audit log stores metadata + hashes + verdict + reason codes only — NEVER plaintext content, NEVER explicit media, NEVER raw OCR.** This is a review checklist item. Encrypt at rest. |
| **D** | Log volume DoS / disk fill. | Bounded size, rotation, rate-limited event classes. |
| **E** | Read access to logs used to reconstruct a child's life. | Access-controlled; encrypted at rest; minimal content by construction. |

**Encryption at rest for Assets 5 & 6** (and any persisted state): **SQLCipher** for the client encrypted
SQLite store, and `age`-encrypted exports/backups; Postgres on the cluster with at-rest encryption +
restricted access. Keys held in the OS keystore. (Details in `data-handling.md`.)

---

## Asset 7 — Hostile-media parsers (the ingest surface) — and their sandbox

Not a stored secret, but the **highest-likelihood remote-code-execution surface**: `bulwark-flow`,
`bulwark-vision`, `bulwark-audio`, `bulwark-video` (ffmpeg), and image/OCR decoders all parse **attacker-controlled
bytes**. A malicious JPEG/MP4/font/codec can carry a memory-corruption exploit. `PLAN.md` §2 mandates these
run as **sandboxed worker processes**.

| STRIDE | Threat | Mitigation |
|---|---|---|
| **T/E** | Crafted media exploits a parser (esp. C/C++ codecs, ffmpeg, Tesseract, image libs) → code exec on a worker. | **Process-isolate each parse** + sandbox: <br>• **Windows:** **AppContainer** (low integrity, no network, no FS beyond a temp scratch). <br>• **Linux:** **seccomp-bpf** syscall allowlist + namespaces + `no_new_privs` + dropped caps; landlock for FS. <br>• **Android:** isolated process; rely on app-sandbox + minimal permissions. <br>• **macOS:** App Sandbox / `sandbox_init` profile. <br>Parser process has **no network** and **no secret access** (no CA key, no client cert, no SMTP creds). |
| **I** | Escaped parser reads other flows' plaintext (Asset 3). | One parse = one short-lived process with only its own input mapped in; kill after use; no shared plaintext pool. |
| **D** | Decompression bomb / pathological media stalls or OOMs a worker. | CPU/mem/time **rlimits** per parse, size caps, timeouts, watchdog kill; bounded queues. |
| **R/E (Rust)** | Memory-safety bug in our own code. | `#![forbid(unsafe_code)]` workspace-wide **except audited FFI** (`PLAN.md` §3); FFI boundaries (ffmpeg via `ffmpeg-sidecar` shelled out — keeps GPL/LGPL **and** the C attack surface out of our process) reviewed and fuzzed. |

---

## Asset 8 — The cluster as a system (split-brain & exfiltration surface)

The clustered backend (`bulwark-cluster`/`bulwark-server`) concentrates plaintext + PII from every device.
`platform-feasibility.md` §6 flags **split-brain** and **cluster-as-exfil-surface** as High risk.

**Split-brain (Postgres quorum):**
- SWIM gossip (`foca`) gives membership/health but is **not** the source of truth for "may I accept work."
- **Postgres is the quorum / source-of-truth.** A node that **loses its Postgres heartbeat/lease stops accepting work** (fail-closed) rather than operating on a stale partition and producing divergent or duplicate verdicts.
- Stateless workers (no sticky routing) → a partitioned node can be drained/killed without losing in-flight integrity; work re-queues.
- Test partitions explicitly (Tier-1 spike #4 in feasibility): kill links, verify the minority side stops accepting work and the majority continues.

**Cluster as exfiltration surface (A4 — compromised node / insider):**
- The cluster sees decrypted everything. A malicious worker or operator is the worst realistic leak.
- Mitigations: deploy on **owner-controlled hardware only** (no third-party/SaaS backend in the default/OSS posture); **in-memory-only** intermediates (Asset 3); **no telemetry / no egress** except verdicts back to the owner's devices and alerts to the owner; **least-privilege** node roles + per-RPC authz (Asset 2); **audit log** of node joins and data access; network policy so workers have no outbound internet except the alert channel and model fetch (checksum-pinned).
- **Honest limitation:** a fully compromised node with legitimate keys can read what it processes. The defense is small TCB, isolation, owner-controlled deployment, and audit — not a guarantee. Documented in `data-handling.md`.

---

## Cross-cutting

### Supply chain (A5)
- **`cargo-deny`** (license allowlist — MIT/Apache/BSD/LGPL-with-isolation only — **and** advisory/RUSTSEC gate) + **`cargo-audit`** in CI; build fails on a flagged advisory or disallowed license (`PLAN.md` §3).
- **Pinned dependencies** (`Cargo.lock` committed); review on bump; minimize transitive surface.
- **Model artifacts checksum-pinned** (SHA256 in `bulwark-core`; reject mismatch on load — `model-research.md`). Fetch over TLS from a pinned source; models are untrusted-until-verified inputs.
- No build scripts / proc-macros from unaudited crates without review; reproducible builds where feasible; signed releases.

### Fail-open vs fail-closed (explicit policy — charter)
Different subsystems get **different** defaults, by design:

| Subsystem | Default | Why |
|---|---|---|
| **CA key missing / TLS interception can't sign** | **Fail-CLOSED** (block, alert, re-provision) | Silently passing unfiltered traffic defeats the product and hides the failure. |
| **Cluster node lost Postgres quorum** | **Fail-CLOSED** (stop accepting work) | Prevents split-brain divergent verdicts. |
| **Hostile parser timeout / crash** | **Fail-CLOSED for that item** (treat as suspicious / block-or-flag), kill process | Don't let a crash become a bypass. |
| **Cert-pinned / E2E app where TLS inspection is impossible** | **Fail-OPEN + log + coverage dashboard** | Per `platform-feasibility.md` §5: blocking all pinned apps is too disruptive for parental control; be **honest about the coverage gap** instead. Fall back to on-device OCR where possible. |
| **QUIC/HTTP3** | **Downgrade** (block UDP/443 → TCP fallback), per-app allowlist for non-fallback apps | Inspectable path preferred; documented. |
| **Analysis backend unreachable (mobile, offload path down)** | Configurable; **default = local tiny-model first-pass + log gap**, do not hard-block the device | Availability vs coverage trade-off, surfaced honestly. |

**Principle:** fail-safe means *child-safe*, but never at the cost of silently pretending to filter when we
aren't, and never by bricking a child's device for unrelated reasons. Where we can't filter, we **say so**
(coverage dashboard) rather than fail silently — that honesty is a security property here.

### "The tool is the threat" (A7)
Bulwark is designed to surveil a child. Misuse, over-collection, false accusation, or use against a
non-minor / on a non-owned device are treated as in-scope harms. Mitigations live in `data-handling.md`
(minimization, retention, no telemetry) and `legal-consent.md` (lawful basis, consent, disclosure,
age-appropriate design, "not legal advice" review gate).

---

## Residual risks (accepted / documented, not solved)
1. **Compromised node with valid keys** can read what it processes (Asset 8) — mitigated, not eliminated.
2. **E2E/pinned coverage gap** — OCR/accessibility only sees on-screen text; some content is never observed (`platform-feasibility.md` §3/§5).
3. **Local admin malware** on a device can attack the keystore at the OS level — outside Bulwark's control.
4. **OS trust-store hygiene** depends on clean uninstall removing our root — covered by a release-blocker test, but a force-killed/partial uninstall can orphan the root.
5. **CSAM legal exposure** — handled by report-never-archive + in-memory-only, but jurisdiction-specific (see `data-handling.md` + `legal-consent.md`).
