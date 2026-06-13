# FOSS distribution — self-hosted first

PH Bulwark's Android apps are distributed through **fully self-hosted, free and
open-source channels — no Google Play, no proprietary services.** The release CI
(`.github/workflows/android-release.yml`) builds and signs the APKs and attaches
them to a GitHub Release; the three channels below all draw from those signed
assets.

Two shipping APKs (the Manager / `apps/parent` is separate and not covered here):

| App | Package | Release asset | What it is |
|---|---|---|---|
| PH Bulwark (child) | `co.predatorhunters.bulwark` | `app-release.apk` | Guardian-installed child-safety content filter (VpnService + opt-in on-screen text reader). |
| PH Bulwark Camera | `co.predatorhunters.bulwark.camera` | `camera-release.apk` | Local-only safe camera; declares **no** network permission. |

> The asset names `app-release.apk` and `camera-release.apk` are fixed contract:
> they are produced under those exact names by the release workflow and matched
> verbatim by the Obtainium regexes below and the F-Droid mirror. Do not rename
> one without the others.

## Signing

Release APKs are signed in CI only when the four `ANDROID_*` repository secrets
are present (`ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`,
`ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`). Both `:app` and `:camera`
build.gradle self-gate their signing config on these, so an absent keystore
yields **unsigned** APKs plus a CI notice — the build never fails for want of a
key. The keystore is **never** committed; it lives only as CI secrets / offline.

A single, stable upgrade key matters: Obtainium and F-Droid both verify that an
update is signed by the **same** key as the installed APK, so re-signing with a
different key breaks in-place updates. Keep one release keystore for the life of
each package.

---

## (a) Self-hosted F-Droid repository — the primary channel

We run our **own** F-Droid repo (a signed-APK mirror, not a build-from-source
repo) at:

```
https://dist.predatorhunters.co.uk/fdroid/repo
```

Operator runbook (drop APK → `fdroid update -c` → rsync `repo/`) and the
offline-key policy are in [`../fdroid/README.md`](../fdroid/README.md); the repo
config + per-app metadata live in `fdroid/config.yml` and `fdroid/metadata/`.

**Add-repo link** users tap or scan (append the fingerprint that `fdroid init`
prints for the offline key — shown as `REPO_FINGERPRINT` below):

```
https://dist.predatorhunters.co.uk/fdroid/repo?fingerprint=REPO_FINGERPRINT
```

Or the F-Droid client deep link:

```
fdroidrepos://dist.predatorhunters.co.uk/fdroid/repo?fingerprint=REPO_FINGERPRINT
```

**QR code:** generate a QR of that `https://…?fingerprint=…` URL (e.g. the
F-Droid app's "Repositories → ⋮ → Scan QR code", or `qrencode -o ph-bulwark-fdroid.png "<url>"`).
Publish the PNG alongside the repo on the dist host. Once added, both apps appear
in the F-Droid client and update from the mirror.

---

## (b) Obtainium — track the GitHub Releases directly

[Obtainium](https://github.com/ImranR98/Obtainium) (GPL — the **app**, installed
by the user; it is not bundled or linked into PH Bulwark, so it does not affect
our permissive licensing) installs and auto-updates APKs straight from a GitHub
Releases page by tag. This is the **auto-update** path; the F-Droid mirror is
manual. Point Obtainium at the releases repo:

```
https://github.com/Jordan-Hall/PH-bulwark
```

Two apps share one releases repo, so add **two** Obtainium sources, each pinned
to its own asset by `apkFilterRegEx`:

Child filter — `co.predatorhunters.bulwark`:

```json
{
  "id": "co.predatorhunters.bulwark",
  "url": "https://github.com/Jordan-Hall/PH-bulwark",
  "author": "Predator Hunters",
  "name": "PH Bulwark",
  "additionalSettings": "{\"apkFilterRegEx\":\"app-release\\\\.apk$\",\"invertAPKFilter\":false,\"verifyLatestTag\":false,\"versionExtractionRegEx\":\"\",\"matchGroupToUse\":\"\",\"trackOnly\":false,\"versionDetection\":true,\"releaseDateAsVersion\":false}"
}
```

Safe camera — `co.predatorhunters.bulwark.camera`:

```json
{
  "id": "co.predatorhunters.bulwark.camera",
  "url": "https://github.com/Jordan-Hall/PH-bulwark",
  "author": "Predator Hunters",
  "name": "PH Bulwark Camera",
  "additionalSettings": "{\"apkFilterRegEx\":\"camera-release\\\\.apk$\",\"invertAPKFilter\":false,\"verifyLatestTag\":false,\"versionExtractionRegEx\":\"\",\"matchGroupToUse\":\"\",\"trackOnly\":false,\"versionDetection\":true,\"releaseDateAsVersion\":false}"
}
```

The `apkFilterRegEx` values (`app-release\.apk$` / `camera-release\.apk$`) must
stay in lock-step with the asset names the release workflow uploads.

---

## (c) Accrescent — submission notes

[Accrescent](https://accrescent.app) is a FOSS-friendly Android app store with
mandatory app signing and a clean security model. Notes for a future submission:

- **Fully-FOSS expectation.** Accrescent expects open-source apps; PH Bulwark's
  code is `Apache-2.0 OR MIT`. The only non-free asset is the trademarked brand
  icon (flagged honestly as `NonFreeAssets` in the F-Droid metadata) — confirm
  Accrescent's stance on a trademarked launcher icon before submitting, or ship
  the permissive shield placeholder.
- **Its own signing.** Accrescent requires apps signed for distribution and
  maintains its own update-key model; you submit the **APK** (not an AAB),
  signed with the upgrade key. Keep the same release keystore so the package
  identity is stable across channels.
- **Submission flow.** Use the `accrescent` developer CLI / `apksigner` to verify
  the signature, then submit through the Accrescent developer console as
  documented at accrescent.app. As with F-Droid, expect questions about the
  VpnService + accessibility + device-admin permission set — answer with the
  child-protection, guardian-managed, **consented** framing (see
  [`FRAMING.md`](FRAMING.md)).

---

## Honest notes

- **Official F-Droid.org is NOT pursued.** Two reasons: (1) a guardian-installed
  parental-control content filter (VpnService + opt-in on-screen text reader +
  device-admin) sits awkwardly in F-Droid.org's inclusion policy and review
  norms; and (2) we self-host the signed APKs and our own repo, which gives us
  control over the release cadence without a third-party gatekeeper. We run our
  own F-Droid **repo** (channel a) instead — same client, our key, our rules.
- **Push: ntfy / UnifiedPush replaces FCM.** To stay free of proprietary Google
  services these FOSS builds use [UnifiedPush](https://unifiedpush.org) with an
  [ntfy](https://ntfy.sh) distributor for guardian alerts, not Firebase Cloud
  Messaging. The push **code** is handled in a separate PR; this document only
  records the distribution implication (no FCM dependency, so the APKs stay
  Google-service-free and installable on de-Googled devices).
- **Framing.** Throughout, PH Bulwark is a consensual, openly-visible
  child-protection content filter on a guardian-owned device — never described as
  covert monitoring or surveillance (see [`FRAMING.md`](FRAMING.md)).
