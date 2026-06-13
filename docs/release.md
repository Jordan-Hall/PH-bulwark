# Release & app-store deployment

How PH Bulwark gets to testers and, later, the public — per platform, plus the
release automation and what a maintainer must supply (accounts, keys). This is a
**free, non-profit, open-source** project, so the store strategy favours open
channels first.

> **Testing phase (now).** We are releasing for **testing**, not general launch.
> Use the lowest-friction channels (direct download, F-Droid, Play **closed
> testing**) and gather feedback before any public store listing.

## 1. Channels by platform

### Android — `co.predatorhunters.bulwark` (+ `…camera`)
**FOSS, self-hosted first.** The owner's decision is to distribute the Android
apps through fully self-hosted FOSS channels — **no Google Play, no proprietary
services.** The full channel map (self-hosted F-Droid repo, Obtainium, Accrescent),
the Obtainium config snippets, and the honest no-official-F-Droid note live in
**[distribution.md](distribution.md)**; the table below summarises.

| Channel | Use | Notes |
|---|---|---|
| **Self-hosted F-Droid repo** (PRIMARY) | values-aligned, self-hosted | Our own repo at `dist.predatorhunters.co.uk/fdroid/repo` (a signed-APK mirror, not build-from-source). Scaffold + operator runbook in `fdroid/`. Official **F-Droid.org is NOT pursued** (parental-control category + we self-host) — see distribution.md. |
| **Obtainium** | auto-update from GitHub Releases | Points at the GitHub Releases repo and tracks new tags by APK name (`app-release.apk` / `camera-release.apk`). The auto-update path. |
| **Accrescent** | FOSS store submission | Requires a fully-FOSS app + its own signing; submit the signed APK via the `accrescent`/`apksigner` flow. |
| **Direct APK** | sideload testers | The same signed `app-release.apk` / `camera-release.apk` Release assets. |
| **Google Play** | deliberately NOT pursued | Self-host-first; the Play/AAB path (`store-publish.yml`) is retained but DEMOTED — see §1a. |

#### 1a. Retained (demoted) Play/AAB path
`store-publish.yml` still exists for a possible future Play closed-testing track
(signed `.aab`, $25 one-time account, strict review of VPN / Accessibility /
Device Admin / `FOREGROUND_SERVICE_SPECIAL_USE` — justify each as **child-safety
on a guardian-managed, consented device**). It is **not** the primary path and is
inert until the Play account + secrets exist. The FOSS path above ships APKs, not
AABs.

### Desktop
| OS | Channel | Signing |
|---|---|---|
| **Windows** | direct download (`bulwark_proxy.exe`/`bulwark_vpn.exe`/console) | **Must be code-signed** — Smart App Control blocks unsigned binaries (os error 4551). An EV/OV cert is needed for clean SmartScreen. |
| **macOS** | direct download `.dmg` | **Sign + notarize** with an Apple Developer ID, else Gatekeeper blocks it. |
| **Linux** | `.deb` / AppImage / direct binary | No mandatory signing; provide a checksum + (optional) GPG sig. |

### Server (cluster tier)
- **Container image** (`deploy/docker/`) pushed to a registry (GHCR/Docker Hub),
  deployed with the Ansible playbook (`deploy/ansible/`). Not an "app store".

### iOS
- The iOS app is **not built yet**. When it exists: **TestFlight** for testing
  (Apple Developer, $99/yr). Note iOS cannot enforce on-device prevention the way
  Android Device Owner does — it contributes the tamper heartbeat + Screen-Time /
  MDM integration only (see `tamper-protection.md`).

## 2. Release process (automation)

Tag a version → CI builds + uploads artifacts to a GitHub Release; store uploads are
then done with fastlane (or by hand during testing).

```sh
# bump versionCode/versionName in platform/android/app/build.gradle.kts, then:
git tag v0.1.0-test.1 && git push origin v0.1.0-test.1
```

- `.github/workflows/release.yml` (tag `v*` or manual dispatch) builds, per platform,
  with a `SHA256SUMS-<platform>` checksum file each: the **Linux server binaries**
  (`bulwark-server`, `bulwark_admin`), the **Windows child filter + adult console**
  (`bulwark_proxy/vpn/svc.exe`, `bulwark-parent.exe`), the **adult console for
  macOS/Linux** (`ph-bulwark-manager-macos` / `-linux`), and the **child Android APK**
  (`ph-bulwark-child-android.apk`, reusing `android.yml` via `workflow_call`) — all
  attached to the GitHub Release (unsigned for testing). An **opt-in Apple scaffold**
  job (repo variable `APPLE_SIGNING_READY=true`) builds the `platform/apple` Rust FFI
  staticlib/xcframework only — there is still no Xcode project/provisioning, so no
  installable iOS/macOS app. The **container image** ships via `docker.yml` / your
  registry.
- The **Android signed release APKs** (FOSS path) are produced by
  `.github/workflows/android-release.yml` on a **published Release** (or manual
  dispatch). It builds the child JNI lib via cargo-ndk, runs
  `gradle :app:assembleRelease :camera:assembleRelease` keyed on the repo
  **secrets** (`ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`,
  `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`), and attaches signed
  `app-release.apk` + `camera-release.apk` as Release assets for the self-hosted
  F-Droid repo / Obtainium / Accrescent (see [distribution.md](distribution.md)).
  Signing self-gates on the secrets — absent keystore ⇒ **unsigned** APKs + a CI
  notice, never a failed build. Both `:app` and `:camera` build.gradle carry the
  env-driven signing block. (Wire the secrets once the release keystore exists —
  see §3.)
- The legacy `release.yml` still attaches a **debug** child APK for sideloading
  testers, and the demoted `store-publish.yml` builds a signed `.aab` for a future
  Play track; neither is the primary distribution path now.
- Store listing text lives in `fastlane/metadata/android/en-US/` (used by F-Droid
  and Play upload). Update it from `market.md`.

## 3. Prerequisites a maintainer must supply
These can't live in the repo — provide them out-of-band / as CI secrets:

- **Android release keystore** (`keytool`-generated) → set the four `ANDROID_*`
  secrets above. The Device-Owner QR-provisioning signature checksum is derived from
  this key's cert SHA-256 (see `deploy/android/device-owner-provisioning.md`).
- **Store accounts**: Google Play ($25 one-time), Apple Developer ($99/yr, for iOS),
  F-Droid (free — submit a merge request to fdroiddata).
- **Desktop code-signing**: a Windows code-signing cert (EV recommended) and an
  Apple Developer ID for macOS notarization.
- **Brand assets**: the processed Predator Hunters logo (background removed) for the
  launcher icon + store graphics, plus screenshots. (The repo ships a vector shield
  placeholder — `res/drawable/ic_shield_foreground.xml`.)

## 4. Honest caveats
- **Play policy** is the biggest unknown: VPN + Accessibility + Device Admin in one
  app draws scrutiny. Lead with the child-safety, guardian-managed, **consented**
  framing and the no-covert-capture / no-data-sale stance. A rejection on the open
  Play track is possible; F-Droid + direct APK keep testing unblocked meanwhile.
- **Versioning**: bump `versionCode` every upload (Play requires monotonic codes).
- Nothing here ships secrets; signing happens only in CI with the secrets set.

## 5. Continuous deployment to the servers (AWS SSM — no inbound SSH)
`.github/workflows/deploy.yml` redeploys a running server on a **published Release**
or manual dispatch via **AWS SSM Run Command**: GitHub authenticates as the scoped
deploy user and tells the instance's SSM agent to `git pull` → rebuild → restart.
**No inbound SSH** — the EC2's SSH port stays locked to the operator's IP. Gated on
a GitHub **Environment** `production`:

| kind | name | value |
|---|---|---|
| secret | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | the scoped `ph-bulwark-deployer` IAM user (needs `ssm:SendCommand`) |
| var | `AWS_REGION` | e.g. `eu-west-2` |
| var | `AWS_INSTANCE_ID` | the EC2 id (must carry the `ph-bulwark-ssm` instance profile) |
| var | `BULWARK_PORT` | optional, default `8443` — MUST match the server's port (Terraform `bulwark_port`) |

**One-time SSM enablement** (admin/root, once): create role `ph-bulwark-ssm` with
`AmazonSSMManagedInstanceCore` (EC2 trust), attach it to the instance, and grant the
deploy user `ssm:SendCommand`/`GetCommandInvocation`/`DescribeInstanceInformation`.
Terraform sets `iam_instance_profile = "ph-bulwark-ssm"` on the instance so it isn't
stripped on the next apply.

Add **required reviewers** on the Environment for an approve-before-deploy gate. For
multiple servers (UK + US), add Environments (`production-us`, …) + duplicate the job.
