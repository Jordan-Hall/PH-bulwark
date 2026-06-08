# Release & app-store deployment

How PH Bulwark gets to testers and, later, the public — per platform, plus the
release automation and what a maintainer must supply (accounts, keys). This is a
**free, non-profit, open-source** project, so the store strategy favours open
channels first.

> **Testing phase (now).** We are releasing for **testing**, not general launch.
> Use the lowest-friction channels (direct download, F-Droid, Play **closed
> testing**) and gather feedback before any public store listing.

## 1. Channels by platform

### Android — `co.predatorhunters.bulwark`
| Channel | Use | Notes |
|---|---|---|
| **Direct APK** | testers now | Built by CI; signed with the release key. Easiest for a testing cohort. |
| **F-Droid** | OSS-aligned distribution | Free, no account fee, values-aligned. **Caveat:** F-Droid inclusion may reject the Device-Owner / Accessibility tooling or require it to be clearly opt-in — submit the metadata and discuss. |
| **Google Play (closed testing)** | wider managed test | $25 one-time account. **Policy review is strict** for our permissions: VPN (`BIND_VPN_SERVICE`), Accessibility, Device Admin, `FOREGROUND_SERVICE_SPECIAL_USE`. Justify each as **child-safety on a guardian-managed, consented device** in the Play data-safety + permissions declarations. Expect review iterations. |
| **Samsung Galaxy Store / others** | optional | Same APK; lower priority. |

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

- `.github/workflows/release.yml` (tag `v*` or manual dispatch) builds the **Linux
  server binaries** (`bulwark-server`, `bulwark_admin`) and attaches them to the GitHub
  Release. The **container image** ships via `docker.yml` / your registry.
- The **Android signed APK** is produced by extending the existing `android.yml`
  build with `assembleRelease` + an `apksigner` step keyed on repo **secrets**
  (`ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`,
  `ANDROID_KEY_PASSWORD`); without them keep shipping the debug/unsigned APK for
  testers. (Wire this once the release keystore exists — see §3.)
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
