# Self-hosted F-Droid repository — PH Bulwark

This directory is the source-controlled part of PH Bulwark's **own** F-Droid
repository, served at `https://dist.predatorhunters.co.uk/fdroid/repo`. It is a
**binary-drop mirror**: the operator drops the signed APKs from a GitHub Release
into `repo/`, regenerates the signed index, and rsyncs `repo/` to the dist host.
We do **not** build apps from source here (no `Builds:` blocks) — the APKs are
built and signed by `.github/workflows/android-release.yml`.

Three apps are mirrored:

| Package | APK asset | Metadata |
|---|---|---|
| `co.predatorhunters.bulwark` (child filter) | `app-release.apk` | `metadata/co.predatorhunters.bulwark.yml` |
| `co.predatorhunters.bulwark.camera` (safe camera) | `camera-release.apk` | `metadata/co.predatorhunters.bulwark.camera.yml` |
| `co.predatorhunters.bulwark.manager` (guardian console) | `manager-release.apk` | `metadata/co.predatorhunters.bulwark.manager.yml` |

## What is and is NOT in git

- **In git:** `config.yml`, `metadata/*.yml`, this README, `.gitignore`.
- **NEVER in git** (blocked by `.gitignore`): the repo **signing keystore**, any
  keystore password, and the generated `repo/` / `archive/` directories with the
  signed APKs and index. The signing key is held **offline**.

## One-time setup (operator, offline machine)

1. Install fdroidserver (Debian/Ubuntu: `apt install fdroidserver`, or
   `pipx install fdroidserver`). Apache-2.0 licensed.
2. From this directory, create the offline repo signing key once:

   ```sh
   fdroid init
   ```

   This generates `keystore.jks` and prints the repo fingerprint. **Back the
   keystore up offline and keep it out of git** (`.gitignore` already blocks
   `*.jks`). Note the fingerprint — it goes in the add-repo URL
   (`?fingerprint=...`) published in `docs/distribution.md`.
3. Supply the keystore passwords at run time, never in `config.yml`:

   ```sh
   export keystorepass='...'
   export keypass='...'
   ```

## Publishing a release (each version)

1. The release CI publishes signed `app-release.apk` + `camera-release.apk` as
   GitHub Release assets. Download them.
2. Drop them into `repo/` (create it if absent):

   ```sh
   mkdir -p repo
   cp /path/to/app-release.apk repo/
   cp /path/to/camera-release.apk repo/
   cp /path/to/manager-release.apk repo/
   ```
3. Regenerate and sign the index (reads `config.yml` + `metadata/`):

   ```sh
   fdroid update -c
   ```

   `-c` reconciles metadata; `fdroid update` signs `index-v1.jar` / `index-v2`
   against the offline key and rolls versions past `archive_older` (4) into
   `archive/`.
4. Sanity-check the metadata before publishing:

   ```sh
   fdroid lint co.predatorhunters.bulwark co.predatorhunters.bulwark.camera co.predatorhunters.bulwark.manager
   ```
5. Rsync the signed output to the dist host (only `repo/`, and `archive/` if you
   serve it):

   ```sh
   rsync -av --delete repo/ deploy@dist.predatorhunters.co.uk:/srv/dist/fdroid/repo/
   ```

That is the whole loop: **drop APK → `fdroid update -c` → rsync `repo/`**.

## Notes

- This repo is intentionally separate from official **F-Droid.org**, which is not
  pursued (see `docs/distribution.md` for why). Clients add this repo by URL/QR.
- For users who prefer to track GitHub Releases directly, **Obtainium** points at
  the releases repo and auto-updates by tag — that, not this mirror, is the
  auto-update path (`docs/distribution.md`).
- `License` in the metadata mirrors the repo's own `Apache-2.0 OR MIT`. If a
  given `fdroid lint` rejects the SPDX `OR` expression, set it to `Apache-2.0`.
