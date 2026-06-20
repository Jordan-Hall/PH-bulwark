# Pre-flash full device backup (Pixel) — READ FIRST

Purpose: capture **everything recoverable** off a phone over `adb` **before** any
risky operation (bootloader unlock / root / custom ROM flash), so the device can be
restored. Written for the PH Bulwark dedicated **Pixel 7a (`lynx`)**, but the steps
apply to any Pixel.

> **Why this matters / the irreplaceable-data rule.** One of the household phones
> holds **late-family-member voice notes that cannot be re-created**
> ([[no-factory-reset-constraint]] in the project memory). **Never** unlock / root /
> flash *that* phone. The ROM work is for a **separate, dedicated** device. This
> backup is the safety net regardless of which phone is connected.

---

## The two hard facts that drive everything

1. **Unlocking a Pixel bootloader WIPES the phone.** `fastboot flashing unlock`
   (required before rooting or flashing any custom image) triggers a **factory
   data reset** — `/data` is erased. So **all backups MUST happen BEFORE the
   unlock.** After unlock there is nothing left to back up.

2. **`adb` cannot read app-PRIVATE storage without root — and you can't get root
   without unlocking (= wiping).** This is the trap. Files under
   `/data/data/<app>/…` (e.g. **Google Recorder** voice recordings, Signal,
   authenticator apps, SMS/call-log databases) are **NOT** captured by
   `adb pull /sdcard`. If the irreplaceable voice notes live inside the recorder
   app's private storage, a naïve `adb pull` will **silently miss them**.

   → **You must EXPORT app-private data to shared storage (or cloud) FIRST**, using
   each app's own export/share feature, so the backup script can then pull it. See
   the manual checklist below. **Do this before running `backup.sh`.**

---

## Step 0 — manual exports (do these ON THE PHONE first)

These move app-private data into `/sdcard` (or Drive) where it can be backed up.
**The voice-notes one is the make-or-break step.**

- [ ] **Voice recordings (CRITICAL).** Open the recorder app (Google Recorder /
      Samsung Voice Recorder / whatever holds the notes). **Select all → Save /
      Export to device storage** (saves `.m4a`/`.wav` into `/sdcard`, often
      `Recordings/` or `Download/`), and/or **share → Save to Drive** as a second
      copy. Confirm the files appear in the **Files** app under Internal storage.
- [ ] **Photos/Videos.** If anything is "in the cloud only," open Google Photos →
      ensure originals are **downloaded** (or rely on the Google account — note it).
- [ ] **WhatsApp / Signal / Telegram.** Use each app's in-app **backup/export**
      (chats + media). Signal: Settings → Chats → **Backups** (writes to `/sdcard`,
      note the 30-digit passphrase). Authenticator-type apps: **export/transfer**
      now — they do **not** survive a wipe.
- [ ] **SMS / MMS / call log.** Install **"SMS Backup & Restore"** (FOSS-ish) →
      back up to a local file in `/sdcard`. (Or confirm Google backup is on.)
- [ ] **Contacts / Calendar.** Confirm they sync to the Google account (note which
      account), or Contacts → **Export to `.vcf`** into `/sdcard`.
- [ ] **2FA / passkeys / banking apps.** Migrate/export now — they are tied to the
      device and will be lost on wipe.

When the above are done, the irreplaceable data is in `/sdcard` (or cloud) and the
script below will capture it.

---

## Step 1 — run the read-only backup

`backup.sh` **only reads** from the phone (`adb pull` / `adb shell` queries). It
**never** writes to, modifies, roots, or wipes the device. Run it from the repo
root on the Windows host (Git Bash):

```sh
# optional: pass the serial if more than one device is attached
bash tools/device-backup/backup.sh 32161FDH20039M
# output goes to ./device-backup-<timestamp>/
```

It captures:
- `meta/` — device props, the **full installed-package list**, system/secure/global
  settings, accounts (so you know what to re-sync), and a list of every audio file
  found (so you can eyeball that the voice notes came through).
- `apks/` — every **third-party APK** (base + split APKs) so exact app versions can
  be reinstalled.
- `sdcard/` — a **complete recursive copy of internal storage** (DCIM, Pictures,
  Movies, Music, Download, Documents, Recordings, `Android/media/…`, etc.).
- `adb-backup/full-backup.ab` — a **best-effort** `adb backup -all` (deprecated and
  unreliable on Android 12+, and apps can opt out — treat as a bonus, **not** the
  primary copy; the `sdcard/` pull + your Step-0 exports are what you rely on).
- `meta/SHA256SUMS.txt` — checksums of every pulled file (integrity + restore proof).

---

## Step 2 — VERIFY before you trust it (do not skip)

```sh
B=./device-backup-<timestamp>
# 1) The voice notes specifically — eyeball the list; confirm the count looks right.
cat "$B/meta/audio-files.txt"; wc -l "$B/meta/audio-files.txt"
# 2) Nothing truncated — re-verify checksums.
(cd "$B" && sha256sum -c meta/SHA256SUMS.txt | grep -v ': OK$' || echo "all OK")
# 3) Size sanity.
du -sh "$B"
```

- **Open a few of the audio files and play them** off the backup copy.
- **Copy the whole `device-backup-<timestamp>/` to at least TWO places**, at least
  one **offline** (external drive). The signing keystore rule applies here too:
  irreplaceable → keep an offline copy ([[signing-keystore]]).

**Only after Step 2 passes** is it safe to consider unlock/flash — and **only on the
dedicated device, never the one with the voice notes.**

---

## Restore

- **Media / files:** `adb push <backup>/sdcard/. /sdcard/` (after the device is set
  up again), then let Photos/Files re-index.
- **Apps:** reinstall from `apks/` — `adb install-multiple <pkg>/*.apk` (split APKs)
  or `adb install <pkg>/base.apk`. App *data* only restores if you used each app's
  own backup/export in Step 0 (or if `full-backup.ab` happened to capture it:
  `adb restore <backup>/adb-backup/full-backup.ab`).
- **Voice notes:** re-import the exported `.m4a`/`.wav` files into the recorder app
  (or just keep them as files — they're the originals).

---

## Notes / limits (honest)

- A true bit-for-bit `/data` image (nandroid) needs root or a custom recovery, which
  needs unlock, which wipes — so it is **not possible before the first unlock**. This
  logical backup (shared storage + APKs + per-app exports) is the maximum achievable
  pre-unlock, which is why **Step 0 exports are mandatory**, not optional.
- The child-app **content-filter validation does NOT need root or a wipe** — it's
  install the APK + enable the AccessibilityService. So for validating the shipped
  app on an existing phone, you never unlock at all. Root/flash is **only** the
  dedicated-ROM path.
