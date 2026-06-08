# Android Device Owner provisioning (strongest tamper-resistance tier)

Provisioning the Aegis child app as **Device Owner** is what makes anti-removal
actually robust: as Device Owner, `Lockdown.enforce` can block uninstall, factory
reset, safe-boot, and pin an always-on VPN — and the app cannot be removed without
`dpm remove-active-admin` or a factory reset. Device Owner can only be established
on a **factory-reset device with no accounts**, openly, at setup — never covertly.

Component: `co.predatorhunters.aegis/.admin.AegisDeviceAdminReceiver`

On completion the receiver's `onProfileProvisioningComplete` (QR/NFC/zero-touch) or
`DEVICE_OWNER_CHANGED` (dev `dpm`) handler calls `Lockdown.enforce` + records
enrollment (`Enrollment`) and opens the dashboard.

## A. Dev / test path (`adb`)

Preconditions: the device is freshly factory-reset **or has NO accounts** (no Google
account, no secondary users/profiles), Aegis installed.

```sh
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell dpm set-device-owner co.predatorhunters.aegis/.admin.AegisDeviceAdminReceiver
# verify:
adb shell dumpsys device_policy | grep -i "Device Owner"
```

Notes:
- `set-device-owner` **fails if any account exists** ("…already some accounts on the
  device"). Remove all accounts or factory-reset first.
- `dpm set-device-owner` does **not** fire `onProfileProvisioningComplete` — it fires
  `DEVICE_OWNER_CHANGED`, which our receiver also handles, so lockdown still
  auto-applies and enrollment is recorded.
- Tear-down (debuggable builds): guardian un-enroll should call `Lockdown.release`
  first; then `adb shell dpm remove-active-admin co.predatorhunters.aegis/.admin.AegisDeviceAdminReceiver`.

## B. QR-code provisioning (self-serve, from factory reset)

On a factory-reset device, on the first **"Hi there / welcome"** setup screen, tap
the screen **6 times** → the device offers a QR scanner → scan the QR below. It
joins Wi-Fi, downloads the APK, verifies the signing-cert checksum, installs Aegis,
sets it as Device Owner, and fires `onProfileProvisioningComplete`.

The QR encodes this minified JSON:

```json
{
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME": "co.predatorhunters.aegis/.admin.AegisDeviceAdminReceiver",
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION": "https://dl.predatorhunters.co.uk/aegis/aegis-child-release.apk",
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM": "<URL-SAFE-BASE64-OF-SIGNING-CERT-SHA256>",
  "android.app.extra.PROVISIONING_SKIP_ENCRYPTION": false,
  "android.app.extra.PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED": true,
  "android.app.extra.PROVISIONING_WIFI_SSID": "HomeNetwork",
  "android.app.extra.PROVISIONING_WIFI_SECURITY_TYPE": "WPA",
  "android.app.extra.PROVISIONING_WIFI_PASSWORD": "<wifi-password>",
  "android.app.extra.PROVISIONING_LOCALE": "en_GB",
  "android.app.extra.PROVISIONING_TIME_ZONE": "Europe/London",
  "android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE": {
    "co.predatorhunters.aegis.family_id": "fam_xxx",
    "co.predatorhunters.aegis.child_id": "child_xxx",
    "co.predatorhunters.aegis.cluster_endpoint": "https://cluster.predatorhunters.co.uk:8443"
  }
}
```

Key points:
- **Component name** must be exactly `co.predatorhunters.aegis/.admin.AegisDeviceAdminReceiver`.
- **Signature checksum** is the **URL-safe, no-padding Base64 of the signing
  certificate SHA-256** (preferred over the full-APK checksum — it survives APK
  rebuilds as long as the signing key is stable). Compute it from the **release**
  APK:
  ```sh
  apksigner verify --print-certs aegis-child-release.apk   # take the cert SHA-256
  # hex -> bytes -> base64url, drop '=' padding
  ```
- **`PROVISIONING_ADMIN_EXTRAS_BUNDLE`** carries `family_id` / `child_id` /
  `cluster_endpoint` straight through to `onProfileProvisioningComplete`
  (`Enrollment` reads them), auto-linking the device to the right child.
- **Wi-Fi extras** are needed so a factory-reset device can reach the download URL
  before any user signs in.

Generate the QR from the minified JSON, e.g.:
```sh
qrencode -o aegis-do-qr.png -d 300 -s 6 < provisioning.min.json
```

## C. NFC & zero-touch (production paths — operational, not app code)

- **NFC**: the same extras delivered as an `application/com.android.managedprovisioning`
  NDEF record from a programmer device.
- **Zero-touch**: register the device serial/IMEI in the zero-touch portal against an
  Aegis configuration pointing at the same component + download location;
  provisioning then happens automatically at first boot, **and re-binds after a
  factory reset** (the only thing that survives a wipe). Requires an EMM/reseller
  registration with Google.

## D. Prerequisites & honest limits

- **Release signing config is required for B/C.** CI builds a *debug* APK
  (`assembleDebug`, debug keystore); production QR/zero-touch needs a `release`
  `signingConfig` with a stable production key, and the checksum above must be that
  key's cert. Adding the production keystore is a follow-up (out of scope here).
- **`DISALLOW_FACTORY_RESET` blocks reset from Settings only.** It does NOT block
  recovery/bootloader/`adb` wipe on an unlocked bootloader. True re-binding after a
  wipe is **zero-touch / Google-account-bound** (§C), not something a normal Device
  Owner can set. Without zero-touch, a recovery wipe defeats Device Owner entirely.
- **What needs a real device / EMM to verify** (cannot be exercised in CI — CI only
  compiles the Kotlin): the full QR-from-factory-reset flow, signature-checksum
  verification (depends on the production key), NFC, and zero-touch.
- **The detection backstop always holds:** a wiped/removed device stops sending the
  tamper heartbeat, so the guardian gets a missed-heartbeat `PROTECTION_DISABLED`
  alert (see `docs/design/tamper-protection.md` §1).
