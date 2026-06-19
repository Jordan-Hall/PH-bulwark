//! Device-Owner provisioning QR helpers — generates the Android enterprise
//! provisioning JSON for "tap the welcome screen 6 times → scan QR" on a
//! freshly factory-reset dedicated device (e.g. a Pixel 7a).
//!
//! # How it fits together
//!
//! 1. The guardian selects a child from the roster (child_id + family_id known).
//! 2. They optionally enter Wi-Fi credentials so the factory-reset device can
//!    reach the download URL before any user account exists.
//! 3. The Manager builds the provisioning JSON (see [`build_provisioning_json`])
//!    and renders it as a QR (reusing the same [`pair_qr_svg`] path as pairing).
//! 4. The guardian scans with the Android Setup Wizard — the device installs PH
//!    Bulwark, sets it as Device Owner, fires
//!    `BulwarkDeviceAdminReceiver.onProfileProvisioningComplete`, which calls
//!    `Enrollment.markProvisioned`, which reads the three EXTRA_* keys from the
//!    `PROVISIONING_ADMIN_EXTRAS_BUNDLE` nested object and auto-links the device
//!    to the right child + server without any further setup step.
//!
//! # What the admin-extras bundle MUST contain
//!
//! `Enrollment.markProvisioned` (Enrollment.kt) reads exactly these three keys:
//! - `co.predatorhunters.bulwark.family_id`   → maps to `Enrollment.EXTRA_FAMILY_ID`
//! - `co.predatorhunters.bulwark.child_id`    → maps to `Enrollment.EXTRA_CHILD_ID`
//! - `co.predatorhunters.bulwark.cluster_endpoint` → maps to `Enrollment.EXTRA_CLUSTER`
//!
//! # Device token
//!
//! `device_token` is NOT in the bundle — `markProvisioned` does not read it;
//! the per-device token is only issued at pair-code redemption (`PairResult.device_token`).
//! A ROM-provisioned device will therefore start with an empty token (`""`, the
//! legacy "enrolled before tokens existed" path). This is a known gap; extending
//! the child app to accept a token via the extras bundle is a future follow-up
//! that REQUIRES a child-app change (out of scope here).
//!
//! # Configurable constants (operator must fill before shipping)
//!
//! - [`CHILD_APK_DOWNLOAD_URL`]: public URL of the signed child-app release APK.
//! - [`CHILD_APK_CERT_CHECKSUM`]: URL-safe, no-padding base64 SHA-256 of the
//!   APK *signing certificate* (NOT the APK itself). Derive it from the release
//!   keystore:
//!   ```sh
//!   apksigner verify --print-certs bulwark-child-release.apk
//!   # take the "SHA-256 digest: <hex>" line, convert hex→bytes→base64url, strip '='
//!   ```
//!   Stored in `C:\Users\Jordan\.ph-bulwark-signing` — NEVER embed the raw key;
//!   only the *public certificate hash* goes here.

use crate::media::pair_qr_svg;
use crate::servers::cluster_endpoint;

// ---------------------------------------------------------------------------
// Operator-configurable constants (TODO: fill before production QR is used)
// ---------------------------------------------------------------------------

/// Public URL of the signed PH Bulwark child-app release APK.
///
/// TODO: replace with the real release URL once CI uploads the signed APK to
/// the distribution bucket (e.g. `https://dl.predatorhunters.co.uk/bulwark/bulwark-child-release.apk`).
/// This value is embedded in every provisioning QR — update and regenerate QRs
/// whenever a signing-certificate rotation requires a new checksum.
pub const CHILD_APK_DOWNLOAD_URL: &str =
    "https://dl.predatorhunters.co.uk/bulwark/bulwark-child-release.apk";

/// URL-safe, no-padding base64 SHA-256 of the APK **signing certificate**.
///
/// TODO: compute this once from the production release APK:
/// ```sh
/// apksigner verify --print-certs bulwark-child-release.apk
/// # e.g. SHA-256 digest: AB CD EF ... → strip spaces → hex
/// # python3 -c "import hashlib,base64,bytes as b; v=bytes.fromhex('ABCDEF...');
/// #   print(base64.urlsafe_b64encode(v).rstrip(b'=').decode())"
/// ```
/// This is NOT a secret — it is the *public* certificate hash that Android uses
/// to verify the download matches the installed signing key. It must be updated
/// any time the release signing key rotates.
pub const CHILD_APK_CERT_CHECKSUM: &str = "TODO_base64url_noPad_SHA256_of_signing_cert";

/// Android Device-Admin component name for PH Bulwark.
/// Must match the `<receiver>` in the child app's AndroidManifest.xml.
const DEVICE_ADMIN_COMPONENT: &str = "co.predatorhunters.bulwark/.admin.BulwarkDeviceAdminReceiver";

// Admin-extras bundle keys — must match Enrollment.kt EXTRA_* constants exactly.
const EXTRA_FAMILY_ID: &str = "co.predatorhunters.bulwark.family_id";
const EXTRA_CHILD_ID: &str = "co.predatorhunters.bulwark.child_id";
const EXTRA_CLUSTER: &str = "co.predatorhunters.bulwark.cluster_endpoint";

/// Parameters for the provisioning QR.  Every field except `cluster_endpoint`
/// (auto-resolved from the active server) is supplied by the guardian.
pub struct ProvisioningParams<'a> {
    /// The child's `child_id` from the roster — passed to the device via extras.
    pub child_id: &'a str,
    /// The child's `family_id` from the roster — passed to the device via extras.
    pub family_id: &'a str,
    /// Cluster endpoint to auto-configure on the child device (e.g. `https://api.predatorhunters.co.uk:8443`).
    /// Defaults to the currently selected server; pass `""` to use the default.
    pub cluster_endpoint_override: &'a str,
    /// Optional Wi-Fi SSID for the factory-reset device.  `None` omits Wi-Fi
    /// extras (guardian provisions on a known-good network or cables in).
    pub wifi_ssid: Option<&'a str>,
    /// Optional Wi-Fi password.  Ignored when `wifi_ssid` is `None`.
    pub wifi_password: Option<&'a str>,
    /// APK download URL override (empty = use [`CHILD_APK_DOWNLOAD_URL`]).
    pub apk_url: &'a str,
    /// Signing-cert checksum override (empty = use [`CHILD_APK_CERT_CHECKSUM`]).
    pub cert_checksum: &'a str,
}

/// Build the Android enterprise-provisioning JSON string.
///
/// The outer object uses the documented
/// `android.app.extra.PROVISIONING_*` keys; the inner
/// `PROVISIONING_ADMIN_EXTRAS_BUNDLE` object uses the three keys that
/// `Enrollment.markProvisioned` reads to auto-link the device.
///
/// Returns `None` only if JSON serialisation fails (never expected in practice).
pub fn build_provisioning_json(p: &ProvisioningParams<'_>) -> Option<String> {
    let endpoint = if p.cluster_endpoint_override.trim().is_empty() {
        cluster_endpoint()
    } else {
        p.cluster_endpoint_override.to_string()
    };
    let apk_url = if p.apk_url.trim().is_empty() {
        CHILD_APK_DOWNLOAD_URL
    } else {
        p.apk_url
    };
    let checksum = if p.cert_checksum.trim().is_empty() {
        CHILD_APK_CERT_CHECKSUM
    } else {
        p.cert_checksum
    };

    let mut obj = serde_json::Map::new();
    obj.insert(
        "android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME".into(),
        serde_json::Value::String(DEVICE_ADMIN_COMPONENT.into()),
    );
    obj.insert(
        "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION".into(),
        serde_json::Value::String(apk_url.into()),
    );
    obj.insert(
        "android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM".into(),
        serde_json::Value::String(checksum.into()),
    );
    obj.insert(
        "android.app.extra.PROVISIONING_SKIP_ENCRYPTION".into(),
        serde_json::Value::Bool(false),
    );
    obj.insert(
        "android.app.extra.PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED".into(),
        serde_json::Value::Bool(true),
    );

    // Wi-Fi extras — only when the guardian supplies an SSID.
    if let Some(ssid) = p.wifi_ssid.filter(|s| !s.trim().is_empty()) {
        obj.insert(
            "android.app.extra.PROVISIONING_WIFI_SSID".into(),
            serde_json::Value::String(ssid.into()),
        );
        obj.insert(
            "android.app.extra.PROVISIONING_WIFI_SECURITY_TYPE".into(),
            serde_json::Value::String("WPA".into()),
        );
        if let Some(pw) = p.wifi_password.filter(|s| !s.is_empty()) {
            obj.insert(
                "android.app.extra.PROVISIONING_WIFI_PASSWORD".into(),
                serde_json::Value::String(pw.into()),
            );
        }
    }

    // Admin-extras bundle — the three keys Enrollment.markProvisioned reads.
    let mut extras = serde_json::Map::new();
    extras.insert(
        EXTRA_FAMILY_ID.into(),
        serde_json::Value::String(p.family_id.to_string()),
    );
    extras.insert(
        EXTRA_CHILD_ID.into(),
        serde_json::Value::String(p.child_id.to_string()),
    );
    extras.insert(EXTRA_CLUSTER.into(), serde_json::Value::String(endpoint));
    obj.insert(
        "android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE".into(),
        serde_json::Value::Object(extras),
    );

    serde_json::to_string(&serde_json::Value::Object(obj)).ok()
}

/// Render the provisioning JSON as an SVG QR (reuses the same `qrcode` crate
/// path as the pairing QR).  The provisioning JSON is denser than a pair code,
/// so we try both error-correction levels (M then L) to maximise scan reliability.
/// Returns `None` if the payload is too large to encode at all (practically
/// impossible with this payload, but handled gracefully).
pub fn provisioning_qr_svg(json: &str) -> Option<String> {
    pair_qr_svg(json)
}
