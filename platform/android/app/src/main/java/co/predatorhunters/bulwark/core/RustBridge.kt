package co.predatorhunters.bulwark.core

/**
 * JNI bridge to the Rust core — `crates/bulwark-client`, built as a C ABI shared
 * library (`libbulwark_client.so`) by `cargo-ndk` and bundled under
 * `app/src/main/jniLibs/<abi>/`.
 *
 * Division of labour:
 *  - [BulwarkVpnService][co.predatorhunters.bulwark.vpn.BulwarkVpnService] hands the TUN
 *    file descriptor to [startVpn]; Rust runs the intercept → classify → policy
 *    → block/blur/mute + alert loop on it (offloading heavy media to the home
 *    cluster via bulwark-infer).
 *  - [BulwarkAccessibilityService][co.predatorhunters.bulwark.accessibility.BulwarkAccessibilityService]
 *    pushes rendered on-screen text (the E2E / pinned-app path) into the same
 *    deterministic grooming pipeline via [analyzeText].
 *
 * The matching exports live on the Rust side behind an `android` cargo feature
 * (`#[no_mangle] pub extern "system" fn Java_..._startVpn(...)`, etc.). These
 * signatures are the contract; see platform/android/README.md.
 */
object RustBridge {
    @Volatile private var loaded = false

    /** Load libbulwark_client.so once. Safe to call repeatedly. */
    @Synchronized
    fun ensureLoaded() {
        if (!loaded) {
            System.loadLibrary("bulwark_client")
            loaded = true
        }
    }

    /**
     * Start the Rust filtering loop on the VpnService TUN [tunFd].
     * @param vpnService service instance used by Rust to call VpnService.protect
     *        on future upstream sockets so they do not loop through the VPN.
     * @param configJson serialized client config (cluster endpoint, device id…).
     * @return an opaque handle to pass back to [stopVpn].
     */
    external fun startVpn(vpnService: android.net.VpnService, tunFd: Int, configJson: String): Long

    /** Stop the loop and release the handle. */
    external fun stopVpn(handle: Long)

    /**
     * True when the transparent data path failed to start or died after
     * starting. [BulwarkVpnService] polls this and calls `stopSelf()` so the
     * captured TUN is released — a captive fd nobody reads blackholes ALL device
     * traffic. A clean [stopVpn] never sets it.
     */
    external fun isDataPathDown(): Boolean

    /**
     * Feed on-device-captured text into the grooming pipeline (E2E/pinned apps).
     * @return a JSON `Verdict` (category, action, severity, score, rationale).
     */
    external fun analyzeText(app: String, threadId: String, text: String): String

    /** Poll the next guardian alert as JSON, or null if none is pending. */
    external fun nextAlert(): String?

    /**
     * Redeem the guardian-generated child pairing code against the selected
     * Accounts endpoint. Returns JSON:
     * `{ ok: true, child_id, family_id, device_token }` or `{ ok: false, error }`.
     * `device_token` is the per-device credential the server mints at redeem and
     * returns exactly once — persist it (`Enrollment`) and send it on heartbeats
     * and config fetches. Never shown in UI, never logged.
     */
    external fun redeemPairCode(endpoint: String, code: String, deviceId: String, caPath: String): String

    /**
     * The device-local pinned cluster CA file (PEM) used to validate `https://`
     * cluster endpoints. Production regions use an on-box self-signed CA that
     * public roots can't validate, so the child pins this; provisioned at
     * pairing. Absent → https RPCs are refused with an actionable message
     * (never plaintext fall-back). Passed to every child→cluster JNI RPC.
     */
    fun clusterCaPath(ctx: android.content.Context): String =
        java.io.File(ctx.filesDir, "cluster_ca.pem").absolutePath

    /**
     * The per-install TLS-inspection ROOT CA in PEM (public cert only — the
     * private key NEVER leaves the device keystore). [caDir] is the app-sandbox
     * CA directory ([inspectionCaDir]); the returned root is byte-identical to
     * the CA the on-device proxy mints leaf certs under. Install it into the
     * device trust store so inspected HTTPS validates instead of showing
     * "connection not private". Empty when the CA can't be loaded/generated.
     * See [CaTrust][co.predatorhunters.bulwark.admin.CaTrust].
     */
    external fun inspectionCaPem(caDir: String): String

    /** App-sandbox directory the inspection CA persists in (`filesDir/ca`); the
     *  same `ca_dir` passed to [startVpn]'s config so the cert matches the proxy. */
    fun inspectionCaDir(ctx: android.content.Context): String =
        java.io.File(ctx.filesDir, "ca").absolutePath

    /**
     * Fetch this device's guardian-set desired runtime config (the remote
     * "VPN switch": filtering on/off, region/server, strictness band) from the
     * ChildControl service on the enrolled server. CONTENT-FREE: policy and
     * routing only. [appliedVersion] is the config_version this device last
     * applied — the server records it as the applied-version ack the parent
     * console shows ("applied ✓ vN"), and the Rust bridge live-applies the
     * fetched strictness band when the config is not older than it. Returns JSON:
     * `{ ok: true, filtering_enabled, server_region, server_endpoint, profile,
     *    require_always_on, config_version, updated_ts }` or `{ ok: false, error }`.
     * [deviceToken] is the per-device credential minted at pairing
     * (`PairResult.device_token`; "" for legacy token-less enrollments) — sent
     * so the server can authenticate this device's config fetch.
     * See [ChildConfigSync][co.predatorhunters.bulwark.vpn.ChildConfigSync].
     */
    external fun fetchChildConfig(endpoint: String, deviceId: String, appliedVersion: Long, caPath: String, deviceToken: String): String

    /**
     * Submit the guardian's review decision for a flagged item: `approve` = allow
     * it through / override the block; otherwise keep it blocked. Routed to the
     * policy engine, which records the decision and may allowlist the host/hash
     * for this child. (Approve/deny is roadmap — see docs/design/parent-notifications.md.)
     */
    external fun submitReviewDecision(alertId: String, approve: Boolean)

    /** Register this parent device's push token so the cluster can deliver alerts
     *  remotely via FCM. No-op when the parent reviews on the same device. */
    external fun registerParentPushToken(token: String)

    /**
     * Report a tamper / protection-downgrade event (an `bulwark.v1.TamperKind`
     * ordinal) so it reaches the guardian as a redacted PROTECTION_DISABLED alert.
     * Content-free — only *which* protection changed. See
     * [TamperReporter][co.predatorhunters.bulwark.tamper.TamperReporter].
     */
    external fun reportTamper(kind: Int)
}
