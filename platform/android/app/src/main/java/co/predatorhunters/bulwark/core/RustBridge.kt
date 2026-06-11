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
     * Feed on-device-captured text into the grooming pipeline (E2E/pinned apps).
     * @return a JSON `Verdict` (category, action, severity, score, rationale).
     */
    external fun analyzeText(app: String, threadId: String, text: String): String

    /** Poll the next guardian alert as JSON, or null if none is pending. */
    external fun nextAlert(): String?

    /**
     * Redeem the guardian-generated child pairing code against the selected
     * Accounts endpoint. Returns JSON:
     * `{ ok: true, child_id, family_id }` or `{ ok: false, error }`.
     */
    external fun redeemPairCode(endpoint: String, code: String, deviceId: String): String

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
     * See [ChildConfigSync][co.predatorhunters.bulwark.vpn.ChildConfigSync].
     */
    external fun fetchChildConfig(endpoint: String, deviceId: String, appliedVersion: Long): String

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
