package co.libertyware.aegis.core

/**
 * JNI bridge to the Rust core — `crates/aegis-client`, built as a C ABI shared
 * library (`libaegis_client.so`) by `cargo-ndk` and bundled under
 * `app/src/main/jniLibs/<abi>/`.
 *
 * Division of labour:
 *  - [AegisVpnService][co.libertyware.aegis.vpn.AegisVpnService] hands the TUN
 *    file descriptor to [startVpn]; Rust runs the intercept → classify → policy
 *    → block/blur/mute + alert loop on it (offloading heavy media to the home
 *    cluster via aegis-infer).
 *  - [AegisAccessibilityService][co.libertyware.aegis.accessibility.AegisAccessibilityService]
 *    pushes rendered on-screen text (the E2E / pinned-app path) into the same
 *    deterministic grooming pipeline via [analyzeText].
 *
 * The matching exports live on the Rust side behind an `android` cargo feature
 * (`#[no_mangle] pub extern "system" fn Java_..._startVpn(...)`, etc.). These
 * signatures are the contract; see platform/android/README.md.
 */
object RustBridge {
    @Volatile private var loaded = false

    /** Load libaegis_client.so once. Safe to call repeatedly. */
    @Synchronized
    fun ensureLoaded() {
        if (!loaded) {
            System.loadLibrary("aegis_client")
            loaded = true
        }
    }

    /**
     * Start the Rust filtering loop on the VpnService TUN [tunFd].
     * @param configJson serialized client config (cluster endpoint, device id…).
     * @return an opaque handle to pass back to [stopVpn].
     */
    external fun startVpn(tunFd: Int, configJson: String): Long

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
     * Report a tamper / protection-downgrade event (an `aegis.v1.TamperKind`
     * ordinal) so it reaches the guardian as a redacted PROTECTION_DISABLED alert.
     * Content-free — only *which* protection changed. See
     * [TamperReporter][co.libertyware.aegis.tamper.TamperReporter].
     */
    external fun reportTamper(kind: Int)
}
