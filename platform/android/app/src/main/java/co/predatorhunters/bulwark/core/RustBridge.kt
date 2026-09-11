package co.predatorhunters.bulwark.core

/**
 * JNI bridge to the Rust core — `crates/bulwark-client`, built as a C ABI shared
 * library (`libbulwark_client.so`) by `cargo-ndk` and bundled under
 * `app/src/main/jniLibs/<abi>/`.
 *
 * Division of labour:
 *  - [BulwarkVpnService][co.predatorhunters.bulwark.vpn.BulwarkVpnService] hands the TUN
 *    file descriptor to [startVpn] for local filtering, or [startServerVpn] for
 *    transport-only WireGuard routing where the region performs TLS inspection,
 *    analysis, policy and remediation.
 *  - [BulwarkAccessibilityService][co.predatorhunters.bulwark.accessibility.BulwarkAccessibilityService]
 *    pushes rendered on-screen text (the E2E / pinned-app path) into the same
 *    deterministic grooming pipeline via [analyzeText].
 */
object RustBridge {
    @Volatile private var loaded = false

    @Synchronized
    fun ensureLoaded() {
        if (!loaded) {
            System.loadLibrary("bulwark_client")
            loaded = true
        }
    }

    external fun startVpn(vpnService: android.net.VpnService, tunFd: Int, configJson: String): Long

    /**
     * Provision the region-side WireGuard peer before Android creates the TUN.
     * Returns `{ ok:true, filter_active, assigned_address, server_endpoint,
     * inspection_ca_pem, inspection_ca_sha256 }` only when the selected region
     * confirms its wg0 path is actively filtered.
     */
    external fun prepareServerVpn(endpoint: String, deviceId: String, caPath: String, deviceToken: String): String

    /**
     * Start transport-only server VPN mode on [tunFd]. No local TLS proxy or media
     * classifier is started; raw IP packets are encrypted to the already-provisioned
     * region and the region owns inspection/enforcement.
     */
    external fun startServerVpn(vpnService: android.net.VpnService, tunFd: Int, configJson: String): Long

    external fun stopVpn(handle: Long)

    external fun isDataPathDown(): Boolean

    external fun analyzeText(app: String, threadId: String, text: String): String

    external fun nextAlert(): String?

    /**
     * Redeem the guardian-generated child pairing code against the selected
     * Accounts endpoint. Returns JSON:
     * `{ ok: true, child_id, family_id, device_token }` or `{ ok: false, error }`.
     */
    external fun redeemPairCode(endpoint: String, code: String, deviceId: String, caPath: String): String

    fun clusterCaPath(ctx: android.content.Context): String =
        java.io.File(ctx.filesDir, "cluster_ca.pem").absolutePath

    /**
     * The per-install LOCAL TLS-inspection root used only by on-device filtering.
     */
    external fun inspectionCaPem(caDir: String): String

    fun inspectionCaDir(ctx: android.content.Context): String =
        java.io.File(ctx.filesDir, "ca").absolutePath

    /**
     * Fetch this device's guardian-set desired runtime config. CONTENT-FREE:
     * policy and routing only. `filter_location` is `on_device` or `on_server`;
     * server mode is applied only after the region VPN and inspection CA are live.
     */
    external fun fetchChildConfig(endpoint: String, deviceId: String, appliedVersion: Long, caPath: String, deviceToken: String): String

    external fun submitReviewDecision(alertId: String, approve: Boolean)

    external fun registerParentPushToken(token: String)

    external fun reportTamper(kind: Int)

    external fun raiseSos(endpoint: String, deviceId: String, caPath: String, deviceToken: String): String
}