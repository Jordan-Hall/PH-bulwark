package co.predatorhunters.bulwark.core

/** JNI bridge for Bulwark's Local VPN and authenticated Remote VPN modes. */
object RustBridge {
    @Volatile private var loaded = false

    @Synchronized
    fun ensureLoaded() {
        if (!loaded) {
            System.loadLibrary("bulwark_client")
            loaded = true
        }
    }

    /** Local VPN: inspection/inference/enforcement run on this device. */
    external fun startVpn(vpnService: android.net.VpnService, tunFd: Int, configJson: String): Long

    /**
     * Authenticate and provision Remote VPN before Android creates the TUN.
     * [stateDir] is app-private storage for the device's persistent WireGuard
     * private key. The private key never crosses JNI or leaves the device.
     */
    external fun prepareServerVpn(
        endpoint: String,
        deviceId: String,
        caPath: String,
        deviceToken: String,
        stateDir: String,
    ): String

    /** Remote VPN: the phone only pumps encrypted IP; the region filters. */
    external fun startServerVpn(
        vpnService: android.net.VpnService,
        tunFd: Int,
        configJson: String,
    ): Long

    external fun stopVpn(handle: Long)

    external fun isDataPathDown(): Boolean

    external fun analyzeText(app: String, threadId: String, text: String): String

    external fun nextAlert(): String?

    external fun redeemPairCode(
        endpoint: String,
        code: String,
        deviceId: String,
        caPath: String,
    ): String

    fun clusterCaPath(ctx: android.content.Context): String =
        java.io.File(ctx.filesDir, "cluster_ca.pem").absolutePath

    external fun inspectionCaPem(caDir: String): String

    fun inspectionCaDir(ctx: android.content.Context): String =
        java.io.File(ctx.filesDir, "ca").absolutePath

    /** App-private Remote VPN key/session working directory. */
    fun remoteVpnDir(ctx: android.content.Context): String =
        java.io.File(ctx.filesDir, "remote_vpn").absolutePath

    external fun fetchChildConfig(
        endpoint: String,
        deviceId: String,
        appliedVersion: Long,
        caPath: String,
        deviceToken: String,
    ): String

    external fun submitReviewDecision(alertId: String, approve: Boolean)

    external fun registerParentPushToken(token: String)

    external fun reportTamper(kind: Int)

    external fun raiseSos(
        endpoint: String,
        deviceId: String,
        caPath: String,
        deviceToken: String,
    ): String
}
