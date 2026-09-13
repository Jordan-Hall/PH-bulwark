package co.predatorhunters.bulwark.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import co.predatorhunters.bulwark.admin.CaTrust
import co.predatorhunters.bulwark.admin.Enrollment
import co.predatorhunters.bulwark.core.RustBridge
import co.predatorhunters.bulwark.notify.AlertNotifier
import org.json.JSONObject
import java.io.File

/**
 * Bulwark VPN shell with two explicit modes:
 * - Local VPN: inspection, analysis and enforcement run on this device.
 * - Remote VPN: this device only captures/encrypts packets; the authenticated
 *   Bulwark region performs inspection, analysis and enforcement.
 */
class BulwarkVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    private var rustHandle: Long = 0L
    @Volatile private var polling = false
    @Volatile private var configPolling = false
    @Volatile private var establishing = false
    @Volatile private var reconfiguring = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        running = true
        lastFailure = ""
        startForeground(NOTIF_ID, buildNotification())

        val replaceDataPath = intent?.action == ACTION_RECONFIGURE
        if (replaceDataPath || tun == null) {
            launchEstablish(replaceDataPath)
        }
        return START_STICKY
    }

    @Synchronized
    private fun launchEstablish(replaceDataPath: Boolean) {
        if (establishing) return
        establishing = true
        reconfiguring = replaceDataPath
        ready = false
        Thread({
            try {
                if (replaceDataPath) {
                    stopDataPath(clearConfigPoller = false)
                }
                establish()
            } finally {
                reconfiguring = false
                establishing = false
            }
        }, if (replaceDataPath) "bulwark-vpn-reconfigure" else "bulwark-vpn-start")
            .apply { isDaemon = true }
            .start()
    }

    private fun establish() {
        RustBridge.ensureLoaded()
        val mode = ChildConfigSync.desiredFilterLocation(this)
        activeFilterLocation = mode

        val startup = when (mode) {
            ChildConfigSync.FILTER_ON_SERVER -> prepareRemoteMode() ?: return
            ChildConfigSync.FILTER_ON_DEVICE -> prepareLocalMode() ?: return
            else -> {
                failStart("unknown VPN mode '$mode'")
                return
            }
        }

        val builder = Builder()
            .setSession(
                if (mode == ChildConfigSync.FILTER_ON_SERVER) {
                    "PH Bulwark Remote VPN"
                } else {
                    "PH Bulwark Local VPN"
                },
            )
            .setMtu(startup.mtu)
            .addAddress(startup.address, 32)
            .addDnsServer(startup.dnsServer)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)

        runCatching { builder.addDisallowedApplication(packageName) }
            .onFailure {
                failStart("could not exclude Bulwark transport from its own VPN")
                return
            }

        val pfd = builder.establish()
        if (pfd == null) {
            failStart("Android refused the VPN tunnel; VPN consent may be missing")
            return
        }
        tun = pfd

        rustHandle = runCatching {
            val config = deviceConfigJson()
            if (mode == ChildConfigSync.FILTER_ON_SERVER) {
                RustBridge.startServerVpn(this, pfd.fd, config)
            } else {
                RustBridge.startVpn(this, pfd.fd, config)
            }
        }.onFailure {
            Log.e(TAG, "Rust VPN data path failed to start", it)
        }.getOrDefault(0L)

        if (rustHandle == 0L || runCatching { RustBridge.isDataPathDown() }.getOrDefault(true)) {
            failStart("${modeLabel(mode)} data path did not become ready")
            return
        }

        ready = true
        lastFailure = ""
        startForeground(NOTIF_ID, buildNotification())
        Log.i(TAG, "${modeLabel(mode)} ready (rustHandle=$rustHandle)")
        startAlertPoller()
        startConfigPoller()
    }

    private fun prepareLocalMode(): StartupConfig? {
        val caResult = CaTrust.ensureInstalled(this)
        Log.i(TAG, "Local VPN inspection CA trust: $caResult")
        if (!caResult.isTrusted()) {
            notifyProvisioningRequired()
            failStart("Local VPN inspection CA is not system-trusted ($caResult)")
            return null
        }
        return StartupConfig(
            address = "10.0.0.2",
            dnsServer = "10.0.0.1",
            mtu = 1500,
        )
    }

    private fun prepareRemoteMode(): StartupConfig? {
        val enrollment = Enrollment.record(this)
        if (enrollment == null || enrollment.deviceToken.isBlank()) {
            failStart("Remote VPN requires a paired device credential")
            return null
        }

        val raw = runCatching {
            RustBridge.prepareServerVpn(
                enrollment.clusterEndpoint,
                enrollment.deviceId,
                RustBridge.clusterCaPath(this),
                enrollment.deviceToken,
                RustBridge.remoteVpnDir(this),
            )
        }.onFailure {
            Log.e(TAG, "Remote VPN authentication/provisioning call failed", it)
        }.getOrNull()
        val result = raw?.let { runCatching { JSONObject(it) }.getOrNull() }
        if (result == null || !result.optBoolean("ok", false)) {
            failStart(
                result?.optString("error", "Remote VPN authentication failed")
                    ?: "Remote VPN authentication failed",
            )
            return null
        }
        if (!result.optBoolean("filter_active", false)) {
            failStart("region did not confirm an active Remote VPN filter")
            return null
        }

        val assignedAddress = result.optString("assigned_address", "").trim()
        val inspectionCaPem = result.optString("inspection_ca_pem", "")
        val sessionExpiresTs = result.optLong("session_expires_ts", 0L)
        if (assignedAddress.isBlank() || inspectionCaPem.isBlank() || sessionExpiresTs <= 0L) {
            failStart("region returned an incomplete authenticated Remote VPN grant")
            return null
        }

        val caResult = CaTrust.ensurePemInstalled(this, inspectionCaPem, "Remote VPN inspection CA")
        Log.i(TAG, "Remote VPN region CA trust: $caResult")
        if (!caResult.isTrusted()) {
            notifyProvisioningRequired()
            failStart("Remote VPN inspection CA is not system-trusted ($caResult)")
            return null
        }

        Log.i(TAG, "Remote VPN authenticated with rotating device-bound lease")
        return StartupConfig(
            address = assignedAddress,
            dnsServer = "1.1.1.1",
            mtu = 1420,
        )
    }

    private fun CaTrust.Result.isTrusted(): Boolean =
        this == CaTrust.Result.INSTALLED_SYSTEM || this == CaTrust.Result.ALREADY_TRUSTED

    private fun deviceConfigJson(): String {
        val enrollment = Enrollment.record(this)
        val json = JSONObject()
            .put("device_id", Enrollment.stableDeviceId(this))
            .put("profile", ChildConfigSync.desiredProfile(this))
            .put("filter_location", ChildConfigSync.desiredFilterLocation(this))
            .put("ca_dir", File(filesDir, "ca").absolutePath)
            .put("remote_vpn_dir", RustBridge.remoteVpnDir(this))
            .put("cluster_ca", File(filesDir, "cluster_ca.pem").absolutePath)
        if (enrollment != null) {
            json.put("cluster_endpoint", enrollment.clusterEndpoint)
                .put("child_id", enrollment.childId)
                .put("family_id", enrollment.familyId)
                .put("device_token", enrollment.deviceToken)
        }
        return json.toString()
    }

    private fun startAlertPoller() {
        if (polling) return
        polling = true
        Thread({
            while (polling) {
                if (!reconfiguring && runCatching { RustBridge.isDataPathDown() }.getOrDefault(true)) {
                    Log.e(TAG, "VPN data path/authentication down — releasing TUN")
                    ready = false
                    lastFailure = "VPN protection stopped or Remote VPN authentication expired"
                    stopSelf()
                    return@Thread
                }
                val alert = runCatching { RustBridge.nextAlert() }.getOrNull()
                if (alert != null) AlertNotifier.notify(this, alert)
                else runCatching { Thread.sleep(2_000) }
            }
        }, "bulwark-alert-poller").apply { isDaemon = true }.start()
    }

    private fun startConfigPoller() {
        if (configPolling) return
        configPolling = true
        Thread({
            while (configPolling) {
                runCatching { ChildConfigSync.fetchAndReconcile(this) }
                runCatching { Thread.sleep(CONFIG_POLL_MS) }
            }
        }, "bulwark-config-poller").apply { isDaemon = true }.start()
    }

    private fun stopDataPath(clearConfigPoller: Boolean) {
        ready = false
        polling = false
        if (clearConfigPoller) configPolling = false
        if (rustHandle != 0L) {
            runCatching { RustBridge.stopVpn(rustHandle) }
            rustHandle = 0L
        }
        runCatching { tun?.close() }
        tun = null
        activeFilterLocation = ""
    }

    private fun failStart(detail: String) {
        lastFailure = detail.take(256)
        Log.e(TAG, detail)
        stopDataPath(clearConfigPoller = true)
        running = false
        stopSelf()
    }

    override fun onDestroy() {
        running = false
        reconfiguring = false
        establishing = false
        stopDataPath(clearConfigPoller = true)
        super.onDestroy()
    }

    private fun buildNotification(): Notification {
        val mgr = getSystemService(NotificationManager::class.java)
        mgr.createNotificationChannel(
            NotificationChannel(CHANNEL, "PH Bulwark VPN", NotificationManager.IMPORTANCE_LOW),
        )
        val mode = modeLabel(ChildConfigSync.desiredFilterLocation(this))
        return Notification.Builder(this, CHANNEL)
            .setContentTitle("PH Bulwark $mode is protecting this device")
            .setContentText(
                "Protection is reported as applied only after the requested VPN mode is authenticated and ready.",
            )
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setOngoing(true)
            .build()
    }

    private fun notifyProvisioningRequired() {
        runCatching {
            val mgr = getSystemService(NotificationManager::class.java)
            mgr.createNotificationChannel(
                NotificationChannel(
                    STATUS_CHANNEL,
                    "PH Bulwark status",
                    NotificationManager.IMPORTANCE_HIGH,
                ),
            )
            val notification = Notification.Builder(this, STATUS_CHANNEL)
                .setContentTitle("PH Bulwark — managed-device setup needed")
                .setContentText(
                    "HTTPS filtering needs this device provisioned as Device Owner so the selected Local or Remote VPN inspection CA can be trusted.",
                )
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setAutoCancel(true)
                .build()
            mgr.notify(STATUS_NOTIF_ID, notification)
        }
    }

    private fun modeLabel(mode: String): String =
        if (mode == ChildConfigSync.FILTER_ON_SERVER) "Remote VPN" else "Local VPN"

    private data class StartupConfig(
        val address: String,
        val dnsServer: String,
        val mtu: Int,
    )

    companion object {
        const val ACTION_RECONFIGURE = "co.predatorhunters.bulwark.vpn.RECONFIGURE"

        private const val TAG = "BulwarkVpn"
        private const val CHANNEL = "bulwark_vpn"
        private const val STATUS_CHANNEL = "bulwark_status"
        private const val NOTIF_ID = 1001
        private const val STATUS_NOTIF_ID = 1002
        private const val CONFIG_POLL_MS = 10_000L

        @Volatile var running = false
            private set

        @Volatile var ready = false
            private set

        @Volatile var activeFilterLocation: String = ""
            private set

        @Volatile var lastFailure: String = ""
            private set
    }
}
