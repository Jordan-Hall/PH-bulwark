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
 * Bulwark's Android VPN shell. In `on_device` mode Rust owns local inspection.
 * In `on_server` mode the phone only captures raw IP and WireGuard-encrypts it
 * to a region that owns inspection, inference, policy and remediation.
 */
class BulwarkVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    private var rustHandle: Long = 0L
    @Volatile private var polling = false
    @Volatile private var configPolling = false
    @Volatile private var establishing = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        running = true
        ready = false
        lastFailure = ""
        startForeground(NOTIF_ID, buildNotification())
        if (tun == null && !establishing) {
            establishing = true
            Thread({
                try {
                    establish()
                } finally {
                    establishing = false
                }
            }, "bulwark-vpn-start").apply { isDaemon = true }.start()
        }
        return START_STICKY
    }

    private fun establish() {
        RustBridge.ensureLoaded()
        val mode = ChildConfigSync.desiredFilterLocation(this)
        activeFilterLocation = mode

        val startup = when (mode) {
            ChildConfigSync.FILTER_ON_SERVER -> prepareServerMode() ?: return
            ChildConfigSync.FILTER_ON_DEVICE -> prepareLocalMode() ?: return
            else -> {
                failStart("unknown filter mode '$mode'")
                return
            }
        }

        val builder = Builder()
            .setSession("PH Bulwark")
            .setMtu(startup.mtu)
            .addAddress(startup.address, 32)
            .addDnsServer(startup.dnsServer)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)

        runCatching { builder.addDisallowedApplication(packageName) }
            .onFailure {
                failStart("could not exclude Bulwark's transport socket from its own VPN")
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
            failStart("$mode data path did not become ready")
            return
        }

        ready = true
        lastFailure = ""
        Log.i(TAG, "Bulwark VPN ready ($mode, rustHandle=$rustHandle)")
        startAlertPoller()
        startConfigPoller()
    }

    private fun prepareLocalMode(): StartupConfig? {
        val caResult = CaTrust.ensureInstalled(this)
        Log.i(TAG, "local inspection CA trust: $caResult")
        if (!caResult.isTrusted()) {
            notifyProvisioningRequired()
            failStart("local inspection CA is not system-trusted ($caResult)")
            return null
        }
        return StartupConfig(
            address = "10.0.0.2",
            dnsServer = "10.0.0.1",
            mtu = 1500,
        )
    }

    private fun prepareServerMode(): StartupConfig? {
        val enrollment = Enrollment.record(this)
        if (enrollment == null || enrollment.deviceToken.isBlank()) {
            failStart("server VPN requires a paired device credential")
            return null
        }

        val raw = runCatching {
            RustBridge.prepareServerVpn(
                enrollment.clusterEndpoint,
                enrollment.deviceId,
                RustBridge.clusterCaPath(this),
                enrollment.deviceToken,
            )
        }.onFailure {
            Log.e(TAG, "server VPN provisioning call failed", it)
        }.getOrNull()
        val result = raw?.let { runCatching { JSONObject(it) }.getOrNull() }
        if (result == null || !result.optBoolean("ok", false)) {
            failStart(result?.optString("error", "server VPN provisioning failed") ?: "server VPN provisioning failed")
            return null
        }
        if (!result.optBoolean("filter_active", false)) {
            failStart("region did not confirm an active server-side filter")
            return null
        }

        val assignedAddress = result.optString("assigned_address", "").trim()
        val inspectionCaPem = result.optString("inspection_ca_pem", "")
        if (assignedAddress.isBlank() || inspectionCaPem.isBlank()) {
            failStart("region returned an incomplete server VPN grant")
            return null
        }

        val caResult = CaTrust.ensurePemInstalled(this, inspectionCaPem, "region inspection CA")
        Log.i(TAG, "region inspection CA trust: $caResult")
        if (!caResult.isTrusted()) {
            notifyProvisioningRequired()
            failStart("region inspection CA is not system-trusted ($caResult)")
            return null
        }

        return StartupConfig(
            address = assignedAddress,
            // DNS is itself routed through WireGuard, so it exits from the region
            // rather than leaking directly from the child network.
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
                if (runCatching { RustBridge.isDataPathDown() }.getOrDefault(true)) {
                    Log.e(TAG, "data path down — tearing down TUN to restore connectivity")
                    ready = false
                    lastFailure = "VPN data path stopped unexpectedly"
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

    private fun failStart(detail: String) {
        lastFailure = detail.take(256)
        ready = false
        Log.e(TAG, detail)
        if (rustHandle != 0L) {
            runCatching { RustBridge.stopVpn(rustHandle) }
            rustHandle = 0L
        }
        runCatching { tun?.close() }
        tun = null
        running = false
        stopSelf()
    }

    override fun onDestroy() {
        ready = false
        running = false
        polling = false
        configPolling = false
        establishing = false
        activeFilterLocation = ""
        if (rustHandle != 0L) {
            RustBridge.stopVpn(rustHandle)
            rustHandle = 0L
        }
        runCatching { tun?.close() }
        tun = null
        super.onDestroy()
    }

    private fun buildNotification(): Notification {
        val mgr = getSystemService(NotificationManager::class.java)
        mgr.createNotificationChannel(
            NotificationChannel(CHANNEL, "PH Bulwark filtering", NotificationManager.IMPORTANCE_LOW),
        )
        return Notification.Builder(this, CHANNEL)
            .setContentTitle("PH Bulwark is protecting this device")
            .setContentText("Protected networking is starting. Applied status is reported only after enforcement is ready.")
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
                .setContentTitle("PH Bulwark — setup needed")
                .setContentText(
                    "Web filtering needs this device set up as a managed (Device Owner) device. Open PH Bulwark to finish setup.",
                )
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setAutoCancel(true)
                .build()
            mgr.notify(STATUS_NOTIF_ID, notification)
        }
    }

    private data class StartupConfig(
        val address: String,
        val dnsServer: String,
        val mtu: Int,
    )

    companion object {
        private const val TAG = "BulwarkVpn"
        private const val CHANNEL = "bulwark_vpn"
        private const val STATUS_CHANNEL = "bulwark_status"
        private const val NOTIF_ID = 1001
        private const val STATUS_NOTIF_ID = 1002
        private const val CONFIG_POLL_MS = 60_000L

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