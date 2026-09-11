package co.predatorhunters.bulwark.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import co.predatorhunters.bulwark.admin.Enrollment
import co.predatorhunters.bulwark.core.RustBridge
import co.predatorhunters.bulwark.notify.AlertNotifier
import org.json.JSONObject
import java.io.File

/**
 * The Bulwark filtering VPN client. `running` means Android started the service;
 * `ready` means the TUN + Rust enforcement data path are actually established.
 */
class BulwarkVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    private var rustHandle: Long = 0L
    @Volatile private var polling = false
    @Volatile private var configPolling = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        running = true
        ready = false
        startForeground(NOTIF_ID, buildNotification())
        if (tun == null) establish()
        return START_STICKY
    }

    private fun establish() {
        RustBridge.ensureLoaded()

        // Wire interception is viable only when our inspection CA is system-trusted.
        // Non-managed/cert-pinned traffic remains covered by the accessibility path;
        // never create a TUN that would simply blackhole HTTPS.
        val caResult = co.predatorhunters.bulwark.admin.CaTrust.ensureInstalled(this)
        Log.i(TAG, "inspection CA trust: $caResult")
        val caTrusted = caResult == co.predatorhunters.bulwark.admin.CaTrust.Result.INSTALLED_SYSTEM ||
            caResult == co.predatorhunters.bulwark.admin.CaTrust.Result.ALREADY_TRUSTED
        if (!caTrusted) {
            Log.e(TAG, "not bringing up tunnel: inspection CA is not system-trusted ($caResult)")
            ready = false
            notifyProvisioningRequired()
            running = false
            stopSelf()
            return
        }

        val pfd = Builder()
            .setSession("PH Bulwark")
            .setMtu(1500)
            .addAddress("10.0.0.2", 32)
            .addDnsServer("10.0.0.1")
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            .addDisallowedApplication(packageName)
            .establish()

        if (pfd == null) {
            Log.e(TAG, "establish() returned null — VPN consent not granted?")
            ready = false
            stopSelf()
            return
        }
        tun = pfd
        rustHandle = runCatching { RustBridge.startVpn(this, pfd.fd, deviceConfigJson()) }
            .onFailure { Log.e(TAG, "Rust VPN data path failed to start", it) }
            .getOrDefault(0L)

        if (rustHandle == 0L || runCatching { RustBridge.isDataPathDown() }.getOrDefault(true)) {
            Log.e(TAG, "Rust VPN data path did not become ready; releasing tunnel")
            ready = false
            stopSelf()
            return
        }

        ready = true
        Log.i(TAG, "Bulwark VPN ready (rustHandle=$rustHandle)")
        startAlertPoller()
        startConfigPoller()
    }

    private fun deviceConfigJson(): String {
        val enrollment = Enrollment.record(this)
        val json = JSONObject()
            .put("device_id", Enrollment.stableDeviceId(this))
            .put("profile", ChildConfigSync.appliedProfile(this))
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

    override fun onDestroy() {
        ready = false
        running = false
        polling = false
        configPolling = false
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
            .setContentText("Protective filtering is starting. Applied status is reported only after enforcement is ready.")
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

    companion object {
        private const val TAG = "BulwarkVpn"
        private const val CHANNEL = "bulwark_vpn"
        private const val STATUS_CHANNEL = "bulwark_status"
        private const val NOTIF_ID = 1001
        private const val STATUS_NOTIF_ID = 1002
        private const val CONFIG_POLL_MS = 60_000L

        /** Android service lifecycle only; do not use as protection readiness. */
        @Volatile var running = false
            private set

        /** True only while TUN + Rust enforcement loop are established and healthy. */
        @Volatile var ready = false
            private set
    }
}
