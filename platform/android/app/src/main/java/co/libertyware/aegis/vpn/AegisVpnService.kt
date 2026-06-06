package co.libertyware.aegis.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import co.libertyware.aegis.admin.Enrollment
import co.libertyware.aegis.core.RustBridge
import co.libertyware.aegis.notify.AlertNotifier
import org.json.JSONObject

/**
 * The Aegis filtering VPN client.
 *
 * Establishes a local TUN via [VpnService.Builder] capturing all device traffic,
 * then hands the tunnel file descriptor to the Rust core ([RustBridge.startVpn])
 * which runs the real-time intercept → classify → policy → block/blur/mute +
 * guardian-email loop. Heavy media analysis offloads to the home cluster per
 * aegis-infer's routing.
 *
 * HONEST COVERAGE (PLAN §0a): Android 7+ ignores user-installed CAs for most
 * apps, and end-to-end-encrypted / cert-pinned apps can't be read on the wire at
 * all. Those are handled on-device by
 * [AegisAccessibilityService][co.libertyware.aegis.accessibility.AegisAccessibilityService],
 * not here.
 */
class AegisVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    private var rustHandle: Long = 0L
    @Volatile private var polling = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIF_ID, buildNotification())
        if (tun == null) establish()
        return START_STICKY
    }

    private fun establish() {
        RustBridge.ensureLoaded()
        val pfd = Builder()
            .setSession("PH Bulwark")
            .setMtu(1500)
            .addAddress("10.0.0.2", 32)
            .addDnsServer("10.0.0.1")
            .addRoute("0.0.0.0", 0)   // capture all IPv4
            .addRoute("::", 0)        // and IPv6
            // Exclude ourselves so our own cluster traffic isn't re-filtered/looped.
            .addDisallowedApplication(packageName)
            .establish()

        if (pfd == null) {
            Log.e(TAG, "establish() returned null — VPN consent not granted?")
            stopSelf()
            return
        }
        tun = pfd
        // Rust owns the read/write loop on the raw fd from here.
        rustHandle = RustBridge.startVpn(this, pfd.fd, deviceConfigJson())
        Log.i(TAG, "Aegis VPN established (rustHandle=$rustHandle)")
        startAlertPoller()
    }

    private fun deviceConfigJson(): String {
        val enrollment = Enrollment.record(this)
        val json = JSONObject()
            .put("device_id", Enrollment.stableDeviceId(this))
        if (enrollment != null) {
            json.put("cluster_endpoint", enrollment.clusterEndpoint)
                .put("child_id", enrollment.childId)
                .put("family_id", enrollment.familyId)
        }
        return json.toString()
    }

    /**
     * Surface flagged alerts to the guardian. Polls the Rust core for the next
     * alert and posts each as a notification (safe evidence + approve/deny) via
     * [AlertNotifier]. This is the same-device path; remote delivery to a separate
     * parent device is via FCM (see docs/design/parent-notifications.md).
     */
    private fun startAlertPoller() {
        if (polling) return
        polling = true
        Thread({
            while (polling) {
                val alert = runCatching { RustBridge.nextAlert() }.getOrNull()
                if (alert != null) AlertNotifier.notify(this, alert)
                else runCatching { Thread.sleep(2_000) }
            }
        }, "aegis-alert-poller").apply { isDaemon = true }.start()
    }

    override fun onDestroy() {
        polling = false
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
            NotificationChannel(CHANNEL, "PH Bulwark filtering", NotificationManager.IMPORTANCE_LOW)
        )
        return Notification.Builder(this, CHANNEL)
            .setContentTitle("PH Bulwark is protecting this device")
            .setContentText("Filtering content and watching for grooming signals.")
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setOngoing(true)
            .build()
    }

    companion object {
        private const val TAG = "AegisVpn"
        private const val CHANNEL = "aegis_vpn"
        private const val NOTIF_ID = 1001
    }
}
