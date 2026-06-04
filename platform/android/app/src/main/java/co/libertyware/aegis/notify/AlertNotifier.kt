package co.libertyware.aegis.notify

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.Base64
import org.json.JSONObject

/**
 * Turns a flagged alert (a JSON `AlertEvent` from the Rust core) into a guardian
 * notification, with the evidence appropriate to the category and Approve /
 * "Keep blocked" actions.
 *
 * EVIDENCE & LAW (docs/security/data-handling.md, docs/design/parent-notifications.md):
 *  - adult image / video → show the **SAFE (blurred/cropped) thumbnail** only
 *    (`evidence.safe_thumbnail`), never the original frame.
 *  - grooming           → show the **redacted text snippet** (`redacted_context`).
 *  - CSAM_SUSPECTED     → **never show the image.** It is blocked and flagged for
 *    reporting; transmitting it (even to the guardian) is unlawful.
 */
object AlertNotifier {
    private const val CHANNEL = "aegis_alerts"
    const val ACTION_APPROVE = "co.libertyware.aegis.APPROVE"
    const val ACTION_DENY = "co.libertyware.aegis.DENY"
    const val EXTRA_ALERT_ID = "alert_id"

    // aegis.v1.Category ordinals.
    private const val CAT_ADULT_IMAGE = 2
    private const val CAT_ADULT_AUDIO = 3
    private const val CAT_ADULT_TEXT = 4
    private const val CAT_GROOMING = 5
    private const val CAT_CSAM = 6

    /** Post a notification for one alert JSON. Safe to call from any thread. */
    fun notify(ctx: Context, alertJson: String) {
        val a = runCatching { JSONObject(alertJson) }.getOrNull() ?: return
        val alertId = a.optString("alert_id", System.nanoTime().toString())
        val category = a.optInt("category", 0)
        val body = a.optString("redacted_context", "Predator Hunters Bulwark flagged content on this device.")

        ensureChannel(ctx)

        val builder = Notification.Builder(ctx, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(titleFor(category))
            .setContentText(body)
            .setAutoCancel(true)

        // Evidence picture: ONLY for non-CSAM, and only the SAFE thumbnail the
        // core placed in evidence.safe_thumbnail (blurred/cropped).
        if (category != CAT_CSAM) {
            thumbnail(a)?.let { bmp ->
                builder.style = Notification.BigPictureStyle()
                    .bigPicture(bmp)
                    .setBigContentTitle(titleFor(category))
            }
        }

        // Approve / deny (routed to the policy engine; see RustBridge).
        builder.addAction(action(ctx, ACTION_APPROVE, "Approve", alertId))
        builder.addAction(action(ctx, ACTION_DENY, "Keep blocked", alertId))

        ctx.getSystemService(NotificationManager::class.java)
            .notify(alertId.hashCode(), builder.build())
    }

    private fun titleFor(category: Int): String = when (category) {
        CAT_ADULT_IMAGE -> "Blocked an adult image"
        CAT_ADULT_AUDIO -> "Muted adult audio"
        CAT_ADULT_TEXT -> "Blocked adult text"
        CAT_GROOMING -> "Possible grooming detected"
        CAT_CSAM -> "Possible CSAM — blocked & flagged (image not shown)"
        else -> "Predator Hunters Bulwark stepped in"
    }

    private fun thumbnail(a: JSONObject): Bitmap? {
        val ev = a.optJSONObject("evidence") ?: return null
        val b64 = ev.optString("safe_thumbnail", "")
        if (b64.isEmpty()) return null
        return runCatching {
            val bytes = Base64.decode(b64, Base64.DEFAULT)
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
        }.getOrNull()
    }

    private fun action(ctx: Context, act: String, label: String, alertId: String): Notification.Action {
        val intent = Intent(ctx, ReviewActionReceiver::class.java).apply {
            action = act
            putExtra(EXTRA_ALERT_ID, alertId)
        }
        val pi = PendingIntent.getBroadcast(
            ctx, (act + alertId).hashCode(), intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Action.Builder(null, label, pi).build()
    }

    private fun ensureChannel(ctx: Context) {
        ctx.getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, "Predator Hunters Bulwark alerts", NotificationManager.IMPORTANCE_HIGH)
        )
    }
}
