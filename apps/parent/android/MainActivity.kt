/*
 * PH Bulwark Manager — custom Android entrypoint + native UnifiedPush receive.
 *
 * WHY THIS FILE IS CHECKED IN (and how dx 0.8 consumes it):
 *   The Manager is a `dx`-built Dioxus app. dx 0.8.0-alpha regenerates the whole
 *   Android scaffold under `target/dx/…` (gitignored) on every build, so we can't
 *   hand-place Kotlin in there. dx DOES expose a committed-source seam though:
 *   `[application].android_main_activity` in Dioxus.toml points dx at THIS file,
 *   which it writes VERBATIM to `app/src/main/kotlin/dev/dioxus/main/MainActivity.kt`
 *   and compiles every build (src/build/android.rs:279-291 — note: the custom path
 *   is read raw, it does NOT pass through handlebars, so the `typealias` below must
 *   be the literal applicationId, not a `{{…}}` placeholder).
 *
 *   A Kotlin file may hold several top-level classes, so the UnifiedPush receive
 *   side ships in THIS same file as a second class (`BulwarkPushService`). No dx
 *   fork and no post-build manifest hack are needed.
 *
 * UNIFIEDPUSH (FOSS, Apache-2.0 — `org.unifiedpush.android:connector`): the modern
 *   3.x connector delivers via a bound `PushService` (the old `MessagingReceiver`
 *   BroadcastReceiver is deprecated upstream). The connector AAR embeds its OWN
 *   exported receiver + the package-visibility `<queries>`; AGP merges those library
 *   manifest entries at build, so our custom AndroidManifest.xml only has to declare
 *   our service (action `org.unifiedpush.android.connector.PUSH_EVENT`) and the
 *   POST_NOTIFICATIONS permission. No Google/Apple services are involved.
 *
 * GUARDIAN-AUTH IS UNTOUCHED: receiving an endpoint just writes it to the app's
 *   private files dir; the token-gated `Review.RegisterPushTarget` RPC (Rust
 *   `crate::api::register_push_target`, behind `NATIVE_PUSH_ENABLED`, issue #140)
 *   still requires the guardian session token. This file never sends anything to
 *   the cluster.
 */
package dev.dioxus.main

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import org.unifiedpush.android.connector.FailedReason
import org.unifiedpush.android.connector.PushService
import org.unifiedpush.android.connector.UnifiedPush
import org.unifiedpush.android.connector.data.PushEndpoint
import org.unifiedpush.android.connector.data.PushMessage
import java.io.File

// dx's template emits this as `typealias BuildConfig = {{application_id}}.BuildConfig`,
// but the custom-activity path is copied raw (no handlebars), so we write the
// resolved applicationId literally. MUST match [bundle]/[android] `identifier`.
typealias BuildConfig = co.predatorhunters.bulwark.manager.BuildConfig

/** Shared constants for the alert notification channel + endpoint handoff file. */
object BulwarkPush {
    const val TAG = "BulwarkPush"
    const val CHANNEL_ID = "bulwark_guardian_alerts"
    const val CHANNEL_NAME = "Guardian alerts"

    /**
     * Endpoint handoff path: the app-private files dir + `bulwark/push_endpoint.txt`,
     * IDENTICAL to the Rust side's `app_config_dir()` (config.rs resolves the same
     * `getFilesDir()` over JNI and appends `bulwark/`). The `PushService` writes the
     * distributor-supplied endpoint URL here; the Rust `saved_push_endpoint()` reads
     * it on the Notifications panel mount — no JNI callback into a (possibly dead)
     * Rust process required.
     */
    fun endpointFile(context: Context): File {
        val dir = File(context.filesDir, "bulwark")
        if (!dir.exists()) dir.mkdirs()
        return File(dir, "push_endpoint.txt")
    }

    fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val mgr = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            if (mgr.getNotificationChannel(CHANNEL_ID) == null) {
                val channel = NotificationChannel(
                    CHANNEL_ID,
                    CHANNEL_NAME,
                    NotificationManager.IMPORTANCE_HIGH,
                ).apply {
                    description = "Redacted, content-free child-safety alerts"
                }
                mgr.createNotificationChannel(channel)
            }
        }
    }
}

/**
 * The Dioxus/wry host activity. `WryActivity` lives in this same `dev.dioxus.main`
 * package (wry injects it at build), so it resolves unqualified. We extend it to
 * (1) create the alert notification channel, (2) request the POST_NOTIFICATIONS
 * runtime grant on API 33+ (declaring it is not enough — without the grant the
 * system silently drops notifications), and (3) link to a UnifiedPush distributor
 * so a NEW_ENDPOINT is actually delivered. Without a register() call the receive
 * side is dead code; with no distributor installed it's a graceful no-op.
 */
class MainActivity : WryActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        BulwarkPush.ensureChannel(this)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(android.Manifest.permission.POST_NOTIFICATIONS),
                    /* requestCode = */ 0x6275, // 'bu'
                )
            }
        }

        // Link to a UnifiedPush distributor (e.g. ntfy) if one is installed, then
        // register so the distributor hands us a NEW_ENDPOINT. tryUseDefaultDistributor
        // is a no-op when no distributor is present (the guardian can still paste an
        // endpoint by hand in the Notifications panel).
        try {
            if (UnifiedPush.getAckDistributor(this) != null) {
                UnifiedPush.register(this)
            } else {
                UnifiedPush.tryUseDefaultDistributor(this) { success ->
                    Log.d(BulwarkPush.TAG, "UnifiedPush distributor linked=$success")
                    if (success) UnifiedPush.register(this)
                }
            }
        } catch (t: Throwable) {
            // Never let push linking crash the console.
            Log.w(BulwarkPush.TAG, "UnifiedPush link/register skipped: ${t.message}")
        }
    }
}

/**
 * Receives UnifiedPush events from the distributor (forwarded by the connector
 * library's embedded receiver via the `PUSH_EVENT` intent — declared on this
 * service in AndroidManifest.xml). Runs even when the Dioxus process is otherwise
 * idle, which is the whole point of push.
 *
 *  - onNewEndpoint → persist the endpoint URL to the handoff file the Rust side reads.
 *  - onMessage     → post a CONTENT-FREE system notification. We parse the redacted
 *                    JSON body the server sends but deliberately surface only a
 *                    generic "new safety alert" line — no titles, no snippets, no
 *                    media — honoring the privacy invariant (CSAM is never shown).
 */
class BulwarkPushService : PushService() {
    override fun onNewEndpoint(endpoint: PushEndpoint, instance: String) {
        try {
            BulwarkPush.endpointFile(this).writeText(endpoint.url.trim())
            Log.d(BulwarkPush.TAG, "Stored UnifiedPush endpoint for handoff")
        } catch (t: Throwable) {
            Log.w(BulwarkPush.TAG, "Failed to store endpoint: ${t.message}")
        }
    }

    override fun onMessage(message: PushMessage, instance: String) {
        // The relayed payload is already redacted + content-free server-side. We
        // deliberately surface NONE of it: the notification body is a fixed generic
        // line, so nothing sensitive can reach the lock screen even if a future
        // payload carried more than intended (and CSAM is never shown — see doc).
        // We don't parse the body at all: there is no field we would render, so
        // there's nothing to validate.
        notifyGeneric()
        Log.d(BulwarkPush.TAG, "Posted content-free alert")
    }

    override fun onRegistrationFailed(reason: FailedReason, instance: String) {
        Log.w(BulwarkPush.TAG, "UnifiedPush registration failed: $reason")
    }

    override fun onUnregistered(instance: String) {
        try {
            val f = BulwarkPush.endpointFile(this)
            if (f.exists()) f.delete()
        } catch (_: Throwable) {
        }
        Log.d(BulwarkPush.TAG, "UnifiedPush unregistered; cleared endpoint handoff")
    }

    private fun notifyGeneric() {
        BulwarkPush.ensureChannel(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            // No runtime grant yet → the system would drop it; skip quietly.
            return
        }
        // Tapping the alert opens the Manager so the guardian lands on the review,
        // instead of having to find the app manually (codex P2).
        val contentIntent = android.app.PendingIntent.getActivity(
            this,
            0,
            android.content.Intent(this, MainActivity::class.java).addFlags(
                android.content.Intent.FLAG_ACTIVITY_NEW_TASK or
                    android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP,
            ),
            android.app.PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = NotificationCompat.Builder(this, BulwarkPush.CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("PH Bulwark Manager")
            .setContentText("New safety alert — open the Manager to review.")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(contentIntent)
            .setAutoCancel(true)
            .build()
        try {
            NotificationManagerCompat.from(this).notify(BulwarkPush.TAG.hashCode(), notification)
        } catch (se: SecurityException) {
            Log.w(BulwarkPush.TAG, "notify denied: ${se.message}")
        }
    }
}
