package co.libertyware.aegis.accessibility

import android.accessibilityservice.AccessibilityService
import android.content.Context
import android.graphics.Color
import android.graphics.PixelFormat
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.FrameLayout
import android.widget.TextView
import co.libertyware.aegis.core.RustBridge
import co.libertyware.aegis.tamper.TamperReporter

/**
 * The end-to-end / cert-pinned answer.
 *
 * Reads the text apps have ALREADY decrypted and rendered on screen (WhatsApp,
 * Signal, Messenger secret chats, Telegram, …) plus notification text, and feeds
 * it into the SAME deterministic grooming pipeline as network chat
 * ([RustBridge.analyzeText]). This is conventional text extraction from the
 * accessibility tree — NOT a model, NOT a vision-LLM.
 *
 * Requires the guardian to grant Accessibility in Settings (consent — see
 * docs/security/legal-consent.md). Only the apps in [MONITORED] are inspected;
 * captured text is analysed on-device and never leaves the device except as a
 * redacted guardian alert.
 */
class AegisAccessibilityService : AccessibilityService() {

    override fun onServiceConnected() {
        RustBridge.ensureLoaded()
        Log.i(TAG, "Aegis accessibility capture connected")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        event ?: return
        val pkg = event.packageName?.toString() ?: return

        // Uninstall-guard: when the package installer / Settings opens, check
        // whether it's an attempt to remove US and, if so, alert + bounce away.
        if (event.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED &&
            pkg in UNINSTALL_SURFACES
        ) {
            guardAgainstUninstall()
            return
        }

        if (pkg !in MONITORED) return

        when (event.eventType) {
            AccessibilityEvent.TYPE_NOTIFICATION_STATE_CHANGED -> {
                val text = event.text.joinToString(" ").trim()
                if (text.isNotEmpty()) submit(pkg, "notif", text)
            }
            AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED,
            AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED -> {
                val root = rootInActiveWindow ?: return
                val text = collectText(root).trim()
                if (text.isNotEmpty()) submit(pkg, threadIdFor(root, pkg), text)
            }
        }
    }

    private fun submit(pkg: String, thread: String, text: String) {
        val verdictJson = runCatching { RustBridge.analyzeText(pkg, thread, text) }
            .getOrDefault("{\"error\":\"bridge unavailable\"}")
        when {
            // HIGH-confidence / illegal -> disruptive on-screen block (+ alert).
            shouldBlock(verdictJson) -> {
                Log.w(TAG, "high-confidence harmful content in $pkg — blocking + alerting")
                blockContent()
                notifyGuardian(pkg, verdictJson)
            }
            // Borderline non-SAFE -> alert the guardian, but DON'T slam the screen.
            // The deterministic detector still fired and the parent is still told;
            // this just stops over-blocking benign-looking chat (the false-positive fix).
            isFlagged(verdictJson) -> {
                Log.w(TAG, "borderline content in $pkg — alerting guardian (no block)")
                notifyGuardian(pkg, verdictJson)
            }
        }
    }

    /**
     * The disruptive on-screen block is reserved for HIGH-CONFIDENCE content: the
     * POLICY engine decided BLOCK, or it's suspected CSAM (illegal — always block).
     * Borderline grooming/adult verdicts are alerted, not blocked. The detector is
     * untouched (it still fired); only the *enforcement* is gated on confidence —
     * the deliberate fix for benign chat being slammed off the screen.
     */
    private fun shouldBlock(json: String): Boolean =
        json.contains("\"action\":\"BLOCK\"") || json.contains("\"CSAM")

    /** Any non-SAFE verdict — worth telling the guardian even if we don't block. */
    private fun isFlagged(json: String): Boolean =
        !json.contains("\"category\":\"SAFE\"") && !json.contains("\"error\"")

    /**
     * ENFORCE on the device: bounce off the harmful screen, cover it with a PH
     * Bulwark block notice, and sound an audible alert so it's unmistakable.
     * (Remote guardian alerting is wired with account linking.)
     */
    private fun blockContent() {
        Handler(Looper.getMainLooper()).post {
            performGlobalAction(GLOBAL_ACTION_HOME)
            playAlert()
            showBlockOverlay()
        }
    }

    private fun playAlert() {
        runCatching {
            val uri = android.media.RingtoneManager.getDefaultUri(android.media.RingtoneManager.TYPE_NOTIFICATION)
            android.media.RingtoneManager.getRingtone(applicationContext, uri)?.play()
        }
    }

    /**
     * Quietly alert the guardian about a flagged detection: a status-bar
     * notification carrying the policy's CONTENT-FREE reason (never the message
     * text). Best-effort + non-disruptive — the remote/parent-app alert rides the
     * account-linked path; this is the local signal so a borderline detection
     * isn't silent just because we chose not to block the screen.
     */
    private fun notifyGuardian(pkg: String, json: String) {
        runCatching {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as android.app.NotificationManager
            val channelId = "ph_bulwark_alerts"
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                nm.createNotificationChannel(
                    android.app.NotificationChannel(
                        channelId, "PH Bulwark alerts",
                        android.app.NotificationManager.IMPORTANCE_HIGH,
                    ),
                )
            }
            val reason = Regex("\"reason\":\"([^\"]*)\"").find(json)?.groupValues?.get(1)
                ?: "Flagged content detected"
            val builder = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                android.app.Notification.Builder(this, channelId)
            } else {
                @Suppress("DEPRECATION")
                android.app.Notification.Builder(this)
            }
            val notification = builder
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle("PH Bulwark — content flagged")
                .setContentText(reason)
                .setAutoCancel(true)
                .build()
            nm.notify(pkg.hashCode(), notification)
        }
    }

    private var overlay: View? = null

    private fun showBlockOverlay() {
        if (overlay != null) return
        val wm = getSystemService(Context.WINDOW_SERVICE) as WindowManager
        val root = FrameLayout(this).apply { setBackgroundColor(0xFF0F3D5C.toInt()) }
        root.addView(
            TextView(this).apply {
                text = "🛡️\n\nBlocked by PH Bulwark\nThis content was flagged as unsafe."
                setTextColor(Color.WHITE); textSize = 22f; gravity = Gravity.CENTER
                setPadding(48, 48, 48, 48)
            },
            FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
                .apply { gravity = Gravity.CENTER },
        )
        val lp = WindowManager.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
            PixelFormat.OPAQUE,
        )
        runCatching { wm.addView(root, lp); overlay = root }
        Handler(Looper.getMainLooper()).postDelayed({ removeOverlay() }, 3000)
    }

    private fun removeOverlay() {
        overlay?.let { v -> runCatching { (getSystemService(Context.WINDOW_SERVICE) as WindowManager).removeView(v) } }
        overlay = null
    }

    /**
     * On an installer / Settings screen, if the visible text is about removing the
     * Aegis app, raise an `APP_UNINSTALL_ATTEMPT` alert and navigate Home. This is
     * FRICTION + DETECTION, not an absolute block — a determined user can still
     * proceed (and on Device Owner the uninstall is blocked outright), but the
     * guardian is always told.
     */
    private fun guardAgainstUninstall() {
        val root = rootInActiveWindow ?: return
        val screen = collectText(root).lowercase()
        // The app's user-facing label is "PH Bulwark"; the package id is ...aegis.
        val mentionsApp = screen.contains("bulwark") || screen.contains("aegis")
        val isUninstall = screen.contains("uninstall") || screen.contains("do you want to uninstall")
        if (mentionsApp && isUninstall) {
            Log.w(TAG, "uninstall attempt detected on PH Bulwark — alerting guardian")
            TamperReporter.report(this, TamperReporter.APP_UNINSTALL_ATTEMPT)
            performGlobalAction(GLOBAL_ACTION_HOME)
        }
    }

    private fun collectText(node: AccessibilityNodeInfo): String {
        val sb = StringBuilder()
        node.text?.let { sb.append(it).append(' ') }
        for (i in 0 until node.childCount) {
            node.getChild(i)?.let { sb.append(collectText(it)) }
        }
        return sb.toString()
    }

    /** Best-effort stable per-conversation id so the grooming state machine can
     *  correlate messages across a thread. Refined per app over time. */
    private fun threadIdFor(root: AccessibilityNodeInfo, pkg: String): String =
        "$pkg:${root.window?.title ?: root.hashCode()}"

    override fun onInterrupt() {}

    companion object {
        private const val TAG = "AegisA11y"
        // Apps the network can't read (E2E / cert-pinned) → on-device capture path.
        private val MONITORED = setOf(
            "com.whatsapp",
            "org.thoughtcrime.securesms",   // Signal
            "com.facebook.orca",            // Messenger
            "com.instagram.android",
            "com.snapchat.android",
            "org.telegram.messenger",
        )

        // Surfaces an app-removal flows through — watched by the uninstall-guard.
        private val UNINSTALL_SURFACES = setOf(
            "com.google.android.packageinstaller",
            "com.android.packageinstaller",
            "com.android.settings",
        )
    }
}
