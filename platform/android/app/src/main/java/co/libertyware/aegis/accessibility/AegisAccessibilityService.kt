package co.libertyware.aegis.accessibility

import android.accessibilityservice.AccessibilityService
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import co.libertyware.aegis.core.RustBridge

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
        // Hand to the Rust grooming engine. A flagged Verdict raises a guardian
        // alert via the same aegis-alert path the network loop uses.
        val verdictJson = runCatching { RustBridge.analyzeText(pkg, thread, text) }
            .getOrDefault("{\"error\":\"bridge unavailable\"}")
        if (verdictJson.contains("\"GROOMING") || verdictJson.contains("\"CSAM")) {
            Log.w(TAG, "flagged text in $pkg")
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
    }
}
