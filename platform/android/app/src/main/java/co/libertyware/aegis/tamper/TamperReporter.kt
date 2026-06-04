package co.libertyware.aegis.tamper

import android.content.Context
import co.libertyware.aegis.core.RustBridge
import co.libertyware.aegis.notify.AlertNotifier
import org.json.JSONObject

/**
 * Funnels a detected tamper / protection-downgrade event to the guardian:
 *  1. reports it to the Rust core ([RustBridge.reportTamper]) so it rides the same
 *     redacted relay path to the home cluster as content alerts (where the
 *     guardian — possibly on another device — sees it), and
 *  2. posts an immediate on-device PROTECTION_DISABLED notification as a local,
 *     real-time signal.
 *
 * TRANSPARENT + CONSENTED: the managed child device visibly runs Aegis; this is
 * parental-control tamper-evidence, not covert surveillance. Carries NO content —
 * only *which* protection changed.
 */
object TamperReporter {
    // aegis.v1.TamperKind ordinals — keep in sync with crates/aegis-proto/proto/aegis.proto.
    const val UNSPECIFIED = 0
    const val APP_UNINSTALL_ATTEMPT = 1
    const val DEVICE_ADMIN_REMOVED = 2
    const val ACCESSIBILITY_DISABLED = 3
    const val VPN_DISABLED = 4
    const val SAFE_MODE_OR_FACTORY_RESET = 6

    /** AlertKind.PROTECTION_DISABLED ordinal (for the local notification JSON). */
    private const val ALERT_PROTECTION_DISABLED = 3

    fun report(ctx: Context, kind: Int) {
        runCatching {
            RustBridge.ensureLoaded()
            RustBridge.reportTamper(kind)
        }
        val json = JSONObject()
            .put("alert_id", "tamper-$kind-${System.currentTimeMillis() / 1000}")
            .put("kind", ALERT_PROTECTION_DISABLED)
            .put("category", 0) // not a content category — a status signal
            .put("redacted_context", message(kind))
            .toString()
        runCatching { AlertNotifier.notify(ctx, json) }
    }

    fun message(kind: Int): String = when (kind) {
        APP_UNINSTALL_ATTEMPT -> "Someone tried to remove the PH Bulwark app on this device."
        DEVICE_ADMIN_REMOVED -> "PH Bulwark device management was turned off on this device."
        ACCESSIBILITY_DISABLED -> "PH Bulwark on-device monitoring was turned off on this device."
        VPN_DISABLED -> "The PH Bulwark filtering VPN was turned off on this device."
        SAFE_MODE_OR_FACTORY_RESET -> "This device entered safe mode or was reset."
        else -> "Aegis protection changed on this device."
    }
}
