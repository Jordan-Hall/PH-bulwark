package co.predatorhunters.bulwark.vpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import androidx.core.content.ContextCompat
import co.predatorhunters.bulwark.admin.Enrollment
import co.predatorhunters.bulwark.core.RustBridge
import org.json.JSONObject

/**
 * Workflow B step 2 (docs/design/parent-controlled-vpn.md §3): apply the
 * guardian's desired runtime config on this device.
 *
 * Fetches the device's OWN ChildConfig (ChildControl.GetChildConfig via
 * [RustBridge.fetchChildConfig]) and reconciles the filtering VPN to it:
 * `filtering_enabled` starts/stops [BulwarkVpnService]. CONTENT-FREE — the
 * config carries policy/routing only, never message or media data.
 *
 * Replay/rollback defense: a config STRICTLY OLDER than the last applied
 * version (persisted here) is ignored, so a captured old "filtering off"
 * config can never roll protection back. The current (same-version) config is
 * re-enforced idempotently so the device converges to the guardian's desired
 * state even after a local restart.
 *
 * Transparent + consented: starting the VPN here only ever succeeds when the
 * one-time VpnService consent is already in place — never a covert grant.
 */
object ChildConfigSync {
    private const val TAG = "BulwarkChildConfig"
    private const val PREFS = "bulwark_child_config"
    private const val KEY_APPLIED_VERSION = "applied_config_version"
    private const val KEY_APPLIED_PROFILE = "applied_profile"

    /** Last config_version this device successfully applied (0 = none yet). */
    fun appliedVersion(ctx: Context): Long =
        prefs(ctx).getLong(KEY_APPLIED_VERSION, 0L)

    /**
     * Last guardian strictness band this device applied ("YOUNG_CHILD",
     * "PRETEEN", "TEEN", "CUSTOM"; "" = none yet -> Rust keeps its baseline).
     * Read by [BulwarkVpnService.deviceConfigJson] so the Rust core comes back
     * up under the right band after a process restart.
     */
    fun appliedProfile(ctx: Context): String =
        prefs(ctx).getString(KEY_APPLIED_PROFILE, "") ?: ""

    /**
     * Fetch the desired config from the enrolled server and reconcile the VPN.
     * Network round-trip — call from a background thread only. Safe no-op when
     * the device is not yet paired, the server is unreachable, or no guardian
     * config exists yet.
     */
    fun fetchAndReconcile(ctx: Context) {
        val enrollment = Enrollment.record(ctx) ?: return // not paired yet
        val json = runCatching {
            RustBridge.ensureLoaded()
            // Passing the applied version makes this poll double as the ack the
            // parent console shows ("applied ✓ vN") — the server records it.
            RustBridge.fetchChildConfig(
                enrollment.clusterEndpoint,
                enrollment.deviceId,
                appliedVersion(ctx),
                RustBridge.clusterCaPath(ctx),
            )
        }.getOrNull() ?: return
        val obj = runCatching { JSONObject(json) }.getOrNull() ?: return
        if (!obj.optBoolean("ok", false)) {
            Log.i(TAG, "no config applied: ${obj.optString("error", "fetch failed")}")
            return
        }

        val version = obj.optLong("config_version", 0L)
        val applied = appliedVersion(ctx)
        if (version < applied) {
            // Stale/replayed config — NEVER roll protection back to it.
            Log.w(TAG, "ignoring stale config v$version (applied v$applied)")
            return
        }

        // Reconcile the strictness band. The Rust bridge already live-applied it
        // for analyzeText (version-gated, no restart needed); persisting it here
        // lets deviceConfigJson() re-seed the band after a process restart.
        val profile = obj.optString("profile", "")
        if (profile.isNotEmpty() && profile != appliedProfile(ctx)) {
            prefs(ctx).edit().putString(KEY_APPLIED_PROFILE, profile).apply()
            Log.i(TAG, "applied guardian strictness band $profile")
        }

        val filteringEnabled = obj.optBoolean("filtering_enabled", true)
        if (filteringEnabled) {
            if (!BulwarkVpnService.running) {
                if (VpnService.prepare(ctx) != null) {
                    // Consent missing: never start covertly; onboarding re-grants.
                    Log.i(TAG, "guardian enabled filtering but VPN consent is missing")
                    return // not applied — retried on the next sync
                }
                ContextCompat.startForegroundService(
                    ctx,
                    Intent(ctx, BulwarkVpnService::class.java),
                )
            }
        } else if (BulwarkVpnService.running) {
            ctx.stopService(Intent(ctx, BulwarkVpnService::class.java))
        }

        if (version > applied) {
            prefs(ctx).edit().putLong(KEY_APPLIED_VERSION, version).apply()
            Log.i(
                TAG,
                "applied guardian config v$version (filtering ${if (filteringEnabled) "on" else "off"})",
            )
        }
    }

    private fun prefs(ctx: Context) =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
