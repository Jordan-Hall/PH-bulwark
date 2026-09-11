package co.predatorhunters.bulwark.vpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import androidx.core.content.ContextCompat
import co.predatorhunters.bulwark.admin.Enrollment
import co.predatorhunters.bulwark.core.RustBridge
import org.json.JSONObject

/** Reconciles guardian desired config without ever acknowledging intent as applied state. */
object ChildConfigSync {
    private const val TAG = "BulwarkChildConfig"
    private const val PREFS = "bulwark_child_config"
    private const val KEY_APPLIED_VERSION = "applied_config_version"
    private const val KEY_APPLIED_PROFILE = "applied_profile"
    private const val KEY_APPLIED_FILTER_LOCATION = "applied_filter_location"
    private const val KEY_SYNC_STATE = "sync_state"
    private const val KEY_SYNC_DETAIL = "sync_detail"

    private const val FILTER_ON_DEVICE = "on_device"
    private const val FILTER_ON_SERVER = "on_server"

    enum class SyncState {
        DESIRED,
        APPLYING,
        APPLIED,
        DEGRADED,
        UNSUPPORTED,
    }

    fun appliedVersion(ctx: Context): Long =
        prefs(ctx).getLong(KEY_APPLIED_VERSION, 0L)

    fun appliedProfile(ctx: Context): String =
        prefs(ctx).getString(KEY_APPLIED_PROFILE, "") ?: ""

    fun appliedFilterLocation(ctx: Context): String =
        prefs(ctx).getString(KEY_APPLIED_FILTER_LOCATION, FILTER_ON_DEVICE) ?: FILTER_ON_DEVICE

    fun cloudFilteringRequested(ctx: Context): Boolean =
        appliedFilterLocation(ctx) == FILTER_ON_SERVER

    fun syncState(ctx: Context): SyncState = runCatching {
        SyncState.valueOf(prefs(ctx).getString(KEY_SYNC_STATE, SyncState.DESIRED.name)!!)
    }.getOrDefault(SyncState.DESIRED)

    fun syncDetail(ctx: Context): String =
        prefs(ctx).getString(KEY_SYNC_DETAIL, "") ?: ""

    /**
     * Fetch desired config and reconcile it. `have_version` is always the last
     * successfully applied version; unsupported/degraded/applying attempts never
     * advance it, so the guardian console cannot receive a false applied ack.
     */
    fun fetchAndReconcile(ctx: Context) {
        val enrollment = Enrollment.record(ctx) ?: return
        val json = runCatching {
            RustBridge.ensureLoaded()
            RustBridge.fetchChildConfig(
                enrollment.clusterEndpoint,
                enrollment.deviceId,
                appliedVersion(ctx),
                RustBridge.clusterCaPath(ctx),
                enrollment.deviceToken,
            )
        }.onFailure {
            transition(ctx, SyncState.DEGRADED, "config fetch failed: ${it.javaClass.simpleName}")
        }.getOrNull() ?: return

        val obj = runCatching { JSONObject(json) }.getOrNull() ?: run {
            transition(ctx, SyncState.DEGRADED, "server returned invalid config payload")
            return
        }
        if (!obj.optBoolean("ok", false)) {
            transition(ctx, SyncState.DEGRADED, obj.optString("error", "config fetch failed"))
            return
        }

        val version = obj.optLong("config_version", 0L)
        val applied = appliedVersion(ctx)
        if (version <= 0L) {
            transition(ctx, SyncState.DEGRADED, "server returned config_version=0")
            return
        }
        if (version < applied) {
            Log.w(TAG, "ignoring stale config v$version (applied v$applied)")
            transition(ctx, SyncState.DEGRADED, "stale desired config refused")
            return
        }
        transition(ctx, if (version == applied) SyncState.APPLIED else SyncState.DESIRED, "desired v$version")

        val profile = obj.optString("profile", "")
        val filterLocation =
            obj.optString("filter_location", FILTER_ON_DEVICE).ifBlank { FILTER_ON_DEVICE }

        // Server-side filtering is not implemented by this Android data path yet.
        // Keep existing on-device protection running, but never claim the desired
        // cloud mode was applied and never advance have_version.
        if (filterLocation == FILTER_ON_SERVER) {
            prefs(ctx).edit()
                .putString(KEY_APPLIED_FILTER_LOCATION, FILTER_ON_SERVER)
                .apply()
            ensureOnDeviceProtectionBestEffort(ctx)
            transition(
                ctx,
                SyncState.UNSUPPORTED,
                "cloud filtering requested but this build only has on-device enforcement",
            )
            return
        }

        val filteringEnabled = obj.optBoolean("filtering_enabled", true)
        if (filteringEnabled) {
            if (VpnService.prepare(ctx) != null) {
                transition(ctx, SyncState.DEGRADED, "VPN consent missing")
                return
            }
            if (!BulwarkVpnService.running) {
                transition(ctx, SyncState.APPLYING, "starting filtering service")
                ContextCompat.startForegroundService(
                    ctx,
                    Intent(ctx, BulwarkVpnService::class.java),
                )
                return
            }
            if (!BulwarkVpnService.ready) {
                transition(ctx, SyncState.APPLYING, "filtering service is not ready yet")
                return
            }
        } else {
            if (BulwarkVpnService.running) {
                transition(ctx, SyncState.APPLYING, "stopping filtering service")
                ctx.stopService(Intent(ctx, BulwarkVpnService::class.java))
                return
            }
        }

        // Only now is desired state actually enforced. Persist policy fields and
        // advance the version atomically in one SharedPreferences transaction.
        prefs(ctx).edit()
            .putString(KEY_APPLIED_PROFILE, profile)
            .putString(KEY_APPLIED_FILTER_LOCATION, FILTER_ON_DEVICE)
            .putLong(KEY_APPLIED_VERSION, version)
            .putString(KEY_SYNC_STATE, SyncState.APPLIED.name)
            .putString(
                KEY_SYNC_DETAIL,
                "applied v$version (filtering ${if (filteringEnabled) "on" else "off"})",
            )
            .apply()
        Log.i(TAG, "applied guardian config v$version after enforcement readiness")
    }

    private fun ensureOnDeviceProtectionBestEffort(ctx: Context) {
        if (BulwarkVpnService.running || VpnService.prepare(ctx) != null) return
        runCatching {
            ContextCompat.startForegroundService(ctx, Intent(ctx, BulwarkVpnService::class.java))
        }
    }

    private fun transition(ctx: Context, state: SyncState, detail: String) {
        prefs(ctx).edit()
            .putString(KEY_SYNC_STATE, state.name)
            .putString(KEY_SYNC_DETAIL, detail.take(256))
            .apply()
        Log.i(TAG, "$state: $detail")
    }

    private fun prefs(ctx: Context) =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
