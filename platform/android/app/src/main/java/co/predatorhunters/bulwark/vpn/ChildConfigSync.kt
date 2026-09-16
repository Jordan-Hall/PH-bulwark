package co.predatorhunters.bulwark.vpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import androidx.core.content.ContextCompat
import co.predatorhunters.bulwark.admin.Enrollment
import co.predatorhunters.bulwark.core.RustBridge
import org.json.JSONObject

object ChildConfigSync {
    private const val TAG = "BulwarkChildConfig"
    private const val PREFS = "bulwark_child_config"
    private const val KEY_APPLIED_VERSION = "applied_config_version"
    private const val KEY_APPLIED_PROFILE = "applied_profile"
    private const val KEY_APPLIED_FILTER_LOCATION = "applied_filter_location"
    private const val KEY_DESIRED_PROFILE = "desired_profile"
    private const val KEY_DESIRED_FILTER_LOCATION = "desired_filter_location"
    private const val KEY_SYNC_STATE = "sync_state"
    private const val KEY_SYNC_DETAIL = "sync_detail"

    const val FILTER_ON_DEVICE = "on_device"
    const val FILTER_ON_SERVER = "on_server"

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

    fun desiredProfile(ctx: Context): String =
        prefs(ctx).getString(KEY_DESIRED_PROFILE, appliedProfile(ctx)) ?: appliedProfile(ctx)

    fun appliedFilterLocation(ctx: Context): String =
        prefs(ctx).getString(KEY_APPLIED_FILTER_LOCATION, FILTER_ON_DEVICE) ?: FILTER_ON_DEVICE

    fun desiredFilterLocation(ctx: Context): String =
        prefs(ctx).getString(KEY_DESIRED_FILTER_LOCATION, appliedFilterLocation(ctx))
            ?: appliedFilterLocation(ctx)

    fun cloudFilteringRequested(ctx: Context): Boolean =
        desiredFilterLocation(ctx) == FILTER_ON_SERVER

    fun syncState(ctx: Context): SyncState = runCatching {
        SyncState.valueOf(prefs(ctx).getString(KEY_SYNC_STATE, SyncState.DESIRED.name)!!)
    }.getOrDefault(SyncState.DESIRED)

    fun syncDetail(ctx: Context): String =
        prefs(ctx).getString(KEY_SYNC_DETAIL, "") ?: ""

    fun fetchAndReconcile(ctx: Context) {
        val enrollment = Enrollment.record(ctx) ?: return
        val applied = appliedVersion(ctx)
        val json = runCatching {
            RustBridge.ensureLoaded()
            RustBridge.fetchChildConfig(
                enrollment.clusterEndpoint,
                enrollment.deviceId,
                applied,
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
        if (version <= 0L) {
            transition(ctx, SyncState.DEGRADED, "server returned config_version=0")
            return
        }
        if (version < applied) {
            Log.w(TAG, "ignoring stale config v$version (applied v$applied)")
            transition(ctx, SyncState.DEGRADED, "stale desired config refused")
            return
        }

        val policyJson = runCatching {
            RustBridge.syncDevicePolicy(
                enrollment.clusterEndpoint,
                enrollment.deviceId,
                applied,
                RustBridge.clusterCaPath(ctx),
                enrollment.deviceToken,
            )
        }.getOrNull()
        val policyOk = policyJson
            ?.let { runCatching { JSONObject(it).optBoolean("ok", false) }.getOrDefault(false) }
            ?: false
        if (!policyOk) {
            Log.w(TAG, "guardian policy sync unavailable; Local VPN approvals fail closed")
        }

        val profile = obj.optString("profile", "")
        val requestedLocation = obj.optString("filter_location", FILTER_ON_DEVICE)
            .ifBlank { FILTER_ON_DEVICE }
        if (requestedLocation != FILTER_ON_DEVICE && requestedLocation != FILTER_ON_SERVER) {
            transition(ctx, SyncState.UNSUPPORTED, "unknown filter location '$requestedLocation'")
            return
        }
        val filteringEnabled = obj.optBoolean("filtering_enabled", true)

        prefs(ctx).edit()
            .putString(KEY_DESIRED_PROFILE, profile)
            .putString(KEY_DESIRED_FILTER_LOCATION, requestedLocation)
            .apply()
        transition(
            ctx,
            if (version == applied) SyncState.APPLIED else SyncState.DESIRED,
            "desired v$version ($requestedLocation)",
        )

        if (filteringEnabled) {
            if (VpnService.prepare(ctx) != null) {
                transition(ctx, SyncState.DEGRADED, "VPN consent missing")
                return
            }

            if (BulwarkVpnService.running &&
                BulwarkVpnService.activeFilterLocation != requestedLocation
            ) {
                transition(
                    ctx,
                    SyncState.APPLYING,
                    "switching VPN from ${BulwarkVpnService.activeFilterLocation} to $requestedLocation",
                )
                // Reconfigure inside the still-running foreground service. This
                // tears down only the old TUN/Rust data path, immediately builds
                // the requested one, and leaves the independent config poller
                // alive so a mode transition cannot strand the device unprotected.
                ContextCompat.startForegroundService(
                    ctx,
                    Intent(ctx, BulwarkVpnService::class.java)
                        .setAction(BulwarkVpnService.ACTION_RECONFIGURE),
                )
                return
            }

            if (!BulwarkVpnService.running) {
                transition(ctx, SyncState.APPLYING, "starting $requestedLocation filtering service")
                ContextCompat.startForegroundService(
                    ctx,
                    Intent(ctx, BulwarkVpnService::class.java),
                )
                return
            }
            if (!BulwarkVpnService.ready) {
                val detail = BulwarkVpnService.lastFailure.ifBlank {
                    "$requestedLocation filtering service is not ready yet"
                }
                transition(ctx, SyncState.APPLYING, detail)
                return
            }
            if (BulwarkVpnService.activeFilterLocation != requestedLocation) {
                transition(ctx, SyncState.DEGRADED, "VPN ready in the wrong filtering mode")
                return
            }
        } else if (BulwarkVpnService.running) {
            transition(ctx, SyncState.APPLYING, "stopping filtering service")
            ctx.stopService(Intent(ctx, BulwarkVpnService::class.java))
            return
        }

        prefs(ctx).edit()
            .putString(KEY_APPLIED_PROFILE, profile)
            .putString(KEY_APPLIED_FILTER_LOCATION, requestedLocation)
            .putLong(KEY_APPLIED_VERSION, version)
            .putString(KEY_SYNC_STATE, SyncState.APPLIED.name)
            .putString(
                KEY_SYNC_DETAIL,
                "applied v$version ($requestedLocation, filtering ${if (filteringEnabled) "on" else "off"})",
            )
            .apply()
        Log.i(TAG, "applied guardian config v$version after enforcement readiness")
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
