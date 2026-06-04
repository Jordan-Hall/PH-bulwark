package co.libertyware.aegis.admin

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.os.UserManager
import android.util.Log

/**
 * Device-policy helpers for the STRONGEST tamper-resistance tier.
 *
 * These only take effect when the Aegis app is the **Device Owner**, provisioned
 * on a factory-reset device via QR / zero-touch / NFC, or in dev with:
 *
 *   adb shell dpm set-device-owner \
 *     co.libertyware.aegis/.admin.AegisDeviceAdminReceiver
 *
 * Each call is a safe no-op (logged) when the app is merely a device admin or
 * unprivileged, so callers don't have to branch.
 *
 * Transparent + consented: Device Owner is established openly at device setup for
 * a managed child device — it is not, and cannot be, applied covertly.
 */
object Lockdown {
    private const val TAG = "AegisLockdown"

    fun adminComponent(ctx: Context): ComponentName =
        ComponentName(ctx, AegisDeviceAdminReceiver::class.java)

    fun dpm(ctx: Context): DevicePolicyManager =
        ctx.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager

    fun isDeviceOwner(ctx: Context): Boolean =
        runCatching { dpm(ctx).isDeviceOwnerApp(ctx.packageName) }.getOrDefault(false)

    fun isActiveAdmin(ctx: Context): Boolean =
        runCatching { dpm(ctx).isAdminActive(adminComponent(ctx)) }.getOrDefault(false)

    /**
     * Apply the full anti-removal policy set (Device Owner only):
     *  - block uninstalling the Aegis app,
     *  - disallow factory reset + safe-mode boot (the usual escape hatches),
     *  - block the user from uninstalling apps generally,
     *  - pin the filtering VPN as **always-on with lockdown** so that if the VPN
     *    is ever off, traffic is BLOCKED (fail-closed) rather than flowing
     *    unfiltered.
     */
    fun enforce(ctx: Context, vpnPackage: String = ctx.packageName) {
        if (!isDeviceOwner(ctx)) {
            Log.i(TAG, "not device owner — anti-removal policies skipped (admin-tier friction only)")
            return
        }
        val dpm = dpm(ctx)
        val admin = adminComponent(ctx)
        runCatching { dpm.setUninstallBlocked(admin, ctx.packageName, true) }
        runCatching { dpm.addUserRestriction(admin, UserManager.DISALLOW_FACTORY_RESET) }
        runCatching { dpm.addUserRestriction(admin, UserManager.DISALLOW_SAFE_BOOT) }
        runCatching { dpm.addUserRestriction(admin, UserManager.DISALLOW_UNINSTALL_APPS) }
        // Always-on VPN, fail-closed: VPN off => no traffic (vs. unfiltered).
        runCatching { dpm.setAlwaysOnVpnPackage(admin, vpnPackage, /* lockdownEnabled = */ true) }
        Log.i(TAG, "device-owner anti-removal policies applied")
    }

    /**
     * Relax the policies (guardian-initiated un-enrollment) so the app can be
     * removed cleanly. Best-effort; no-op unless Device Owner.
     */
    fun release(ctx: Context) {
        if (!isDeviceOwner(ctx)) return
        val dpm = dpm(ctx)
        val admin = adminComponent(ctx)
        runCatching { dpm.setUninstallBlocked(admin, ctx.packageName, false) }
        runCatching { dpm.clearUserRestriction(admin, UserManager.DISALLOW_FACTORY_RESET) }
        runCatching { dpm.clearUserRestriction(admin, UserManager.DISALLOW_SAFE_BOOT) }
        runCatching { dpm.clearUserRestriction(admin, UserManager.DISALLOW_UNINSTALL_APPS) }
        runCatching { dpm.setAlwaysOnVpnPackage(admin, null, false) }
    }
}
