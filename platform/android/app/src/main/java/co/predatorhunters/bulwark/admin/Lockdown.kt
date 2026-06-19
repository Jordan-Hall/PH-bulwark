package co.predatorhunters.bulwark.admin

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.os.UserManager
import android.provider.Settings
import android.util.Log
import co.predatorhunters.bulwark.accessibility.BulwarkAccessibilityService

/**
 * Device-policy helpers for the STRONGEST tamper-resistance tier.
 *
 * These only take effect when the Bulwark app is the **Device Owner**, provisioned
 * on a factory-reset device via QR / zero-touch / NFC, or in dev with:
 *
 *   adb shell dpm set-device-owner \
 *     co.predatorhunters.bulwark/.admin.BulwarkDeviceAdminReceiver
 *
 * Each call is a safe no-op (logged) when the app is merely a device admin or
 * unprivileged, so callers don't have to branch.
 *
 * Transparent + consented: Device Owner is established openly at device setup for
 * a managed child device — it is not, and cannot be, applied covertly.
 */
object Lockdown {
    private const val TAG = "BulwarkLockdown"

    fun adminComponent(ctx: Context): ComponentName =
        ComponentName(ctx, BulwarkDeviceAdminReceiver::class.java)

    fun dpm(ctx: Context): DevicePolicyManager =
        ctx.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager

    fun isDeviceOwner(ctx: Context): Boolean =
        runCatching { dpm(ctx).isDeviceOwnerApp(ctx.packageName) }.getOrDefault(false)

    fun isActiveAdmin(ctx: Context): Boolean =
        runCatching { dpm(ctx).isAdminActive(adminComponent(ctx)) }.getOrDefault(false)

    /**
     * Apply the full anti-removal policy set (Device Owner only):
     *  - block uninstalling the Bulwark app,
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
     * Turn protection ON with no setup prompts (Device Owner only): permit + enable
     * the detection AccessibilityService and grant the runtime permissions it
     * declares, so a freshly-provisioned managed child device protects from first
     * boot without the guardian toggling anything in Settings.
     *
     * This only ENABLES the already-installed protection service and grants perms it
     * already declares — it changes NO detection logic. Best-effort + idempotent: a
     * safe no-op when the app is not Device Owner, and each step is wrapped so a
     * platform that refuses one (e.g. a newer Android that blocks silent a11y enable
     * via setSecureSetting) just falls back to a one-time manual enable. Verify on a
     * real managed device — silent a11y enable is version-sensitive.
     */
    fun enableProtectionServices(ctx: Context) {
        if (!isDeviceOwner(ctx)) {
            Log.i(TAG, "not device owner — protection service left to manual enable")
            return
        }
        val dpm = dpm(ctx)
        val admin = adminComponent(ctx)
        val flat = ComponentName(ctx, BulwarkAccessibilityService::class.java).flattenToString()

        // Under Device-Owner policy, permit accessibility services (null = allow all,
        // so our detection service is permitted alongside any the guardian allows).
        runCatching { dpm.setPermittedAccessibilityServices(admin, null) }

        // Enable the detection AccessibilityService via the secure settings a Device
        // Owner may write. APPEND to any already-enabled services so we never clobber
        // another enabled service.
        runCatching {
            val current = Settings.Secure.getString(
                ctx.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
            ).orEmpty()
            val already = current.split(':').any { it.equals(flat, ignoreCase = true) }
            val merged = when {
                current.isBlank() -> flat
                already -> current
                else -> "$current:$flat"
            }
            dpm.setSecureSetting(admin, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES, merged)
            dpm.setSecureSetting(admin, Settings.Secure.ACCESSIBILITY_ENABLED, "1")
        }

        // Auto-grant the runtime-dangerous permissions the app declares (today only
        // POST_NOTIFICATIONS, for the always-visible protection-status notice). Add
        // camera/mic here if the on-device detection path ever needs them.
        runCatching {
            dpm.setPermissionGrantState(
                admin,
                ctx.packageName,
                android.Manifest.permission.POST_NOTIFICATIONS,
                DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED,
            )
        }
        Log.i(TAG, "device-owner: protection service enabled + runtime perms granted")
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
