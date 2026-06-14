package co.predatorhunters.bulwark.admin

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.util.Log
import co.predatorhunters.bulwark.MainActivity
import co.predatorhunters.bulwark.tamper.TamperReporter

// CaTrust lives in the same package (co.predatorhunters.bulwark.admin).

/**
 * Device-admin receiver (the WEAK tamper-resistance tier — works without a factory
 * reset).
 *
 * While this app is an ACTIVE device admin, Android will not let it be uninstalled
 * until admin is first deactivated in Settings — that's the friction. If admin is
 * deactivated, [onDisabled] fires a `DEVICE_ADMIN_REMOVED` tamper alert so the
 * guardian is told the protection was weakened.
 *
 * For real lockdown the app is provisioned as **Device Owner** (see [Lockdown]):
 * a Device Owner DPC cannot be deactivated or its app uninstalled at all without
 * `adb shell dpm remove-active-admin` or a factory reset.
 *
 * Transparent + consented: enabling device admin is a visible, guardian-driven
 * step on the managed child device.
 */
class BulwarkDeviceAdminReceiver : DeviceAdminReceiver() {

    override fun onDisableRequested(context: Context, intent: Intent): CharSequence =
        "Turning this off removes PH Bulwark child-safety protection from this device. " +
            "Your guardian will be notified."

    override fun onDisabled(context: Context, intent: Intent) {
        TamperReporter.report(context, TamperReporter.DEVICE_ADMIN_REMOVED)
    }

    /**
     * Fired by the platform when QR / NFC / zero-touch managed provisioning
     * finishes (API 21+). Bulwark is already the Device Owner at this point — apply
     * the anti-removal lockdown, record enrollment, and open the dashboard.
     */
    override fun onProfileProvisioningComplete(context: Context, intent: Intent) {
        val extras = intent.getParcelableExtra<android.os.PersistableBundle>(
            DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE
        )
        finalizeProvisioning(context, extras)
    }

    /**
     * Belt-and-braces: `DEVICE_OWNER_CHANGED` has no dedicated callback, and the
     * dev path (`adb shell dpm set-device-owner`) does NOT fire
     * `onProfileProvisioningComplete` — so we also finalize here. Must call
     * `super.onReceive` so the base class still dispatches the admin callbacks.
     */
    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)
        if (intent.action == DevicePolicyManager.ACTION_DEVICE_OWNER_CHANGED) {
            finalizeProvisioning(context, null)
        }
    }

    /** Idempotent finalize: enforce lockdown, trust the inspection CA, record
     *  enrollment, surface the UI. */
    private fun finalizeProvisioning(context: Context, extras: android.os.PersistableBundle?) {
        Log.i(TAG, "finalizing Device Owner provisioning")
        runCatching { Lockdown.enforce(context) }
        runCatching {
            val dpm = Lockdown.dpm(context)
            val admin = Lockdown.adminComponent(context)
            dpm.setProfileName(admin, "PH Bulwark managed")
        }
        // Now that we are Device Owner, install the per-install TLS-inspection CA
        // into the SYSTEM trust store so inspected HTTPS validates the moment the
        // filtering VPN starts (the establish() fail-closed path also calls this;
        // doing it here means the CA is trusted as soon as the device is managed,
        // not only on the first VPN start). Idempotent / safe no-op if present.
        runCatching {
            val result = CaTrust.ensureInstalled(context)
            Log.i(TAG, "inspection CA trust at provisioning: $result")
        }
        runCatching { Enrollment.markProvisioned(context, extras) }
        runCatching {
            val launch = Intent(context, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                .putExtra(MainActivity.EXTRA_FROM_PROVISIONING, true)
            context.startActivity(launch)
        }
    }

    private companion object {
        const val TAG = "BulwarkDeviceAdmin"
    }
}
