package co.libertyware.aegis.admin

import android.app.admin.DeviceAdminReceiver
import android.content.Context
import android.content.Intent
import co.libertyware.aegis.tamper.TamperReporter

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
class AegisDeviceAdminReceiver : DeviceAdminReceiver() {

    override fun onDisableRequested(context: Context, intent: Intent): CharSequence =
        "Turning this off removes Aegis child-safety protection from this device. " +
            "Your guardian will be notified."

    override fun onDisabled(context: Context, intent: Intent) {
        TamperReporter.report(context, TamperReporter.DEVICE_ADMIN_REMOVED)
    }
}
