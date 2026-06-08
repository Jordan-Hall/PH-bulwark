package co.predatorhunters.bulwark.admin

import android.content.Context
import android.os.PersistableBundle
import android.provider.Settings
import java.util.UUID

/**
 * Records that this device has been provisioned as Device Owner and (optionally)
 * which family/child/cluster it was enrolled to. Idempotent. The POSITIVE
 * counterpart to [TamperReporter][co.predatorhunters.bulwark.tamper.TamperReporter] —
 * "device is now managed + enrolled".
 *
 * Pair-code enrollment and Device Owner provisioning are deliberately separate:
 * a device can be linked to a family/server before Android lockdown is enabled.
 */
object Enrollment {
    private const val PREFS = "bulwark_enrollment"
    private const val KEY_PROVISIONED = "provisioned"
    private const val KEY_ENROLLED = "enrolled"
    private const val KEY_FAMILY_ID = "family_id"
    private const val KEY_CHILD_ID = "child_id"
    private const val KEY_CLUSTER = "cluster_endpoint"
    private const val KEY_DEVICE_ID = "device_id"

    // Keys passed through PROVISIONING_ADMIN_EXTRAS_BUNDLE (see the QR JSON in
    // deploy/android/device-owner-provisioning.md).
    const val EXTRA_FAMILY_ID = "co.predatorhunters.bulwark.family_id"
    const val EXTRA_CHILD_ID = "co.predatorhunters.bulwark.child_id"
    const val EXTRA_CLUSTER = "co.predatorhunters.bulwark.cluster_endpoint"

    fun isProvisioned(ctx: Context): Boolean =
        prefs(ctx).getBoolean(KEY_PROVISIONED, false)

    fun isEnrolled(ctx: Context): Boolean =
        prefs(ctx).getBoolean(KEY_ENROLLED, false) ||
            (!childId(ctx).isNullOrBlank() && !familyId(ctx).isNullOrBlank())

    fun record(ctx: Context): EnrollmentRecord? {
        val p = prefs(ctx)
        val familyId = p.getString(KEY_FAMILY_ID, null)?.takeIf { it.isNotBlank() }
        val childId = p.getString(KEY_CHILD_ID, null)?.takeIf { it.isNotBlank() }
        val endpoint = p.getString(KEY_CLUSTER, null)?.takeIf { it.isNotBlank() }
        return if (familyId != null && childId != null && endpoint != null) {
            EnrollmentRecord(
                familyId = familyId,
                childId = childId,
                clusterEndpoint = endpoint,
                deviceId = stableDeviceId(ctx),
                deviceOwnerProvisioned = isProvisioned(ctx),
            )
        } else {
            null
        }
    }

    fun familyId(ctx: Context): String? = prefs(ctx).getString(KEY_FAMILY_ID, null)

    fun childId(ctx: Context): String? = prefs(ctx).getString(KEY_CHILD_ID, null)

    fun clusterEndpoint(ctx: Context): String? = prefs(ctx).getString(KEY_CLUSTER, null)

    fun stableDeviceId(ctx: Context): String {
        val p = prefs(ctx)
        p.getString(KEY_DEVICE_ID, null)
            ?.takeIf { it.isNotBlank() }
            ?.let { return it }

        val androidId = Settings.Secure.getString(ctx.contentResolver, Settings.Secure.ANDROID_ID)
            ?.trim()
            ?.lowercase()
            ?.takeIf { it.isNotBlank() && it != "9774d56d682e549c" }
        val id = if (androidId != null) {
            "android-$androidId"
        } else {
            "android-${UUID.randomUUID()}"
        }
        p.edit().putString(KEY_DEVICE_ID, id).apply()
        return id
    }

    fun savePairing(
        ctx: Context,
        familyId: String,
        childId: String,
        clusterEndpoint: String,
        deviceId: String = stableDeviceId(ctx),
    ) {
        prefs(ctx).edit()
            .putBoolean(KEY_ENROLLED, true)
            .putString(KEY_FAMILY_ID, familyId.trim())
            .putString(KEY_CHILD_ID, childId.trim())
            .putString(KEY_CLUSTER, clusterEndpoint.trim())
            .putString(KEY_DEVICE_ID, deviceId.trim())
            .apply()
    }

    /**
     * Mark this device provisioned, recording any family/child/cluster identifiers
     * the provisioning flow carried in `extras` (may be null on the `dpm`/dev path).
     * Idempotent: the enrolled flag is only flipped once.
     */
    fun markProvisioned(ctx: Context, extras: PersistableBundle?) {
        val p = prefs(ctx)
        val editor = p.edit()
        val familyId = extras?.getString(EXTRA_FAMILY_ID)
        val childId = extras?.getString(EXTRA_CHILD_ID)
        val cluster = extras?.getString(EXTRA_CLUSTER)
        familyId?.let { editor.putString(KEY_FAMILY_ID, it) }
        childId?.let { editor.putString(KEY_CHILD_ID, it) }
        cluster?.let { editor.putString(KEY_CLUSTER, it) }
        val hasPairing = !familyId.isNullOrBlank() &&
            !childId.isNullOrBlank() &&
            !cluster.isNullOrBlank()
        if (hasPairing) {
            editor.putBoolean(KEY_ENROLLED, true)
            editor.putString(KEY_DEVICE_ID, stableDeviceId(ctx))
        }
        editor.putBoolean(KEY_PROVISIONED, true)
        editor.apply()
    }

    private fun prefs(ctx: Context) =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}

data class EnrollmentRecord(
    val familyId: String,
    val childId: String,
    val clusterEndpoint: String,
    val deviceId: String,
    val deviceOwnerProvisioned: Boolean,
)
