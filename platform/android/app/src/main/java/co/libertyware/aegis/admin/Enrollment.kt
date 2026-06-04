package co.libertyware.aegis.admin

import android.content.Context
import android.os.PersistableBundle

/**
 * Records that this device has been provisioned as Device Owner and (optionally)
 * which family/child/cluster it was enrolled to. Idempotent. The POSITIVE
 * counterpart to [TamperReporter][co.libertyware.aegis.tamper.TamperReporter] —
 * "device is now managed + enrolled".
 *
 * Option 1 (no proto/JNI change): the enrolled state is persisted locally and the
 * existing content-free `ProtectionStatus` heartbeat (which reports device-owner /
 * always-on-lockdown) implicitly tells the cluster the device is now managed. A
 * dedicated "provisioned" RPC is a documented follow-up.
 */
object Enrollment {
    private const val PREFS = "aegis_enrollment"
    private const val KEY_PROVISIONED = "provisioned"
    private const val KEY_FAMILY_ID = "family_id"
    private const val KEY_CHILD_ID = "child_id"
    private const val KEY_CLUSTER = "cluster_endpoint"

    // Keys passed through PROVISIONING_ADMIN_EXTRAS_BUNDLE (see the QR JSON in
    // deploy/android/device-owner-provisioning.md).
    const val EXTRA_FAMILY_ID = "co.libertyware.aegis.family_id"
    const val EXTRA_CHILD_ID = "co.libertyware.aegis.child_id"
    const val EXTRA_CLUSTER = "co.libertyware.aegis.cluster_endpoint"

    fun isProvisioned(ctx: Context): Boolean =
        prefs(ctx).getBoolean(KEY_PROVISIONED, false)

    fun childId(ctx: Context): String? = prefs(ctx).getString(KEY_CHILD_ID, null)

    /**
     * Mark this device provisioned, recording any family/child/cluster identifiers
     * the provisioning flow carried in `extras` (may be null on the `dpm`/dev path).
     * Idempotent: the enrolled flag is only flipped once.
     */
    fun markProvisioned(ctx: Context, extras: PersistableBundle?) {
        val p = prefs(ctx)
        val editor = p.edit()
        extras?.getString(EXTRA_FAMILY_ID)?.let { editor.putString(KEY_FAMILY_ID, it) }
        extras?.getString(EXTRA_CHILD_ID)?.let { editor.putString(KEY_CHILD_ID, it) }
        extras?.getString(EXTRA_CLUSTER)?.let { editor.putString(KEY_CLUSTER, it) }
        editor.putBoolean(KEY_PROVISIONED, true)
        editor.apply()
    }

    private fun prefs(ctx: Context) =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
