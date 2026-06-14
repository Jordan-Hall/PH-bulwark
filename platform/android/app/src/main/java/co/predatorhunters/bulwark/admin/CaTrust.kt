package co.predatorhunters.bulwark.admin

import android.content.Context
import android.util.Log
import co.predatorhunters.bulwark.core.RustBridge
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory

/**
 * Installs the per-install TLS-inspection ROOT CA into the device trust store so
 * inspected HTTPS validates instead of showing "connection not private".
 *
 * The CA is generated and held by the Rust core ([RustBridge.inspectionCaPem]);
 * only its PUBLIC certificate crosses the JNI boundary — the private key never
 * leaves the device keystore.
 *
 * ## Honest coverage limit
 * Only a **Device Owner** (or Profile Owner) can install into the SYSTEM trust
 * store via [android.app.admin.DevicePolicyManager.installCaCert] — that store is
 * the one Chrome and non-pinned apps actually trust. On a device that is merely a
 * device-admin or unprivileged, there is NO way to make apps trust a user-added
 * CA (Android 7+ ignores the user store by design), so transparent HTTPS needs
 * the device provisioned as Device Owner; otherwise the on-device accessibility/
 * OCR path covers what the network can't read. Cert-pinned / E2E apps are never
 * inspectable on the wire regardless. Transparent + consented: this only ever runs
 * on a guardian-provisioned managed device, never covertly.
 */
object CaTrust {
    private const val TAG = "BulwarkCaTrust"

    enum class Result {
        /** Installed (or already present) in the system store — HTTPS will validate. */
        INSTALLED_SYSTEM,

        /** Already trusted in the system store; nothing to do. */
        ALREADY_TRUSTED,

        /** Not Device Owner: cannot reach the system store (apps ignore user CAs). */
        NOT_MANAGED,

        /** Rust returned no CA (engine not initialised / no ca_dir yet). */
        NO_CA,

        /** An error occurred while installing. */
        ERROR,
    }

    /**
     * Fetch the inspection CA from the Rust core and, when this app is Device
     * Owner, install it into the system trust store. Safe to call repeatedly:
     * a no-op when already trusted, and a logged no-op when not Device Owner.
     */
    fun ensureInstalled(ctx: Context): Result {
        RustBridge.ensureLoaded()
        val pem = runCatching { RustBridge.inspectionCaPem(RustBridge.inspectionCaDir(ctx)) }
            .getOrDefault("")
        if (pem.isBlank()) {
            Log.w(TAG, "no inspection CA available yet (engine/ca_dir not ready)")
            return Result.NO_CA
        }
        if (!Lockdown.isDeviceOwner(ctx)) {
            Log.i(
                TAG,
                "not Device Owner — system CA install unavailable; Android 7+ apps " +
                    "ignore user-store CAs, so transparent HTTPS needs a managed device",
            )
            return Result.NOT_MANAGED
        }
        return try {
            val der = pemToDer(pem)
            val dpm = Lockdown.dpm(ctx)
            val admin = Lockdown.adminComponent(ctx)
            if (runCatching { dpm.hasCaCertInstalled(admin, der) }.getOrDefault(false)) {
                Result.ALREADY_TRUSTED
            } else if (dpm.installCaCert(admin, der)) {
                Log.i(TAG, "inspection CA installed into the system trust store")
                Result.INSTALLED_SYSTEM
            } else {
                Log.e(TAG, "installCaCert returned false")
                Result.ERROR
            }
        } catch (e: Exception) {
            Log.e(TAG, "installing inspection CA failed", e)
            Result.ERROR
        }
    }

    /**
     * Read-only check: is the per-install inspection CA already trusted in the
     * SYSTEM store? Cheap and side-effect-free — for status UI that runs on every
     * resume. Short-circuits to `false` when not Device Owner (a non-managed
     * device can never have it system-trusted), avoiding a Rust/JNI call on the
     * hot path. Never installs anything.
     */
    fun isInstalled(ctx: Context): Boolean {
        if (!Lockdown.isDeviceOwner(ctx)) return false
        return runCatching {
            RustBridge.ensureLoaded()
            val pem = RustBridge.inspectionCaPem(RustBridge.inspectionCaDir(ctx))
            if (pem.isBlank()) return false
            val der = pemToDer(pem)
            Lockdown.dpm(ctx).hasCaCertInstalled(Lockdown.adminComponent(ctx), der)
        }.getOrDefault(false)
    }

    /**
     * PEM → DER. `installCaCert`/`hasCaCertInstalled` accept either, but parsing
     * to a real X.509 first rejects garbage early and yields the canonical DER.
     */
    private fun pemToDer(pem: String): ByteArray {
        val cf = CertificateFactory.getInstance("X.509")
        val cert = cf.generateCertificate(ByteArrayInputStream(pem.toByteArray(Charsets.US_ASCII)))
        return cert.encoded
    }
}
