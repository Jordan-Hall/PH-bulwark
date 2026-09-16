package co.predatorhunters.bulwark.admin

import android.content.Context
import android.util.Log
import co.predatorhunters.bulwark.core.RustBridge
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory

/** Installs Bulwark inspection roots into the managed device system trust store. */
object CaTrust {
    private const val TAG = "BulwarkCaTrust"

    enum class Result {
        INSTALLED_SYSTEM,
        ALREADY_TRUSTED,
        NOT_MANAGED,
        NO_CA,
        ERROR,
    }

    /** Install the per-install LOCAL inspection root used by on-device mode. */
    fun ensureInstalled(ctx: Context): Result {
        RustBridge.ensureLoaded()
        val pem = runCatching { RustBridge.inspectionCaPem(RustBridge.inspectionCaDir(ctx)) }
            .getOrDefault("")
        return ensurePemInstalled(ctx, pem, "local inspection CA")
    }

    /**
     * Install a validated PUBLIC inspection root supplied by an authenticated
     * server-VPN provisioning response. The corresponding private key never
     * reaches the phone; it remains on the selected filtering region.
     */
    fun ensurePemInstalled(ctx: Context, pem: String, label: String = "inspection CA"): Result {
        if (pem.isBlank()) {
            Log.w(TAG, "$label is empty")
            return Result.NO_CA
        }
        if (!Lockdown.isDeviceOwner(ctx)) {
            Log.i(TAG, "not Device Owner — cannot system-trust $label")
            return Result.NOT_MANAGED
        }
        return try {
            val der = pemToDer(pem)
            val dpm = Lockdown.dpm(ctx)
            val admin = Lockdown.adminComponent(ctx)
            if (runCatching { dpm.hasCaCertInstalled(admin, der) }.getOrDefault(false)) {
                Result.ALREADY_TRUSTED
            } else if (dpm.installCaCert(admin, der)) {
                Log.i(TAG, "$label installed into the system trust store")
                Result.INSTALLED_SYSTEM
            } else {
                Log.e(TAG, "installCaCert returned false for $label")
                Result.ERROR
            }
        } catch (e: Exception) {
            Log.e(TAG, "installing $label failed", e)
            Result.ERROR
        }
    }

    /** Read-only check for the local on-device inspection root. */
    fun isInstalled(ctx: Context): Boolean {
        if (!Lockdown.isDeviceOwner(ctx)) return false
        return runCatching {
            RustBridge.ensureLoaded()
            val pem = RustBridge.inspectionCaPem(RustBridge.inspectionCaDir(ctx))
            isPemInstalled(ctx, pem)
        }.getOrDefault(false)
    }

    /** Read-only check for any supplied Bulwark inspection root. */
    fun isPemInstalled(ctx: Context, pem: String): Boolean {
        if (!Lockdown.isDeviceOwner(ctx) || pem.isBlank()) return false
        return runCatching {
            val der = pemToDer(pem)
            Lockdown.dpm(ctx).hasCaCertInstalled(Lockdown.adminComponent(ctx), der)
        }.getOrDefault(false)
    }

    private fun pemToDer(pem: String): ByteArray {
        val cf = CertificateFactory.getInstance("X.509")
        val cert = cf.generateCertificate(ByteArrayInputStream(pem.toByteArray(Charsets.US_ASCII)))
        return cert.encoded
    }
}