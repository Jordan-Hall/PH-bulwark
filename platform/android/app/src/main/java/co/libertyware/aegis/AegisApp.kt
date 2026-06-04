package co.libertyware.aegis

import android.app.Application
import co.libertyware.aegis.admin.Lockdown

/** Application entry point. Reserved for process-wide init (logging, config). */
class AegisApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // Re-assert anti-removal policy on every launch. No-op unless this app is
        // the Device Owner (admin-tier installs get only the deactivate-first
        // friction); safe to call always.
        runCatching { Lockdown.enforce(this) }
    }
}
