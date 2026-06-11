package co.predatorhunters.bulwark

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.ActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.core.content.ContextCompat
import co.predatorhunters.bulwark.accessibility.BulwarkAccessibilityService
import co.predatorhunters.bulwark.admin.Enrollment
import co.predatorhunters.bulwark.admin.EnrollmentRecord
import co.predatorhunters.bulwark.admin.Lockdown
import co.predatorhunters.bulwark.vpn.BulwarkVpnService
import co.predatorhunters.bulwark.vpn.ChildConfigSync

private val Colors = lightColorScheme(
    primary = Navy,
    onPrimary = Color.White,
    secondary = Sky,
    background = Mist,
    onBackground = Ink,
    surface = Color.White,
    onSurface = Ink,
)

private const val PREFS = "ph_bulwark"
private const val KEY_SERVER = "server_id"
private const val KEY_SELF_HOSTED = "self_hosted_endpoint"
private const val KEY_ONBOARDING_DONE = "onboarding_done"
private const val KEY_VPN_CONSENTED = "vpn_consented"

/**
 * Hosts the guided onboarding journey ([OnboardingJourney]) and, once setup is
 * complete (or the guardian has finished onboarding), a calm read-only
 * [StatusDashboard]. The journey vs. dashboard decision is derived from saved
 * "onboarding seen" state combined with the LIVE permission/enrollment status,
 * so a half-finished setup always resumes at the first incomplete step.
 */
class MainActivity : ComponentActivity() {

    private var accessibilityOn by mutableStateOf(false)
    private var vpnConsented by mutableStateOf(false)
    private var vpnRunning by mutableStateOf(false)
    private var antiRemovalOn by mutableStateOf(false)
    private var paired by mutableStateOf(false)
    private var enrollment by mutableStateOf<EnrollmentRecord?>(null)

    /** "Force the journey" — set when the guardian taps "Review setup" on the dashboard. */
    private var forceJourney by mutableStateOf(false)

    private val vpnConsentLauncher =
        registerForResult { result ->
            if (result.resultCode == RESULT_OK) {
                markVpnConsented()
                startVpnService()
            }
            refreshLocalState()
        }

    override fun onResume() {
        super.onResume()
        refreshLocalState()
        // Workflow B step 2: apply any newer guardian config while we are in
        // the foreground — covers "protection turned back ON from the parent
        // app" when the VPN service (and its poller) is not running.
        Thread({
            runCatching { ChildConfigSync.fetchAndReconcile(applicationContext) }
        }, "bulwark-config-sync").apply { isDaemon = true }.start()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        refreshLocalState()
        setContent {
            MaterialTheme(colorScheme = Colors) {
                Surface(Modifier.fillMaxSize(), color = Mist) {
                    Root()
                }
            }
        }
    }

    @Composable
    private fun Root() {
        val state = SetupState(
            accessibilityOn = accessibilityOn,
            vpnConsented = vpnConsented,
            vpnRunning = vpnRunning,
            antiRemovalOn = antiRemovalOn,
            paired = paired,
        )
        val onboardingDone = prefs().getBoolean(KEY_ONBOARDING_DONE, false)
        val showDashboard = !forceJourney && onboardingDone && isFullySetUp(state)

        AnimatedContent(
            targetState = showDashboard,
            transitionSpec = { fadeIn(tween(260)).togetherWith(fadeOut(tween(180))) },
            label = "root",
        ) { dashboard ->
            if (dashboard) {
                StatusDashboard(
                    state = state,
                    enrollment = enrollment,
                    deviceId = Enrollment.stableDeviceId(this@MainActivity),
                    onOpenAccessibility = ::openAccessibilitySettings,
                    onStartVpn = ::requestVpnConsent,
                    onReconfigure = { forceJourney = true },
                )
            } else {
                OnboardingJourney(
                    state = state,
                    deviceId = Enrollment.stableDeviceId(this@MainActivity),
                    savedServer = prefs().getString(KEY_SERVER, DEFAULT_SERVER) ?: DEFAULT_SERVER,
                    savedSelfHosted = prefs().getString(KEY_SELF_HOSTED, "") ?: "",
                    onSaveServer = { server, selfHosted ->
                        prefs().edit()
                            .putString(KEY_SERVER, server)
                            .putString(KEY_SELF_HOSTED, selfHosted.trim())
                            .apply()
                    },
                    onSaveEnrollment = { familyId, childId, endpoint, deviceId, deviceToken ->
                        Enrollment.savePairing(
                            this@MainActivity,
                            familyId = familyId,
                            childId = childId,
                            clusterEndpoint = endpoint,
                            deviceId = deviceId,
                            deviceToken = deviceToken,
                        )
                        refreshLocalState()
                    },
                    onGrantAccessibility = ::openAccessibilitySettings,
                    onGrantVpn = ::requestVpnConsent,
                    onGrantAntiRemoval = ::requestAntiRemoval,
                    onFinish = {
                        prefs().edit().putBoolean(KEY_ONBOARDING_DONE, true).apply()
                        forceJourney = false
                        refreshLocalState()
                    },
                )
            }
        }
    }

    // -----------------------------------------------------------------------
    // Grant actions — real system intents; no fabricated bridge calls.
    // -----------------------------------------------------------------------

    private fun openAccessibilitySettings() {
        startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
    }

    /**
     * VpnService consent: [VpnService.prepare] returns an Intent if the user must
     * consent, or null if consent was already given. On null we can start the
     * service straight away; otherwise we launch the system consent dialog and
     * start on RESULT_OK (handled by [vpnConsentLauncher]).
     */
    private fun requestVpnConsent() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnConsentLauncher.launch(intent)
        } else {
            markVpnConsented()
            startVpnService()
            refreshLocalState()
        }
    }

    private fun startVpnService() {
        ContextCompat.startForegroundService(
            this,
            Intent(this, BulwarkVpnService::class.java),
        )
    }

    private fun markVpnConsented() {
        prefs().edit().putBoolean(KEY_VPN_CONSENTED, true).apply()
        vpnConsented = true
    }

    /**
     * Anti-removal is OPTIONAL/advanced. The codebase exposes Device Owner
     * enforcement ([Lockdown.enforce]) but no in-app "become device owner" flow
     * (that happens via managed provisioning / `dpm` on the parent-managed path).
     * We therefore present this as parent-managed and, as a best-effort advanced
     * action, send the guardian to the standard "add device admin" screen for the
     * REAL, manifest-declared admin receiver. If admin is already active and we
     * are Device Owner, we apply the anti-removal policy set.
     */
    private fun requestAntiRemoval() {
        if (Lockdown.isDeviceOwner(this)) {
            Lockdown.enforce(this)
            refreshLocalState()
            return
        }
        val intent = Intent(android.app.admin.DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN)
            .putExtra(
                android.app.admin.DevicePolicyManager.EXTRA_DEVICE_ADMIN,
                Lockdown.adminComponent(this),
            )
            .putExtra(
                android.app.admin.DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                getString(R.string.device_admin_description),
            )
        runCatching { startActivity(intent) }
    }

    // -----------------------------------------------------------------------
    // Live state
    // -----------------------------------------------------------------------

    private fun refreshLocalState() {
        accessibilityOn = isAccessibilityEnabled()
        // Consent is sticky once granted; VpnService.prepare == null also means
        // consent is currently in place (e.g. always-on configured by the parent).
        vpnConsented = prefs().getBoolean(KEY_VPN_CONSENTED, false) ||
            VpnService.prepare(this) == null
        // Honest live state: BulwarkVpnService flips `running` in
        // onStartCommand/onDestroy — consent alone must never show "running".
        vpnRunning = BulwarkVpnService.running
        antiRemovalOn = Lockdown.isDeviceOwner(this) || Lockdown.isActiveAdmin(this)
        paired = Enrollment.isEnrolled(this)
        enrollment = Enrollment.record(this)
    }

    private fun prefs() = getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun isAccessibilityEnabled(): Boolean {
        val flat = Settings.Secure.getString(
            contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
        ) ?: return false
        val svc = "${packageName}/${BulwarkAccessibilityService::class.java.name}"
        return flat.split(':').any { it.equals(svc, ignoreCase = true) }
    }

    private fun registerForResult(onResult: (ActivityResult) -> Unit) =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult(), onResult)

    companion object {
        const val EXTRA_FROM_PROVISIONING = "from_provisioning"
    }
}
