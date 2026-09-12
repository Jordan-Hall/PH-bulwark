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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Surface
import androidx.compose.material3.Typography
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import co.predatorhunters.bulwark.accessibility.BulwarkAccessibilityService
import co.predatorhunters.bulwark.admin.CaTrust
import co.predatorhunters.bulwark.admin.Enrollment
import co.predatorhunters.bulwark.admin.EnrollmentRecord
import co.predatorhunters.bulwark.admin.Lockdown
import co.predatorhunters.bulwark.vpn.BulwarkVpnService
import co.predatorhunters.bulwark.vpn.ChildConfigSync

private val Colors = lightColorScheme(
    primary = Navy,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFE5F1F7),
    onPrimaryContainer = NavyDeep,
    secondary = Sky,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFE8F5FB),
    onSecondaryContainer = NavyDeep,
    background = Mist,
    onBackground = Ink,
    surface = Color.White,
    onSurface = Ink,
    surfaceVariant = Color(0xFFF1F5F7),
    onSurfaceVariant = Slate,
    outline = Color(0xFFDCE4E8),
    error = Danger,
)

private val AppTypography = Typography(
    headlineLarge = TextStyle(
        fontSize = 30.sp,
        lineHeight = 36.sp,
        fontWeight = FontWeight.ExtraBold,
        letterSpacing = (-0.6).sp,
    ),
    headlineSmall = TextStyle(
        fontSize = 24.sp,
        lineHeight = 30.sp,
        fontWeight = FontWeight.Bold,
        letterSpacing = (-0.35).sp,
    ),
    titleMedium = TextStyle(
        fontSize = 16.sp,
        lineHeight = 22.sp,
        fontWeight = FontWeight.SemiBold,
    ),
    bodyMedium = TextStyle(
        fontSize = 14.sp,
        lineHeight = 20.sp,
        fontWeight = FontWeight.Normal,
    ),
    labelLarge = TextStyle(
        fontSize = 14.sp,
        lineHeight = 19.sp,
        fontWeight = FontWeight.SemiBold,
    ),
)

private val AppShapes = Shapes(
    extraSmall = RoundedCornerShape(10.dp),
    small = RoundedCornerShape(14.dp),
    medium = RoundedCornerShape(18.dp),
    large = RoundedCornerShape(24.dp),
    extraLarge = RoundedCornerShape(30.dp),
)

private const val PREFS = "ph_bulwark"
private const val KEY_SERVER = "server_id"
private const val KEY_SELF_HOSTED = "self_hosted_endpoint"
private const val KEY_ONBOARDING_DONE = "onboarding_done"
private const val KEY_VPN_CONSENTED = "vpn_consented"

/**
 * Hosts the guided onboarding journey ([OnboardingJourney]) and, once setup is
 * complete, a calm read-only protection dashboard. The journey vs. dashboard
 * decision is derived from saved onboarding state combined with LIVE protection
 * state, so a half-finished setup always resumes at the first incomplete step.
 */
class MainActivity : ComponentActivity() {

    private var accessibilityOn by mutableStateOf(false)
    private var vpnConsented by mutableStateOf(false)
    private var vpnRunning by mutableStateOf(false)
    private var antiRemovalOn by mutableStateOf(false)
    private var isDeviceOwner by mutableStateOf(false)
    private var caInstalled by mutableStateOf(false)
    private var paired by mutableStateOf(false)
    private var enrollment by mutableStateOf<EnrollmentRecord?>(null)
    private var cloudFilteringRequested by mutableStateOf(false)

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
        // Apply any newer guardian config while foregrounded. This also covers a
        // guardian turning protection back on while the VPN service is stopped.
        Thread({
            runCatching { ChildConfigSync.fetchAndReconcile(applicationContext) }
        }, "bulwark-config-sync").apply { isDaemon = true }.start()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (intent.getBooleanExtra(EXTRA_FROM_PROVISIONING, false)) {
            forceJourney = false
        }
        refreshLocalState()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        refreshLocalState()
        setContent {
            MaterialTheme(
                colorScheme = Colors,
                typography = AppTypography,
                shapes = AppShapes,
            ) {
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
            cloudFilteringRequested = cloudFilteringRequested,
            isDeviceOwner = isDeviceOwner,
            caInstalled = caInstalled,
        )
        val onboardingDone = prefs().getBoolean(KEY_ONBOARDING_DONE, false)
        val showDashboard = !forceJourney && onboardingDone && isFullySetUp(state)

        AnimatedContent(
            targetState = showDashboard,
            transitionSpec = { fadeIn(tween(260)).togetherWith(fadeOut(tween(180))) },
            label = "root",
        ) { dashboard ->
            if (dashboard) {
                PremiumStatusDashboard(
                    state = state,
                    enrollment = enrollment,
                    deviceId = Enrollment.stableDeviceId(this@MainActivity),
                    onOpenAccessibility = ::openAccessibilitySettings,
                    onStartVpn = ::requestVpnConsent,
                    onReconfigure = { forceJourney = true },
                    onOpenBrowser = ::openSafeBrowser,
                    canProvisionManaged = canProvisionManaged(),
                    onProvisionManaged = ::launchManagedProvisioning,
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

    private fun openAccessibilitySettings() {
        startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
    }

    private fun openSafeBrowser() {
        startActivity(Intent(this, co.predatorhunters.bulwark.browser.BrowserActivity::class.java))
    }

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

    private fun requestAntiRemoval() {
        if (Lockdown.isDeviceOwner(this)) {
            Lockdown.enforce(this)
            runCatching { CaTrust.ensureInstalled(this) }
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

    @Suppress("DEPRECATION")
    private fun canProvisionManaged(): Boolean {
        if (Lockdown.isDeviceOwner(this)) return false
        return runCatching {
            Lockdown.dpm(this).isProvisioningAllowed(
                android.app.admin.DevicePolicyManager.ACTION_PROVISION_MANAGED_DEVICE,
            )
        }.getOrDefault(false)
    }

    @Suppress("DEPRECATION")
    private fun launchManagedProvisioning() {
        val intent = Intent(android.app.admin.DevicePolicyManager.ACTION_PROVISION_MANAGED_DEVICE)
            .putExtra(
                android.app.admin.DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME,
                Lockdown.adminComponent(this),
            )
        runCatching { startActivity(intent) }
    }

    private fun refreshLocalState() {
        accessibilityOn = isAccessibilityEnabled()
        vpnConsented = prefs().getBoolean(KEY_VPN_CONSENTED, false) ||
            VpnService.prepare(this) == null
        vpnRunning = BulwarkVpnService.running
        isDeviceOwner = Lockdown.isDeviceOwner(this)
        antiRemovalOn = isDeviceOwner || Lockdown.isActiveAdmin(this)
        caInstalled = CaTrust.isInstalled(this)
        paired = Enrollment.isEnrolled(this)
        enrollment = Enrollment.record(this)
        cloudFilteringRequested = ChildConfigSync.cloudFilteringRequested(this)
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
