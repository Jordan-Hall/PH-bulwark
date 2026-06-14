package co.predatorhunters.bulwark

import android.util.Base64
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.SizeTransform
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import co.predatorhunters.bulwark.admin.EnrollmentRecord
import co.predatorhunters.bulwark.core.RustBridge
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import java.io.File
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

// ---------------------------------------------------------------------------
// Palette — single source of truth for both Onboarding and MainActivity.
// Calm, trustworthy, safe — NOT a scary security tool.
// ---------------------------------------------------------------------------
internal val Navy = Color(0xFF0F3D5C)
internal val NavyDeep = Color(0xFF0A2C44)
internal val Sky = Color(0xFF3AA0DC)
internal val Mist = Color(0xFFF5F7F1)
internal val Ink = Color(0xFF13212B)
internal val Slate = Color(0xFF5B6670)
internal val Good = Color(0xFF57A639)
internal val Warn = Color(0xFF996D14)
internal val Danger = Color(0xFFC0392B)

// ---------------------------------------------------------------------------
// Server model — keep IDs/endpoints identical to the previous screen.
// ---------------------------------------------------------------------------
internal data class ServerOption(val id: String, val labelRes: Int, val endpoint: String)

internal val Servers = listOf(
    ServerOption(
        "uk",
        R.string.server_uk,
        "https://api.predatorhunters.co.uk:8443",
    ),
    ServerOption("us", R.string.server_us, "https://us.cloud.phbulwark.app"),
    ServerOption("self", R.string.server_self, ""),
)

internal const val DEFAULT_SERVER = "uk"

// ---------------------------------------------------------------------------
// The guided journey: ONE thing per screen, with a calm progress indicator.
// ---------------------------------------------------------------------------
internal enum class Step {
    Welcome,
    Transparency,
    Accessibility,
    Vpn,
    AntiRemoval,
    Pair,
    Done,
}

/** The four "progress dot" steps. Welcome/Transparency are intro; Done is the finish. */
private val ProgressSteps = listOf(
    Step.Accessibility,
    Step.Vpn,
    Step.AntiRemoval,
    Step.Pair,
)

/**
 * Live, observed setup state. MainActivity supplies these from the real
 * services; the journey only reflects them.
 */
internal data class SetupState(
    val accessibilityOn: Boolean,
    val vpnConsented: Boolean,
    val vpnRunning: Boolean,
    val antiRemovalOn: Boolean,
    val paired: Boolean,
    /**
     * Guardian asked for server-side ("cloud") filtering. HONEST STATUS ONLY:
     * the server-side data path is still staged, so filtering keeps running
     * on-device regardless — this just lets the dashboard say it's rolling out.
     */
    val cloudFilteringRequested: Boolean = false,
    /**
     * This app is the Android **Device Owner** — the only role that can install
     * the per-install TLS-inspection CA into the SYSTEM trust store. Without it,
     * the filtering VPN fail-closes (it would break all HTTPS), so this gates
     * whether full network filtering can run at all. Defaulted so existing call
     * sites (DoneStep summary, journey) stay source-compatible.
     */
    val isDeviceOwner: Boolean = false,
    /**
     * The per-install TLS-inspection CA is trusted in the SYSTEM store. Together
     * with [isDeviceOwner] this is what lets inspected HTTPS validate instead of
     * showing "connection not private".
     */
    val caInstalled: Boolean = false,
) {
    val vpnReady: Boolean get() = vpnConsented || vpnRunning

    /**
     * The honest "Protection active" definition: Device Owner + inspection CA
     * system-trusted + the filtering tunnel actually up. [vpnRunning] alone is
     * already gated on CA trust by the service's fail-closed [establish] path,
     * but we state all three so the reason ladder can name the missing piece.
     */
    val protectionActive: Boolean get() = isDeviceOwner && caInstalled && vpnRunning
}

/**
 * First incomplete required step, so a half-finished setup resumes where it left
 * off. Anti-removal is optional and never gates completion.
 */
internal fun firstIncompleteStep(state: SetupState): Step = when {
    !state.accessibilityOn -> Step.Accessibility
    !state.vpnReady -> Step.Vpn
    !state.paired -> Step.Pair
    else -> Step.Done
}

internal fun isFullySetUp(state: SetupState): Boolean =
    state.accessibilityOn && state.vpnReady && state.paired

// ===========================================================================
// Journey host
// ===========================================================================

@Composable
internal fun OnboardingJourney(
    state: SetupState,
    deviceId: String,
    savedServer: String,
    savedSelfHosted: String,
    onSaveServer: (String, String) -> Unit,
    onSaveEnrollment: (String, String, String, String, String) -> Unit,
    onGrantAccessibility: () -> Unit,
    onGrantVpn: () -> Unit,
    onGrantAntiRemoval: () -> Unit,
    onFinish: () -> Unit,
) {
    var step by remember { mutableStateOf(firstIncompleteStep(state)) }
    var forward by remember { mutableStateOf(true) }

    fun goTo(next: Step) {
        forward = next.ordinal >= step.ordinal
        step = next
    }

    val progressIndex = ProgressSteps.indexOf(step)
    val showProgress = step != Step.Welcome && step != Step.Transparency && step != Step.Done

    Column(
        Modifier
            .fillMaxSize()
            .background(Mist)
            .padding(horizontal = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.height(28.dp))
        if (showProgress) {
            ProgressDots(current = progressIndex, total = ProgressSteps.size)
            Spacer(Modifier.height(6.dp))
            Text(
                stringResource(R.string.step_progress, progressIndex + 1, ProgressSteps.size),
                color = Slate,
                fontSize = 12.sp,
                fontWeight = FontWeight.Medium,
            )
        }

        AnimatedContent(
            targetState = step,
            transitionSpec = {
                val dir = if (forward) 1 else -1
                (slideInHorizontally(tween(320)) { full -> dir * full / 6 } + fadeIn(tween(320)))
                    .togetherWith(
                        slideOutHorizontally(tween(220)) { full -> -dir * full / 6 } + fadeOut(tween(180)),
                    )
                    .using(SizeTransform(clip = false))
            },
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth(),
            label = "step",
        ) { current ->
            Column(
                Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState()),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                when (current) {
                    Step.Welcome -> WelcomeStep(onNext = { goTo(Step.Transparency) })

                    Step.Transparency -> TransparencyStep(
                        onBack = { goTo(Step.Welcome) },
                        onNext = {
                            val next = firstIncompleteStep(state)
                            goTo(if (next == Step.Done) Step.Accessibility else next)
                        },
                    )

                    Step.Accessibility -> AccessibilityStep(
                        granted = state.accessibilityOn,
                        onGrant = onGrantAccessibility,
                        onBack = { goTo(Step.Transparency) },
                        onNext = { goTo(Step.Vpn) },
                    )

                    Step.Vpn -> VpnStep(
                        ready = state.vpnReady,
                        running = state.vpnRunning,
                        onGrant = onGrantVpn,
                        onBack = { goTo(Step.Accessibility) },
                        onNext = { goTo(Step.AntiRemoval) },
                    )

                    Step.AntiRemoval -> AntiRemovalStep(
                        enabled = state.antiRemovalOn,
                        onGrant = onGrantAntiRemoval,
                        onBack = { goTo(Step.Vpn) },
                        onNext = { goTo(Step.Pair) },
                    )

                    Step.Pair -> PairStep(
                        alreadyPaired = state.paired,
                        deviceId = deviceId,
                        savedServer = savedServer,
                        savedSelfHosted = savedSelfHosted,
                        onSaveServer = onSaveServer,
                        onEnrollment = onSaveEnrollment,
                        onBack = { goTo(Step.AntiRemoval) },
                        onNext = { goTo(Step.Done) },
                    )

                    Step.Done -> DoneStep(
                        state = state,
                        onFinish = onFinish,
                    )
                }
            }
        }
    }
}

// ===========================================================================
// Step screens — each: big headline, one short paragraph, single primary CTA.
// ===========================================================================

@Composable
private fun WelcomeStep(onNext: () -> Unit) {
    StepScaffold(
        primaryLabel = stringResource(R.string.welcome_cta),
        onPrimary = onNext,
    ) {
        Image(
            painter = painterResource(R.drawable.bulwark_logo),
            contentDescription = stringResource(R.string.cd_shield),
            modifier = Modifier
                .size(112.dp)
                .clip(RoundedCornerShape(24.dp)),
        )
        Spacer(Modifier.height(24.dp))
        Text(
            stringResource(R.string.welcome_title),
            color = Navy,
            fontSize = 30.sp,
            fontWeight = FontWeight.ExtraBold,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        Text(
            stringResource(R.string.welcome_body),
            color = Slate,
            fontSize = 16.sp,
            fontWeight = FontWeight.Medium,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(20.dp))
        TrustChip(stringResource(R.string.welcome_chip))
    }
}

@Composable
private fun TransparencyStep(onBack: () -> Unit, onNext: () -> Unit) {
    StepScaffold(
        primaryLabel = stringResource(R.string.transparency_cta),
        onPrimary = onNext,
        secondaryLabel = stringResource(R.string.action_back),
        onSecondary = onBack,
    ) {
        StepIcon("🛡️")
        Spacer(Modifier.height(20.dp))
        Text(
            stringResource(R.string.transparency_title),
            color = Navy,
            fontSize = 26.sp,
            fontWeight = FontWeight.ExtraBold,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        Text(
            stringResource(R.string.transparency_body),
            color = Ink,
            fontSize = 16.sp,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(18.dp))
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            PromiseRow(stringResource(R.string.transparency_promise_1))
            PromiseRow(stringResource(R.string.transparency_promise_2))
            PromiseRow(stringResource(R.string.transparency_promise_3))
        }
    }
}

@Composable
private fun AccessibilityStep(
    granted: Boolean,
    onGrant: () -> Unit,
    onBack: () -> Unit,
    onNext: () -> Unit,
) {
    PermissionScaffold(
        emoji = "💬",
        title = stringResource(R.string.accessibility_title),
        body = stringResource(R.string.accessibility_body),
        whyLine = stringResource(R.string.accessibility_why),
        granted = granted,
        grantedLabel = stringResource(R.string.accessibility_granted),
        actionLabel = stringResource(R.string.accessibility_action),
        reGrantLabel = stringResource(R.string.accessibility_regrant),
        trust = stringResource(R.string.accessibility_trust),
        onGrant = onGrant,
        onBack = onBack,
        onNext = onNext,
    )
}

@Composable
private fun VpnStep(
    ready: Boolean,
    running: Boolean,
    onGrant: () -> Unit,
    onBack: () -> Unit,
    onNext: () -> Unit,
) {
    PermissionScaffold(
        emoji = "🌐",
        title = stringResource(R.string.vpn_title),
        body = stringResource(R.string.vpn_body),
        whyLine = stringResource(R.string.vpn_why),
        granted = ready,
        grantedLabel = stringResource(if (running) R.string.vpn_granted_active else R.string.vpn_granted_ready),
        actionLabel = stringResource(R.string.vpn_action),
        reGrantLabel = stringResource(R.string.vpn_regrant),
        trust = stringResource(R.string.vpn_trust),
        onGrant = onGrant,
        onBack = onBack,
        onNext = onNext,
    )
}

@Composable
private fun AntiRemovalStep(
    enabled: Boolean,
    onGrant: () -> Unit,
    onBack: () -> Unit,
    onNext: () -> Unit,
) {
    StepScaffold(
        primaryLabel = stringResource(R.string.action_continue),
        onPrimary = onNext,
        secondaryLabel = stringResource(R.string.action_back),
        onSecondary = onBack,
    ) {
        StepIcon("🔒")
        Spacer(Modifier.height(18.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                stringResource(R.string.anti_removal_title),
                color = Navy,
                fontSize = 26.sp,
                fontWeight = FontWeight.ExtraBold,
            )
            Spacer(Modifier.width(10.dp))
            OptionalPill()
        }
        Spacer(Modifier.height(12.dp))
        Text(
            stringResource(R.string.anti_removal_body),
            color = Ink,
            fontSize = 16.sp,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(8.dp))
        Text(
            stringResource(R.string.anti_removal_note),
            color = Slate,
            fontSize = 14.sp,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(20.dp))
        StatusLine(
            active = enabled,
            on = stringResource(R.string.anti_removal_on),
            off = stringResource(R.string.anti_removal_off),
        )
        if (!enabled) {
            Spacer(Modifier.height(16.dp))
            OutlinedButton(
                onClick = onGrant,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                shape = RoundedCornerShape(12.dp),
            ) {
                Text(stringResource(R.string.anti_removal_advanced), color = Navy, fontWeight = FontWeight.SemiBold)
            }
        }
    }
}

@Composable
private fun PairStep(
    alreadyPaired: Boolean,
    deviceId: String,
    savedServer: String,
    savedSelfHosted: String,
    onSaveServer: (String, String) -> Unit,
    onEnrollment: (String, String, String, String, String) -> Unit,
    onBack: () -> Unit,
    onNext: () -> Unit,
) {
    var selectedServer by remember(savedServer) { mutableStateOf(savedServer.ifBlank { DEFAULT_SERVER }) }
    var selfHosted by remember(savedSelfHosted) { mutableStateOf(savedSelfHosted) }
    var code by remember { mutableStateOf("") }
    var fullSetupCode by remember { mutableStateOf("") }
    var state by remember {
        mutableStateOf<PairingState>(if (alreadyPaired) PairingState.Success("") else PairingState.Idle)
    }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val caPath = RustBridge.clusterCaPath(context)
    // Whether this device already holds the server's pinned certificate (from a
    // previous setup code); refreshed after a successful pin below.
    var caPinned by remember { mutableStateOf(File(caPath).exists()) }

    // Full-setup-code path: the guardian scans the console's setup QR with the
    // camera (one tap) or pastes the copied payload. Both carry the SAME
    // single-use pair code plus the server address and (for https servers) the
    // certificate this device must pin before connecting.
    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.let { fullSetupCode = it }
    }
    val scanPrompt = stringResource(R.string.pair_scan_prompt)
    val payloadResult = remember(fullSetupCode) {
        if (fullSetupCode.isBlank()) null else parseSetupPayload(context, fullSetupCode)
    }
    val payload = (payloadResult as? SetupPayloadResult.Parsed)?.payload
    val payloadError = (payloadResult as? SetupPayloadResult.Invalid)?.message
    val payloadExpired = payload?.isExpired() == true

    val endpoint = payload?.serverEndpoint ?: resolveEndpoint(selectedServer, selfHosted)
    val normalizedCode = payload?.pairCode ?: normalizedPairCode(code)
    // A built-in cloud region serves a PUBLIC certificate (Let's Encrypt), so it
    // needs no pinned CA. A self-hosted https server may use a private CA: there
    // we still want the certificate up front (via the full setup code) rather
    // than a failed handshake. A payload without a CA normally means the server
    // validates via public roots — EXCEPT when it says `ca_omitted` (the console
    // pins a CA but the QR was too dense to carry it; the copy button has the
    // full code). Manual self-hosted entry (no payload, no pin) also requires
    // the CA up front.
    val isBuiltinEndpoint = Servers.any { it.id != "self" && it.endpoint == endpoint }
    val needsCa = endpoint.startsWith("https://") && !isBuiltinEndpoint && !caPinned &&
        (payload == null || (payload.clusterCaPem == null && payload.caOmitted))
    val endpointReady = endpoint.isNotBlank()
    val loading = state is PairingState.Loading
    val paired = alreadyPaired || state is PairingState.Success
    val readyToPair = endpointReady && normalizedCode.length >= 4 &&
        payloadError == null && !payloadExpired && !needsCa

    StepScaffold(
        primaryLabel = if (paired) stringResource(R.string.action_continue) else stringResource(R.string.pair_cta),
        onPrimary = {
            if (paired) {
                onNext()
            } else {
                state = PairingState.Loading
                val pairEndpoint = endpoint
                val pairCode = normalizedCode
                val caPem = payload?.clusterCaPem
                val fromPayload = payload != null
                scope.launch {
                    val outcome = withContext(Dispatchers.IO) {
                        // Pin the server's certificate BEFORE the redeem call —
                        // an https endpoint is only ever contacted verified.
                        if (caPem != null) {
                            val pinned = runCatching { File(caPath).writeText(caPem) }.isSuccess
                            if (!pinned) {
                                return@withContext PairingOutcome.Error(
                                    context.getString(R.string.pair_err_save_cert),
                                )
                            }
                        }
                        runCatching {
                            RustBridge.ensureLoaded()
                            parsePairingResult(
                                context,
                                RustBridge.redeemPairCode(pairEndpoint, pairCode, deviceId, caPath),
                            )
                        }.getOrElse {
                            PairingOutcome.Error(
                                context.getString(
                                    R.string.pair_err_bridge,
                                    it.message ?: it.javaClass.simpleName,
                                ),
                            )
                        }
                    }
                    if (caPem != null) caPinned = File(caPath).exists()
                    state = when (outcome) {
                        is PairingOutcome.Success -> {
                            if (fromPayload) {
                                // Keep the saved server choice consistent with
                                // what the setup code actually paired against.
                                val preset = Servers.firstOrNull { it.endpoint == pairEndpoint }
                                onSaveServer(preset?.id ?: "self", if (preset == null) pairEndpoint else selfHosted)
                            }
                            onEnrollment(outcome.familyId, outcome.childId, pairEndpoint, deviceId, outcome.deviceToken)
                            PairingState.Success(outcome.childId)
                        }
                        is PairingOutcome.Error -> PairingState.Error(outcome.message)
                    }
                }
            }
        },
        primaryEnabled = paired || (readyToPair && !loading),
        primaryLoading = loading,
        secondaryLabel = stringResource(R.string.action_back),
        onSecondary = onBack,
    ) {
        StepIcon("🔗")
        Spacer(Modifier.height(16.dp))
        Text(
            stringResource(if (paired) R.string.pair_title_done else R.string.pair_title),
            color = Navy,
            fontSize = 26.sp,
            fontWeight = FontWeight.ExtraBold,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(10.dp))
        Text(
            stringResource(if (paired) R.string.pair_body_done else R.string.pair_body),
            color = Slate,
            fontSize = 15.sp,
            textAlign = TextAlign.Center,
        )

        if (!paired) {
            Spacer(Modifier.height(20.dp))
            OutlinedButton(
                onClick = {
                    scanLauncher.launch(
                        ScanOptions()
                            .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                            .setPrompt(scanPrompt)
                            .setBeepEnabled(false)
                            .setOrientationLocked(false),
                    )
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.pair_scan))
            }
            Spacer(Modifier.height(10.dp))
            OutlinedTextField(
                value = fullSetupCode,
                onValueChange = { fullSetupCode = it },
                modifier = Modifier.fillMaxWidth(),
                minLines = 2,
                maxLines = 4,
                label = { Text(stringResource(R.string.pair_full_code_label)) },
                placeholder = { Text(stringResource(R.string.pair_full_code_hint)) },
            )
            Spacer(Modifier.height(12.dp))
            if (payload != null) {
                Card(
                    Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    elevation = CardDefaults.cardElevation(1.dp),
                ) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(stringResource(R.string.pair_from_console), color = Ink, fontSize = 15.sp, fontWeight = FontWeight.Bold)
                        if (payload.childName.isNotBlank()) {
                            DetailLine(stringResource(R.string.pair_detail_child), payload.childName)
                        }
                        DetailLine(stringResource(R.string.pair_detail_server), payload.serverEndpoint)
                        DetailLine(stringResource(R.string.pair_detail_code), payload.pairCode)
                        DetailLine(
                            stringResource(R.string.pair_detail_certificate),
                            when {
                                payload.clusterCaPem != null -> stringResource(R.string.pair_cert_included)
                                payload.caOmitted -> stringResource(R.string.pair_cert_omitted)
                                else -> stringResource(R.string.pair_cert_public)
                            },
                        )
                    }
                }
            } else {
                Card(
                    Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    elevation = CardDefaults.cardElevation(1.dp),
                ) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text(stringResource(R.string.pair_server_heading), color = Ink, fontSize = 15.sp, fontWeight = FontWeight.Bold)
                        Servers.forEach { opt ->
                            ServerRow(
                                option = opt,
                                selected = selectedServer == opt.id,
                                onClick = {
                                    selectedServer = opt.id
                                    onSaveServer(opt.id, selfHosted)
                                },
                            )
                        }
                        if (selectedServer == "self") {
                            OutlinedTextField(
                                value = selfHosted,
                                onValueChange = {
                                    selfHosted = it
                                    onSaveServer(selectedServer, it)
                                },
                                modifier = Modifier.fillMaxWidth(),
                                singleLine = true,
                                label = { Text(stringResource(R.string.pair_self_hosted_label)) },
                                placeholder = { Text(stringResource(R.string.pair_self_hosted_hint)) },
                                keyboardOptions = KeyboardOptions(
                                    keyboardType = KeyboardType.Uri,
                                    imeAction = ImeAction.Done,
                                ),
                            )
                        }
                    }
                }
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = code,
                    onValueChange = { code = normalizedPairCode(it).take(12) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    label = { Text(stringResource(R.string.pair_short_code_label)) },
                    keyboardOptions = KeyboardOptions(
                        capitalization = KeyboardCapitalization.Characters,
                        keyboardType = KeyboardType.Ascii,
                        imeAction = ImeAction.Done,
                    ),
                )
            }
            Spacer(Modifier.height(8.dp))
            val current = state
            when {
                payloadError != null ->
                    Text(payloadError, color = Danger, fontSize = 13.sp)
                payloadExpired ->
                    Text(
                        stringResource(R.string.pair_expired),
                        color = Warn,
                        fontSize = 13.sp,
                    )
                needsCa && payload != null ->
                    Text(
                        stringResource(R.string.pair_needs_ca_qr),
                        color = Warn,
                        fontSize = 13.sp,
                    )
                needsCa ->
                    Text(
                        stringResource(R.string.pair_needs_ca),
                        color = Warn,
                        fontSize = 13.sp,
                    )
                current is PairingState.Loading ->
                    Text(stringResource(R.string.pair_contacting), color = Slate, fontSize = 13.sp)
                current is PairingState.Success ->
                    Text(stringResource(R.string.pair_success_short), color = Good, fontSize = 13.sp)
                current is PairingState.Error ->
                    Text(current.message, color = Danger, fontSize = 13.sp)
                !endpointReady ->
                    Text(stringResource(R.string.pair_need_self_url), color = Warn, fontSize = 13.sp)
            }
        } else {
            Spacer(Modifier.height(20.dp))
            StatusLine(active = true, on = stringResource(R.string.pair_status_paired), off = "")
        }
    }
}

@Composable
private fun DoneStep(state: SetupState, onFinish: () -> Unit) {
    // Honest finish: only claim "Protection active" when the tunnel is genuinely
    // up (managed device + CA trusted). Otherwise this is a setup-saved state and
    // the dashboard's managed-device guidance carries the next step — never a
    // green "active" that contradicts the dashboard.
    val active = state.protectionActive
    StepScaffold(
        primaryLabel = stringResource(R.string.done_cta),
        onPrimary = onFinish,
    ) {
        Box(
            Modifier
                .size(96.dp)
                .clip(CircleShape)
                .background(if (active) Color(0xFFE7F4EE) else Color(0xFFFBF2DE)),
            contentAlignment = Alignment.Center,
        ) {
            Text(if (active) "✓" else "→", color = if (active) Good else Warn, fontSize = 48.sp, fontWeight = FontWeight.ExtraBold)
        }
        Spacer(Modifier.height(24.dp))
        Text(
            stringResource(if (active) R.string.done_title_active else R.string.done_title_saved),
            color = Navy,
            fontSize = 28.sp,
            fontWeight = FontWeight.ExtraBold,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(10.dp))
        Text(
            stringResource(if (active) R.string.done_body_active else R.string.done_body_saved),
            color = Slate,
            fontSize = 16.sp,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(24.dp))
        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White),
            elevation = CardDefaults.cardElevation(1.dp),
        ) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                SummaryRow(stringResource(R.string.summary_paired), state.paired)
                SummaryRow(stringResource(R.string.summary_chat_safety), state.accessibilityOn)
                SummaryRow(stringResource(R.string.summary_filtering_ready), state.vpnReady)
                SummaryRow(stringResource(R.string.summary_managed), state.isDeviceOwner, optionalWhenOff = true)
                SummaryRow(stringResource(R.string.summary_anti_removal), state.antiRemovalOn, optionalWhenOff = true)
            }
        }
    }
}

// ===========================================================================
// Status dashboard (trimmed evolution of the old single-scroll screen).
// Shown once setup is complete; calm, read-only with light recovery actions.
// ===========================================================================

@Composable
internal fun StatusDashboard(
    state: SetupState,
    enrollment: EnrollmentRecord?,
    deviceId: String,
    onOpenAccessibility: () -> Unit,
    onStartVpn: () -> Unit,
    onReconfigure: () -> Unit,
    /** Open the in-app PH Bulwark Browser (full-content pre-checked web view). */
    onOpenBrowser: () -> Unit = {},
    /** True only on a fresh/no-accounts device where the app may legitimately
     *  launch managed provisioning itself; surfaces the one-tap entry. */
    canProvisionManaged: Boolean = false,
    /** Launch the platform managed-provisioning flow (Device Owner setup). */
    onProvisionManaged: () -> Unit = {},
) {
    val context = LocalContext.current
    Column(
        Modifier
            .fillMaxSize()
            .background(Mist)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        // HONEST header: "Protection active" requires the filtering tunnel to be
        // genuinely up — which the service only allows on a managed (Device Owner)
        // device with the inspection CA system-trusted. Everything short of that
        // is "Setup needed" with one calm, guardian-facing reason.
        val active = state.protectionActive
        Box(
            Modifier
                .size(112.dp)
                .clip(CircleShape)
                .background(if (active) Color(0x1F57A639) else Color(0x1F996D14)),
            contentAlignment = Alignment.Center,
        ) {
            Image(
                painter = painterResource(R.drawable.bulwark_logo),
                contentDescription = stringResource(R.string.cd_shield),
                modifier = Modifier
                    .size(76.dp)
                    .clip(RoundedCornerShape(18.dp)),
            )
        }
        Text(stringResource(R.string.dashboard_brand), color = Slate, fontSize = 12.sp, fontWeight = FontWeight.Bold, letterSpacing = 2.sp)
        Text(
            stringResource(if (active) R.string.dashboard_title_active else R.string.dashboard_title_setup),
            color = Navy,
            fontSize = 26.sp,
            fontWeight = FontWeight.ExtraBold,
            textAlign = TextAlign.Center,
        )
        Text(
            statusReason(context, state),
            color = if (active) Good else Warn,
            fontSize = 14.sp,
            fontWeight = FontWeight.SemiBold,
            textAlign = TextAlign.Center,
        )

        // Child SOS — paired devices only (an unpaired SOS has nowhere to go).
        if (enrollment != null) {
            SosCard()
        }

        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White),
            elevation = CardDefaults.cardElevation(1.dp),
        ) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.dashboard_status_heading), color = Ink, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                SummaryRow(stringResource(R.string.summary_paired), state.paired)
                SummaryRow(stringResource(R.string.summary_chat_safety), state.accessibilityOn)
                // HONEST: network filtering is "on" only when the tunnel is truly
                // up. The service fail-closes off a managed device, so consent
                // alone must not read as "filtering on".
                SummaryRow(stringResource(R.string.summary_filtering_on), state.vpnRunning)
                SummaryRow(stringResource(R.string.summary_managed), state.isDeviceOwner, optionalWhenOff = true)
                SummaryRow(stringResource(R.string.summary_anti_removal), state.antiRemovalOn, optionalWhenOff = true)
                if (state.cloudFilteringRequested) {
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .background(Color(0xFFEAF1F6))
                            .padding(horizontal = 12.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.Top,
                    ) {
                        Text("☁", color = Sky, fontSize = 14.sp)
                        Spacer(Modifier.width(8.dp))
                        Text(
                            stringResource(R.string.dashboard_cloud_note),
                            color = Navy,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Medium,
                            lineHeight = 16.sp,
                        )
                    }
                }
            }
        }

        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White),
            elevation = CardDefaults.cardElevation(1.dp),
        ) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.dashboard_this_device), color = Ink, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                if (enrollment != null) {
                    DetailLine(stringResource(R.string.dashboard_detail_server), enrollment.clusterEndpoint)
                    DetailLine(stringResource(R.string.dashboard_detail_child), shortId(enrollment.childId))
                    DetailLine(stringResource(R.string.dashboard_detail_device), shortId(enrollment.deviceId))
                    if (enrollment.deviceOwnerProvisioned) {
                        DetailLine(stringResource(R.string.dashboard_management), stringResource(R.string.dashboard_management_active))
                    }
                } else {
                    DetailLine(stringResource(R.string.dashboard_detail_device), shortId(deviceId))
                }
            }
        }

        // The blocker for full web filtering: only a Device Owner can system-trust
        // the on-device TLS-inspection certificate, so an unmanaged device gets the
        // honest "what to do next" instead of a silent half-protected state.
        if (!state.isDeviceOwner) {
            ManagedSetupCard(
                canProvisionManaged = canProvisionManaged,
                onProvisionManaged = onProvisionManaged,
            )
        }

        if (!state.accessibilityOn) {
            DashboardAction(stringResource(R.string.dashboard_action_chat), onOpenAccessibility)
        }
        // Honest: offer the action whenever filtering is not actually running
        // (consent without a live tunnel still needs a tap to (re)start it).
        if (!state.vpnRunning) {
            DashboardAction(stringResource(R.string.dashboard_action_filtering), onStartVpn)
        }

        // The in-app safe browser: a guarded web view that pre-checks a page's
        // full rendered content (visible + off-screen) before the child reads it.
        DashboardAction("Open safe browser", onOpenBrowser)

        OutlinedButton(
            onClick = onReconfigure,
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            shape = RoundedCornerShape(12.dp),
        ) {
            Text(stringResource(R.string.dashboard_review), color = Navy, fontWeight = FontWeight.SemiBold)
        }

        PrivacyFooter()
    }
}

/**
 * ONE calm, guardian-facing line explaining the current protection state. The
 * ladder names the single most important missing piece (most-blocking first) so
 * the dashboard never says "Protection active" and "do X" at the same time.
 */
internal fun statusReason(context: android.content.Context, state: SetupState): String = context.getString(
    when {
        state.protectionActive -> R.string.reason_active
        !state.paired -> R.string.reason_pair
        !state.isDeviceOwner -> R.string.reason_managed
        !state.caInstalled -> R.string.reason_ca
        !state.vpnConsented -> R.string.reason_consent
        else -> R.string.reason_starting
    },
)

/**
 * Guidance for getting this device to **Device Owner**, the only role that can
 * system-trust the on-device TLS-inspection certificate so secure sites can be
 * filtered. Two honest, real paths — never a button that pretends to do what the
 * app can't. Where the platform genuinely allows in-app managed provisioning
 * (a fresh / no-accounts device), the one-tap entry is offered.
 */
@Composable
private fun ManagedSetupCard(
    canProvisionManaged: Boolean,
    onProvisionManaged: () -> Unit,
) {
    Card(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(1.dp),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(stringResource(R.string.managed_title), color = Ink, fontSize = 16.sp, fontWeight = FontWeight.Bold)
            Text(
                stringResource(R.string.managed_body),
                color = Slate,
                fontSize = 13.sp,
                lineHeight = 18.sp,
            )
            ProvisionPath(
                badge = "A",
                title = stringResource(R.string.managed_path_a_title),
                body = stringResource(R.string.managed_path_a_body),
            )
            ProvisionPath(
                badge = "B",
                title = stringResource(R.string.managed_path_b_title),
                body = stringResource(R.string.managed_path_b_body),
            )
            if (canProvisionManaged) {
                Spacer(Modifier.height(2.dp))
                Button(
                    onClick = onProvisionManaged,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Navy, contentColor = Color.White),
                ) {
                    Text(stringResource(R.string.managed_cta), fontWeight = FontWeight.SemiBold)
                }
                Text(
                    stringResource(R.string.managed_available_note),
                    color = Slate,
                    fontSize = 11.sp,
                )
            }
        }
    }
}

@Composable
private fun ProvisionPath(badge: String, title: String, body: String) {
    Row(verticalAlignment = Alignment.Top) {
        Box(
            Modifier
                .size(24.dp)
                .clip(CircleShape)
                .background(Color(0xFFEAF1F6)),
            contentAlignment = Alignment.Center,
        ) {
            Text(badge, color = Navy, fontSize = 12.sp, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.width(10.dp))
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, color = Ink, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
            Text(body, color = Slate, fontSize = 12.sp, lineHeight = 16.sp)
        }
    }
}

@Composable
private fun DashboardAction(label: String, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        modifier = Modifier
            .fillMaxWidth()
            .height(50.dp),
        shape = RoundedCornerShape(12.dp),
        colors = ButtonDefaults.buttonColors(containerColor = Navy, contentColor = Color.White),
    ) {
        Text(label, fontWeight = FontWeight.SemiBold)
    }
}

// ===========================================================================
// Reusable building blocks
// ===========================================================================

/**
 * Calm step layout: centred content, then a primary + optional secondary button
 * with generous spacing. Lives inside the journey's scrolling column.
 */
@Composable
private fun StepScaffold(
    primaryLabel: String,
    onPrimary: () -> Unit,
    primaryEnabled: Boolean = true,
    primaryLoading: Boolean = false,
    secondaryLabel: String? = null,
    onSecondary: (() -> Unit)? = null,
    content: @Composable () -> Unit,
) {
    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
        Spacer(Modifier.height(24.dp))
        content()
        Spacer(Modifier.height(36.dp))
        Button(
            onClick = onPrimary,
            enabled = primaryEnabled && !primaryLoading,
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
            shape = RoundedCornerShape(14.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Navy, contentColor = Color.White),
        ) {
            if (primaryLoading) {
                CircularProgressIndicator(Modifier.size(20.dp), color = Color.White, strokeWidth = 2.dp)
            } else {
                Text(primaryLabel, fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
            }
        }
        if (secondaryLabel != null && onSecondary != null) {
            Spacer(Modifier.height(6.dp))
            OutlinedButton(
                onClick = onSecondary,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                shape = RoundedCornerShape(14.dp),
            ) {
                Text(secondaryLabel, color = Slate, fontWeight = FontWeight.Medium)
            }
        }
        Spacer(Modifier.height(24.dp))
    }
}

/**
 * The shared permission step body: emoji, title, plain-language reason, a "why"
 * line, live status, a single primary grant, and trust microcopy.
 */
@Composable
private fun PermissionScaffold(
    emoji: String,
    title: String,
    body: String,
    whyLine: String,
    granted: Boolean,
    grantedLabel: String,
    actionLabel: String,
    reGrantLabel: String,
    trust: String,
    onGrant: () -> Unit,
    onBack: () -> Unit,
    onNext: () -> Unit,
) {
    StepScaffold(
        primaryLabel = if (granted) stringResource(R.string.action_continue) else actionLabel,
        onPrimary = { if (granted) onNext() else onGrant() },
        secondaryLabel = stringResource(R.string.action_back),
        onSecondary = onBack,
    ) {
        StepIcon(emoji)
        Spacer(Modifier.height(20.dp))
        Text(
            title,
            color = Navy,
            fontSize = 26.sp,
            fontWeight = FontWeight.ExtraBold,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        Text(body, color = Ink, fontSize = 16.sp, textAlign = TextAlign.Center)
        Spacer(Modifier.height(14.dp))
        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFFEAF1F6)),
        ) {
            Text(
                whyLine,
                color = Navy,
                fontSize = 13.sp,
                fontWeight = FontWeight.Medium,
                modifier = Modifier.padding(14.dp),
            )
        }
        Spacer(Modifier.height(18.dp))
        StatusLine(active = granted, on = grantedLabel, off = stringResource(R.string.action_not_on_yet))
        if (granted) {
            Spacer(Modifier.height(12.dp))
            OutlinedButton(
                onClick = onGrant,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(46.dp),
                shape = RoundedCornerShape(12.dp),
            ) {
                Text(reGrantLabel, color = Slate, fontWeight = FontWeight.Medium)
            }
        }
        Spacer(Modifier.height(14.dp))
        Text(trust, color = Slate, fontSize = 12.sp, textAlign = TextAlign.Center)
    }
}

@Composable
private fun ProgressDots(current: Int, total: Int) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        repeat(total) { i ->
            val widthDp by animateFloatAsState(
                targetValue = if (i == current) 30f else 9f,
                animationSpec = tween(320),
                label = "dot$i",
            )
            val dotColor by animateColorAsState(
                targetValue = when {
                    i == current -> Sky
                    current >= 0 && i < current -> Good
                    else -> Color(0xFFD3DEE7)
                },
                animationSpec = tween(320),
                label = "dotColor$i",
            )
            Box(
                Modifier
                    .height(9.dp)
                    .width(widthDp.dp)
                    .clip(RoundedCornerShape(50))
                    .background(dotColor),
            )
        }
    }
}

@Composable
private fun StepIcon(emoji: String) {
    Box(
        Modifier
            .size(96.dp)
            .clip(CircleShape)
            .background(Color(0x143AA0DC)),
        contentAlignment = Alignment.Center,
    ) {
        Box(
            Modifier
                .size(80.dp)
                .clip(CircleShape)
                .background(Brush.verticalGradient(listOf(Color(0xFFEFF6FA), Color(0xFFDDEAF3))))
                .border(1.dp, Color(0xFFCBDEE9), CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            Text(emoji, fontSize = 38.sp)
        }
    }
}

@Composable
private fun StatusLine(active: Boolean, on: String, off: String) {
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(if (active) Color(0xFFE7F4EE) else Color(0xFFF1F4F6))
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .size(22.dp)
                .clip(CircleShape)
                .background(if (active) Good else Color(0xFFCBD5DC)),
            contentAlignment = Alignment.Center,
        ) {
            Text(if (active) "✓" else "•", color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.width(10.dp))
        Text(
            if (active) on else off,
            color = if (active) Good else Slate,
            fontSize = 14.sp,
            fontWeight = FontWeight.SemiBold,
        )
    }
}

@Composable
private fun SummaryRow(label: String, active: Boolean, optionalWhenOff: Boolean = false) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier
                .size(20.dp)
                .clip(CircleShape)
                .background(
                    when {
                        active -> Good
                        optionalWhenOff -> Color(0xFFCBD5DC)
                        else -> Color(0xFFF1C0BB)
                    },
                ),
            contentAlignment = Alignment.Center,
        ) {
            Text(if (active) "✓" else "•", color = Color.White, fontSize = 11.sp, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.width(10.dp))
        Text(label, color = Ink, fontSize = 14.sp, fontWeight = FontWeight.Medium, modifier = Modifier.weight(1f))
        Text(
            stringResource(
                when {
                    active -> R.string.state_on
                    optionalWhenOff -> R.string.state_optional
                    else -> R.string.state_off
                },
            ),
            color = when {
                active -> Good
                optionalWhenOff -> Slate
                else -> Danger
            },
            fontSize = 13.sp,
            fontWeight = FontWeight.Bold,
        )
    }
}

@Composable
private fun PromiseRow(text: String) {
    Row(verticalAlignment = Alignment.Top) {
        Text("✓", color = Good, fontSize = 16.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.width(10.dp))
        Text(text, color = Ink, fontSize = 14.sp)
    }
}

@Composable
private fun TrustChip(text: String) {
    Box(
        Modifier
            .clip(RoundedCornerShape(50))
            .background(NavyDeep)
            .padding(horizontal = 14.dp, vertical = 7.dp),
    ) {
        Text(text, color = Sky, fontSize = 12.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun OptionalPill() {
    Box(
        Modifier
            .clip(RoundedCornerShape(50))
            .background(Color(0xFFF1F4F6))
            .padding(horizontal = 10.dp, vertical = 4.dp),
    ) {
        Text(stringResource(R.string.anti_removal_optional), color = Slate, fontSize = 11.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun ServerRow(option: ServerOption, selected: Boolean, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(if (selected) Color(0xFFEAF1F6) else Color.White)
            .clickable(onClick = onClick)
            .padding(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .size(20.dp)
                .clip(CircleShape)
                .background(if (selected) Navy else Color(0xFFD3DEE7)),
            contentAlignment = Alignment.Center,
        ) {
            if (selected) Text("✓", color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(stringResource(option.labelRes), color = Ink, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal)
            if (option.endpoint.isNotBlank()) {
                Text(option.endpoint, color = Slate, fontSize = 11.sp)
            }
        }
    }
}

@Composable
private fun DetailLine(label: String, value: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = Slate, fontSize = 12.sp, modifier = Modifier.weight(0.34f))
        Text(value, color = Ink, fontSize = 12.sp, fontWeight = FontWeight.Medium, modifier = Modifier.weight(0.66f))
    }
}

@Composable
private fun PrivacyFooter() {
    Card(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = NavyDeep),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(stringResource(R.string.footer_title), color = Sky, fontWeight = FontWeight.Bold, fontSize = 13.sp)
            Text(stringResource(R.string.footer_body), color = Color(0xFFCFE0EC), fontSize = 12.sp)
        }
    }
}

// ===========================================================================
// Shared helpers + pairing state machine (identical behaviour to the old screen).
// ===========================================================================

internal fun resolveEndpoint(serverId: String, selfHosted: String): String {
    if (serverId == "self") {
        return selfHosted.trim().takeIf { it.startsWith("http://") || it.startsWith("https://") } ?: ""
    }
    return Servers.firstOrNull { it.id == serverId }?.endpoint
        ?: Servers.first { it.id == DEFAULT_SERVER }.endpoint
}

internal fun normalizedPairCode(input: String): String =
    input
        .filter { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' }
        .uppercase(Locale.US)

internal fun shortId(id: String): String =
    if (id.length <= 16) id else "${id.take(8)}...${id.takeLast(6)}"

internal fun parsePairingResult(context: android.content.Context, json: String): PairingOutcome {
    val obj = runCatching { JSONObject(json) }.getOrElse {
        return PairingOutcome.Error(context.getString(R.string.pair_err_unreadable_response))
    }
    if (!obj.optBoolean("ok", false)) {
        return PairingOutcome.Error(obj.optString("error", context.getString(R.string.pair_err_default)))
    }
    val childId = obj.optString("child_id").takeIf { it.isNotBlank() }
    val familyId = obj.optString("family_id").takeIf { it.isNotBlank() }
    // Per-device credential minted at redeem and returned exactly once; ""
    // when pairing against an older server that doesn't mint tokens yet.
    val deviceToken = obj.optString("device_token")
    return if (childId != null && familyId != null) {
        PairingOutcome.Success(childId = childId, familyId = familyId, deviceToken = deviceToken)
    } else {
        PairingOutcome.Error(context.getString(R.string.pair_err_missing_ids))
    }
}

internal sealed interface PairingOutcome {
    data class Success(
        val childId: String,
        val familyId: String,
        /** Per-device credential from `PairResult.device_token` ("" = legacy server). */
        val deviceToken: String = "",
    ) : PairingOutcome
    data class Error(val message: String) : PairingOutcome
}

internal sealed interface PairingState {
    data object Idle : PairingState
    data object Loading : PairingState
    data class Success(val childId: String) : PairingState
    data class Error(val message: String) : PairingState
}

// ===========================================================================
// Full setup code — pairing payload v2 (docs/design/app-pairing-and-regions.md).
// The copyable string the parent console shows alongside the QR code; pasting
// it pre-fills server + pair code and (for https servers) carries the cluster
// certificate this device pins BEFORE its first connection. The certificate is
// public material — the single-use pair code inside remains the only credential.
// ===========================================================================

internal data class SetupPayload(
    val version: Int,
    val serverRegion: String,
    val serverEndpoint: String,
    val pairCode: String,
    val expiresTs: Long,
    val childName: String,
    /** Decoded cluster CA PEM text, or null when the payload carried none. */
    val clusterCaPem: String?,
    /**
     * True when the console HAS a pinned CA for this server but left it out of
     * this payload (the dense-QR fallback) — pairing must wait for the full
     * setup code rather than attempt an unpinned handshake that can only fail.
     */
    val caOmitted: Boolean,
) {
    /** Client-side expiry check so an expired code never even hits the server. */
    fun isExpired(now: Long = System.currentTimeMillis()): Boolean =
        expiresTs > 0 && now > expiresTs
}

internal sealed interface SetupPayloadResult {
    data class Parsed(val payload: SetupPayload) : SetupPayloadResult
    data class Invalid(val message: String) : SetupPayloadResult
}

/**
 * Parse a pasted setup code (the v2 JSON payload; the certificate field is
 * optional). Every failure is a calm, plain-language message — never a stack
 * trace, and nothing from the pasted text is ever echoed back.
 */
internal fun parseSetupPayload(context: android.content.Context, raw: String): SetupPayloadResult {
    val obj = runCatching { JSONObject(raw.trim()) }.getOrElse {
        return SetupPayloadResult.Invalid(context.getString(R.string.pair_err_invalid_code))
    }
    val version = obj.optInt("v", 0)
    if (version < 1) {
        return SetupPayloadResult.Invalid(context.getString(R.string.pair_err_incomplete))
    }
    val endpoint = obj.optString("server_endpoint").trim()
    if (!(endpoint.startsWith("http://") || endpoint.startsWith("https://"))) {
        return SetupPayloadResult.Invalid(context.getString(R.string.pair_err_no_server))
    }
    val pairCode = normalizedPairCode(obj.optString("pair_code"))
    if (pairCode.length < 4) {
        return SetupPayloadResult.Invalid(context.getString(R.string.pair_err_no_paircode))
    }
    val caB64 = obj.optString("cluster_ca_pem_b64").trim()
    val caPem = if (caB64.isEmpty()) {
        null
    } else {
        val decoded = runCatching { String(Base64.decode(caB64, Base64.DEFAULT), Charsets.UTF_8) }.getOrNull()
        if (decoded == null || !decoded.contains("-----BEGIN CERTIFICATE-----")) {
            return SetupPayloadResult.Invalid(context.getString(R.string.pair_err_bad_cert))
        }
        decoded
    }
    return SetupPayloadResult.Parsed(
        SetupPayload(
            version = version,
            serverRegion = obj.optString("server_region"),
            serverEndpoint = endpoint,
            pairCode = pairCode,
            expiresTs = obj.optLong("expires_ts", 0L),
            childName = obj.optString("child_name"),
            clusterCaPem = caPem,
            caOmitted = obj.optBoolean("ca_omitted", false),
        ),
    )
}
