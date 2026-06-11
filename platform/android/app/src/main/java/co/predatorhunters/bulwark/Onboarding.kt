package co.predatorhunters.bulwark

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.SizeTransform
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import co.predatorhunters.bulwark.admin.EnrollmentRecord
import co.predatorhunters.bulwark.core.RustBridge
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
internal data class ServerOption(val id: String, val label: String, val endpoint: String)

internal val Servers = listOf(
    ServerOption(
        "uk",
        "UK - London",
        "http://ec2-35-179-110-106.eu-west-2.compute.amazonaws.com:8443",
    ),
    ServerOption("us", "US cloud", "https://us.cloud.phbulwark.app"),
    ServerOption("self", "Self-hosted", ""),
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
) {
    val vpnReady: Boolean get() = vpnConsented || vpnRunning
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
    onSaveEnrollment: (String, String, String, String) -> Unit,
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
                "Step ${progressIndex + 1} of ${ProgressSteps.size}",
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
        primaryLabel = "Get started",
        onPrimary = onNext,
    ) {
        Image(
            painter = painterResource(R.drawable.bulwark_logo),
            contentDescription = "PH Bulwark Shield",
            modifier = Modifier
                .size(112.dp)
                .clip(RoundedCornerShape(24.dp)),
        )
        Spacer(Modifier.height(24.dp))
        Text(
            "Welcome to PH Bulwark",
            color = Navy,
            fontSize = 30.sp,
            fontWeight = FontWeight.ExtraBold,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        Text(
            "A calmer way to keep this device safe. We'll guide you through setup — it takes about two minutes.",
            color = Slate,
            fontSize = 16.sp,
            fontWeight = FontWeight.Medium,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(20.dp))
        TrustChip("Private by design")
    }
}

@Composable
private fun TransparencyStep(onBack: () -> Unit, onNext: () -> Unit) {
    StepScaffold(
        primaryLabel = "I understand",
        onPrimary = onNext,
        secondaryLabel = "Back",
        onSecondary = onBack,
    ) {
        StepIcon("🛡️")
        Spacer(Modifier.height(20.dp))
        Text(
            "What PH Bulwark does",
            color = Navy,
            fontSize = 26.sp,
            fontWeight = FontWeight.ExtraBold,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        Text(
            "It checks content on this device for safety and flags signs of grooming or harmful material.",
            color = Ink,
            fontSize = 16.sp,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(18.dp))
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            PromiseRow("This is not spying. Messages are checked on the device itself.")
            PromiseRow("Only redacted safety alerts ever leave this device — never the words.")
            PromiseRow("Protection is always visible. It is never hidden, and can be turned off anytime.")
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
        title = "On-device chat safety",
        body = "Lets PH Bulwark read the text already shown on screen in messaging apps, so it can spot grooming even in end-to-end-encrypted chats.",
        whyLine = "Why we need this: encrypted chats can only be checked where they are read — right here on the device.",
        granted = granted,
        grantedLabel = "Chat safety is on",
        actionLabel = "Turn on chat safety",
        reGrantLabel = "Open accessibility settings",
        trust = "Nothing you type is sent anywhere. Checks happen on-device.",
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
        title = "Network filtering",
        body = "A private on-device filter checks web and app traffic for unsafe content and blocks it before it loads.",
        whyLine = "Why we need this: Android routes traffic through a local VPN so the filter can see and stop harmful content.",
        granted = ready,
        grantedLabel = if (running) "Filtering is active" else "Filtering is ready",
        actionLabel = "Turn on filtering",
        reGrantLabel = "Re-check filtering",
        trust = "The filter runs on this device. Browsing is not logged or sent away.",
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
        primaryLabel = "Continue",
        onPrimary = onNext,
        secondaryLabel = "Back",
        onSecondary = onBack,
    ) {
        StepIcon("🔒")
        Spacer(Modifier.height(18.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "Anti-removal",
                color = Navy,
                fontSize = 26.sp,
                fontWeight = FontWeight.ExtraBold,
            )
            Spacer(Modifier.width(10.dp))
            OptionalPill()
        }
        Spacer(Modifier.height(12.dp))
        Text(
            "Optional. Helps protection stay on by making PH Bulwark harder to remove or switch off by accident.",
            color = Ink,
            fontSize = 16.sp,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(8.dp))
        Text(
            "This is usually set up by the parent app on a managed device. You can safely skip it for now.",
            color = Slate,
            fontSize = 14.sp,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(20.dp))
        StatusLine(active = enabled, on = "Anti-removal is active", off = "Managed by the parent app")
        if (!enabled) {
            Spacer(Modifier.height(16.dp))
            OutlinedButton(
                onClick = onGrant,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                shape = RoundedCornerShape(12.dp),
            ) {
                Text("Enable device admin (advanced)", color = Navy, fontWeight = FontWeight.SemiBold)
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
    onEnrollment: (String, String, String, String) -> Unit,
    onBack: () -> Unit,
    onNext: () -> Unit,
) {
    var selectedServer by remember(savedServer) { mutableStateOf(savedServer.ifBlank { DEFAULT_SERVER }) }
    var selfHosted by remember(savedSelfHosted) { mutableStateOf(savedSelfHosted) }
    var code by remember { mutableStateOf("") }
    var state by remember {
        mutableStateOf<PairingState>(if (alreadyPaired) PairingState.Success("") else PairingState.Idle)
    }
    val scope = rememberCoroutineScope()

    val endpoint = resolveEndpoint(selectedServer, selfHosted)
    val normalizedCode = normalizedPairCode(code)
    val endpointReady = endpoint.isNotBlank()
    val loading = state is PairingState.Loading
    val paired = alreadyPaired || state is PairingState.Success

    StepScaffold(
        primaryLabel = if (paired) "Continue" else "Pair this device",
        onPrimary = {
            if (paired) {
                onNext()
            } else {
                state = PairingState.Loading
                scope.launch {
                    val outcome = withContext(Dispatchers.IO) {
                        runCatching {
                            RustBridge.ensureLoaded()
                            parsePairingResult(
                                RustBridge.redeemPairCode(endpoint, normalizedCode, deviceId),
                            )
                        }.getOrElse {
                            PairingOutcome.Error(
                                "Enrollment bridge unavailable: ${it.message ?: it.javaClass.simpleName}",
                            )
                        }
                    }
                    state = when (outcome) {
                        is PairingOutcome.Success -> {
                            onEnrollment(outcome.familyId, outcome.childId, endpoint, deviceId)
                            PairingState.Success(outcome.childId)
                        }
                        is PairingOutcome.Error -> PairingState.Error(outcome.message)
                    }
                }
            }
        },
        primaryEnabled = paired || (endpointReady && normalizedCode.length >= 4 && !loading),
        primaryLoading = loading,
        secondaryLabel = "Back",
        onSecondary = onBack,
    ) {
        StepIcon("🔗")
        Spacer(Modifier.height(16.dp))
        Text(
            if (paired) "Paired with the parent app" else "Pair with the parent app",
            color = Navy,
            fontSize = 26.sp,
            fontWeight = FontWeight.ExtraBold,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(10.dp))
        Text(
            if (paired) {
                "This device is linked to your family. Alerts will reach the guardian."
            } else {
                "Pick your server, then enter the short code shown in the parent app."
            },
            color = Slate,
            fontSize = 15.sp,
            textAlign = TextAlign.Center,
        )

        if (!paired) {
            Spacer(Modifier.height(20.dp))
            Card(
                Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                elevation = CardDefaults.cardElevation(1.dp),
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("Server", color = Ink, fontSize = 15.sp, fontWeight = FontWeight.Bold)
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
                            label = { Text("Self-hosted URL") },
                            placeholder = { Text("https://your-server:8443") },
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
                label = { Text("Code from parent app") },
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.Characters,
                    keyboardType = KeyboardType.Ascii,
                    imeAction = ImeAction.Done,
                ),
            )
            Spacer(Modifier.height(8.dp))
            when (val current = state) {
                PairingState.Idle ->
                    if (!endpointReady) Text("Enter a self-hosted URL first.", color = Warn, fontSize = 13.sp)
                PairingState.Loading ->
                    Text("Contacting selected server...", color = Slate, fontSize = 13.sp)
                is PairingState.Success ->
                    Text("Paired. This device is ready.", color = Good, fontSize = 13.sp)
                is PairingState.Error ->
                    Text(current.message, color = Danger, fontSize = 13.sp)
            }
        } else {
            Spacer(Modifier.height(20.dp))
            StatusLine(active = true, on = "This device is paired", off = "")
        }
    }
}

@Composable
private fun DoneStep(state: SetupState, onFinish: () -> Unit) {
    StepScaffold(
        primaryLabel = "Go to dashboard",
        onPrimary = onFinish,
    ) {
        Box(
            Modifier
                .size(96.dp)
                .clip(CircleShape)
                .background(Color(0xFFE7F4EE)),
            contentAlignment = Alignment.Center,
        ) {
            Text("✓", color = Good, fontSize = 48.sp, fontWeight = FontWeight.ExtraBold)
        }
        Spacer(Modifier.height(24.dp))
        Text(
            "Protection is active",
            color = Navy,
            fontSize = 28.sp,
            fontWeight = FontWeight.ExtraBold,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(10.dp))
        Text(
            "This device is set up and watching for harmful content. You're all done.",
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
                SummaryRow("Paired with parent app", state.paired)
                SummaryRow("Chat safety on", state.accessibilityOn)
                SummaryRow("Network filtering on", state.vpnReady)
                SummaryRow("Anti-removal", state.antiRemovalOn, optionalWhenOff = true)
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
) {
    Column(
        Modifier
            .fillMaxSize()
            .background(Mist)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Image(
            painter = painterResource(R.drawable.bulwark_logo),
            contentDescription = "PH Bulwark Shield",
            modifier = Modifier
                .size(72.dp)
                .clip(RoundedCornerShape(16.dp)),
        )
        Text("PH Bulwark Shield", color = Navy, fontSize = 22.sp, fontWeight = FontWeight.ExtraBold)
        val allOn = isFullySetUp(state)
        Text(
            if (allOn) "Protection is active" else "Protection needs attention",
            color = if (allOn) Good else Warn,
            fontSize = 14.sp,
            fontWeight = FontWeight.SemiBold,
        )

        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White),
            elevation = CardDefaults.cardElevation(1.dp),
        ) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Status", color = Ink, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                SummaryRow("Paired with parent app", state.paired)
                SummaryRow("Chat safety on", state.accessibilityOn)
                SummaryRow("Network filtering on", state.vpnReady)
                SummaryRow("Anti-removal", state.antiRemovalOn, optionalWhenOff = true)
            }
        }

        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White),
            elevation = CardDefaults.cardElevation(1.dp),
        ) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("This device", color = Ink, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                if (enrollment != null) {
                    DetailLine("Server", enrollment.clusterEndpoint)
                    DetailLine("Child", shortId(enrollment.childId))
                    DetailLine("Device", shortId(enrollment.deviceId))
                    if (enrollment.deviceOwnerProvisioned) {
                        DetailLine("Management", "Device Owner lockdown active")
                    }
                } else {
                    DetailLine("Device", shortId(deviceId))
                }
            }
        }

        if (!state.accessibilityOn) {
            DashboardAction("Turn on chat safety", onOpenAccessibility)
        }
        if (!state.vpnReady) {
            DashboardAction("Turn on network filtering", onStartVpn)
        }

        OutlinedButton(
            onClick = onReconfigure,
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            shape = RoundedCornerShape(12.dp),
        ) {
            Text("Review setup", color = Navy, fontWeight = FontWeight.SemiBold)
        }

        PrivacyFooter()
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
        primaryLabel = if (granted) "Continue" else actionLabel,
        onPrimary = { if (granted) onNext() else onGrant() },
        secondaryLabel = "Back",
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
        StatusLine(active = granted, on = grantedLabel, off = "Not turned on yet")
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
            val active = current >= 0 && i <= current
            val widthDp by animateFloatAsState(
                targetValue = if (i == current) 28f else 9f,
                animationSpec = tween(280),
                label = "dot$i",
            )
            Box(
                Modifier
                    .height(9.dp)
                    .width(widthDp.dp)
                    .clip(RoundedCornerShape(50))
                    .background(if (active) Sky else Color(0xFFD3DEE7)),
            )
        }
    }
}

@Composable
private fun StepIcon(emoji: String) {
    Box(
        Modifier
            .size(84.dp)
            .clip(CircleShape)
            .background(Color(0xFFEAF1F6)),
        contentAlignment = Alignment.Center,
    ) {
        Text(emoji, fontSize = 40.sp)
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
            when {
                active -> "On"
                optionalWhenOff -> "Optional"
                else -> "Off"
            },
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
        Text("Optional", color = Slate, fontSize = 11.sp, fontWeight = FontWeight.Bold)
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
            Text(option.label, color = Ink, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal)
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
            Text("Private by design", color = Sky, fontWeight = FontWeight.Bold, fontSize = 13.sp)
            Text("Only redacted safety alerts leave this device.", color = Color(0xFFCFE0EC), fontSize = 12.sp)
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

internal fun parsePairingResult(json: String): PairingOutcome {
    val obj = runCatching { JSONObject(json) }.getOrElse {
        return PairingOutcome.Error("Enrollment returned an unreadable response")
    }
    if (!obj.optBoolean("ok", false)) {
        return PairingOutcome.Error(obj.optString("error", "Enrollment failed"))
    }
    val childId = obj.optString("child_id").takeIf { it.isNotBlank() }
    val familyId = obj.optString("family_id").takeIf { it.isNotBlank() }
    return if (childId != null && familyId != null) {
        PairingOutcome.Success(childId = childId, familyId = familyId)
    } else {
        PairingOutcome.Error("Enrollment response was missing account ids")
    }
}

internal sealed interface PairingOutcome {
    data class Success(val childId: String, val familyId: String) : PairingOutcome
    data class Error(val message: String) : PairingOutcome
}

internal sealed interface PairingState {
    data object Idle : PairingState
    data object Loading : PairingState
    data class Success(val childId: String) : PairingState
    data class Error(val message: String) : PairingState
}
