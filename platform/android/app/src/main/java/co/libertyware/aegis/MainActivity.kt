package co.libertyware.aegis

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.lightColorScheme
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
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import co.libertyware.aegis.accessibility.AegisAccessibilityService
import co.libertyware.aegis.admin.Enrollment
import co.libertyware.aegis.admin.EnrollmentRecord
import co.libertyware.aegis.core.RustBridge
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

private val Navy = Color(0xFF0F3D5C)
private val NavyDeep = Color(0xFF0A2C44)
private val Sky = Color(0xFF3AA0DC)
private val Mist = Color(0xFFF5F7F1)
private val Ink = Color(0xFF13212B)
private val Slate = Color(0xFF5B6670)
private val Good = Color(0xFF57A639)
private val Warn = Color(0xFF996D14)
private val Danger = Color(0xFFC0392B)

private val Colors = lightColorScheme(
    primary = Navy,
    onPrimary = Color.White,
    secondary = Sky,
    background = Mist,
    onBackground = Ink,
    surface = Color.White,
    onSurface = Ink,
)

private data class ServerOption(val id: String, val label: String, val endpoint: String)

private val Servers = listOf(
    ServerOption(
        "uk",
        "UK - London",
        "http://ec2-35-179-110-106.eu-west-2.compute.amazonaws.com:8443",
    ),
    ServerOption("us", "US cloud", "https://us.cloud.phbulwark.app"),
    ServerOption("self", "Self-hosted", ""),
)

private const val PREFS = "ph_bulwark"
private const val KEY_SERVER = "server_id"
private const val KEY_SELF_HOSTED = "self_hosted_endpoint"
private const val DEFAULT_SERVER = "uk"

class MainActivity : ComponentActivity() {
    private var ocrOn by mutableStateOf(false)
    private var managed by mutableStateOf(false)
    private var enrollment by mutableStateOf<EnrollmentRecord?>(null)

    override fun onResume() {
        super.onResume()
        refreshLocalState()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        refreshLocalState()
        setContent {
            MaterialTheme(colorScheme = Colors) {
                Surface(Modifier.fillMaxSize(), color = Mist) {
                    Dashboard(
                        ocrOn = ocrOn,
                        managed = managed,
                        enrollment = enrollment,
                        deviceId = Enrollment.stableDeviceId(this),
                        savedServer = prefs().getString(KEY_SERVER, DEFAULT_SERVER) ?: DEFAULT_SERVER,
                        savedSelfHosted = prefs().getString(KEY_SELF_HOSTED, "") ?: "",
                        onSaveServer = { server, selfHosted ->
                            prefs().edit()
                                .putString(KEY_SERVER, server)
                                .putString(KEY_SELF_HOSTED, selfHosted.trim())
                                .apply()
                        },
                        onSaveEnrollment = { familyId, childId, endpoint, deviceId ->
                            Enrollment.savePairing(
                                this,
                                familyId = familyId,
                                childId = childId,
                                clusterEndpoint = endpoint,
                                deviceId = deviceId,
                            )
                            refreshLocalState()
                        },
                        onGrantOcr = {
                            startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
                        },
                    )
                }
            }
        }
    }

    private fun refreshLocalState() {
        ocrOn = isAccessibilityEnabled()
        managed = Enrollment.isProvisioned(this)
        enrollment = Enrollment.record(this)
    }

    private fun prefs() = getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun isAccessibilityEnabled(): Boolean {
        val flat = Settings.Secure.getString(
            contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
        ) ?: return false
        val svc = "${packageName}/${AegisAccessibilityService::class.java.name}"
        return flat.split(':').any { it.equals(svc, ignoreCase = true) }
    }

    companion object {
        const val EXTRA_FROM_PROVISIONING = "from_provisioning"
    }
}

@Composable
private fun Dashboard(
    ocrOn: Boolean,
    managed: Boolean,
    enrollment: EnrollmentRecord?,
    deviceId: String,
    savedServer: String,
    savedSelfHosted: String,
    onSaveServer: (String, String) -> Unit,
    onSaveEnrollment: (String, String, String, String) -> Unit,
    onGrantOcr: () -> Unit,
) {
    var selectedServer by remember(savedServer) { mutableStateOf(savedServer.ifBlank { DEFAULT_SERVER }) }
    var selfHosted by remember(savedSelfHosted) { mutableStateOf(savedSelfHosted) }
    val endpoint = resolveEndpoint(selectedServer, selfHosted)

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Header()
        EnrollmentStatusCard(enrollment = enrollment, managed = managed, deviceId = deviceId)
        ServerCard(
            selected = selectedServer,
            selfHosted = selfHosted,
            onPick = { id ->
                selectedServer = id
                onSaveServer(id, selfHosted)
            },
            onSelfHostedChange = { url ->
                selfHosted = url
                onSaveServer(selectedServer, url)
            },
        )
        PairCodeCard(
            endpoint = endpoint,
            deviceId = deviceId,
            onEnrollment = onSaveEnrollment,
        )
        StatusCard(
            title = "On-device chat safety",
            body = "E2E and pinned chats are checked locally with redacted alerts only.",
            active = ocrOn,
            cta = if (ocrOn) "Open accessibility settings" else "Turn on protection",
            onClick = onGrantOcr,
        )
        VpnStatusCard()
        PrivacyNote()
    }
}

@Composable
private fun Header() {
    Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Box(Modifier.size(84.dp).clip(CircleShape).background(Navy), contentAlignment = Alignment.Center) {
            Image(
                painter = painterResource(R.drawable.ic_shield_foreground),
                contentDescription = "PH Bulwark shield",
                modifier = Modifier.size(84.dp),
                colorFilter = ColorFilter.tint(Color.White),
            )
        }
        Text("PH Bulwark", color = Navy, fontSize = 28.sp, fontWeight = FontWeight.ExtraBold)
        Text("Child device setup", color = Slate, fontSize = 13.sp, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun EnrollmentStatusCard(enrollment: EnrollmentRecord?, managed: Boolean, deviceId: String) {
    val paired = enrollment != null
    val bg = if (paired) Color(0xFFE7F4EE) else Color.White
    val fg = if (paired) Good else Ink
    Card(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = bg),
        elevation = CardDefaults.cardElevation(1.dp),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (paired) "Paired to parent app" else "Not paired",
                    color = fg,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f),
                )
                StatusPill(if (paired) "Ready" else "Setup", paired)
            }
            if (enrollment != null) {
                DetailLine("Server", enrollment.clusterEndpoint)
                DetailLine("Child", shortId(enrollment.childId))
                DetailLine("Device", shortId(enrollment.deviceId))
            } else {
                DetailLine("Device", shortId(deviceId))
            }
            if (managed) {
                DetailLine("Management", "Device Owner lockdown active")
            }
        }
    }
}

@Composable
private fun ServerCard(
    selected: String,
    selfHosted: String,
    onPick: (String) -> Unit,
    onSelfHostedChange: (String) -> Unit,
) {
    Card(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(1.dp),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Server", color = Ink, fontSize = 18.sp, fontWeight = FontWeight.Bold)
            Servers.forEach { opt ->
                ServerRow(option = opt, selected = selected == opt.id, onClick = { onPick(opt.id) })
            }
            if (selected == "self") {
                OutlinedTextField(
                    value = selfHosted,
                    onValueChange = onSelfHostedChange,
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
}

@Composable
private fun ServerRow(option: ServerOption, selected: Boolean, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
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
        Spacer(Modifier.size(12.dp))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(option.label, color = Ink, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal)
            if (option.endpoint.isNotBlank()) {
                Text(option.endpoint, color = Slate, fontSize = 11.sp)
            }
        }
    }
}

@Composable
private fun PairCodeCard(
    endpoint: String,
    deviceId: String,
    onEnrollment: (String, String, String, String) -> Unit,
) {
    var code by remember { mutableStateOf("") }
    var state by remember { mutableStateOf<PairingState>(PairingState.Idle) }
    val scope = rememberCoroutineScope()
    val normalizedCode = normalizedPairCode(code)
    val endpointReady = endpoint.isNotBlank()
    val loading = state is PairingState.Loading

    Card(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(1.dp),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Pair code", color = Ink, fontSize = 18.sp, fontWeight = FontWeight.Bold)
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
            Button(
                onClick = {
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
                },
                enabled = endpointReady && normalizedCode.length >= 4 && !loading,
                modifier = Modifier.fillMaxWidth().height(48.dp),
                shape = RoundedCornerShape(8.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Navy, contentColor = Color.White),
            ) {
                if (loading) {
                    CircularProgressIndicator(Modifier.size(18.dp), color = Color.White, strokeWidth = 2.dp)
                } else {
                    Text("Pair this device", fontWeight = FontWeight.SemiBold)
                }
            }
            when (val current = state) {
                PairingState.Idle -> {
                    if (!endpointReady) Text("Enter a self-hosted URL first.", color = Warn, fontSize = 13.sp)
                }
                PairingState.Loading -> Text("Contacting selected server...", color = Slate, fontSize = 13.sp)
                is PairingState.Success -> Text("Paired. Child ${shortId(current.childId)} is ready.", color = Good, fontSize = 13.sp)
                is PairingState.Error -> Text(current.message, color = Danger, fontSize = 13.sp)
            }
        }
    }
}

@Composable
private fun StatusCard(
    title: String,
    body: String,
    active: Boolean,
    cta: String,
    onClick: () -> Unit,
) {
    Card(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(1.dp),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(title, color = Ink, fontSize = 18.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                StatusPill(if (active) "On" else "Off", active)
            }
            Text(body, color = Slate, style = MaterialTheme.typography.bodyMedium)
            Button(
                onClick = onClick,
                modifier = Modifier.fillMaxWidth().height(48.dp),
                shape = RoundedCornerShape(8.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (active) Sky else Navy,
                    contentColor = Color.White,
                ),
            ) {
                Text(cta, fontWeight = FontWeight.SemiBold)
            }
        }
    }
}

@Composable
private fun VpnStatusCard() {
    Card(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFFFFF6E6)),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Network filtering VPN", color = Warn, fontWeight = FontWeight.Bold, fontSize = 16.sp)
            Text("In development for Android. On-device chat safety can run now.", color = Slate)
        }
    }
}

@Composable
private fun PrivacyNote() {
    Card(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = NavyDeep),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Private by design", color = Sky, fontWeight = FontWeight.Bold, fontSize = 13.sp)
            Text("Only redacted safety alerts leave this device.", color = Color(0xFFCFE0EC), fontSize = 12.sp)
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
private fun StatusPill(text: String, active: Boolean) {
    val bg = if (active) Color(0xFFE7F4EE) else Color(0xFFFDECEC)
    val fg = if (active) Good else Danger
    Box(Modifier.clip(RoundedCornerShape(50)).background(bg).padding(horizontal = 10.dp, vertical = 4.dp)) {
        Text(text, color = fg, fontSize = 12.sp, fontWeight = FontWeight.Bold)
    }
}

private fun resolveEndpoint(serverId: String, selfHosted: String): String {
    if (serverId == "self") {
        return selfHosted.trim().takeIf { it.startsWith("http://") || it.startsWith("https://") }
            ?: ""
    }
    return Servers.firstOrNull { it.id == serverId }?.endpoint
        ?: Servers.first { it.id == DEFAULT_SERVER }.endpoint
}

private fun normalizedPairCode(input: String): String =
    input
        .filter { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' }
        .uppercase(Locale.US)

private fun shortId(id: String): String =
    if (id.length <= 16) id else "${id.take(8)}...${id.takeLast(6)}"

private fun parsePairingResult(json: String): PairingOutcome {
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

private sealed interface PairingOutcome {
    data class Success(val childId: String, val familyId: String) : PairingOutcome
    data class Error(val message: String) : PairingOutcome
}

private sealed interface PairingState {
    data object Idle : PairingState
    data object Loading : PairingState
    data class Success(val childId: String) : PairingState
    data class Error(val message: String) : PairingState
}
