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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import co.libertyware.aegis.accessibility.AegisAccessibilityService
import co.libertyware.aegis.admin.Enrollment

// --- PH Bulwark brand palette (matches res/values/ic_launcher_background.xml #0F3D5C) ---
private val Navy = Color(0xFF0F3D5C)
private val NavyDeep = Color(0xFF0A2C44)
private val Sky = Color(0xFF3AA0DC)
private val Mist = Color(0xFFEDF3F8)
private val Ink = Color(0xFF13212B)
private val Slate = Color(0xFF5B6B77)
private val Good = Color(0xFF1B8A5A)
private val Warn = Color(0xFFB8860B)

private val Colors = lightColorScheme(
    primary = Navy, onPrimary = Color.White, secondary = Sky,
    background = Mist, onBackground = Ink, surface = Color.White, onSurface = Ink,
)

// Server choices (mirror the parent console's CLOUD_REGIONS).
private data class ServerOption(val id: String, val label: String, val endpoint: String)
private val SERVERS = listOf(
    ServerOption("uk", "PH Bulwark Cloud — UK (London)", "https://uk.cloud.phbulwark.app"),
    ServerOption("us", "PH Bulwark Cloud — US", "https://us.cloud.phbulwark.app"),
    ServerOption("self", "Self-hosted (enter in setup)", ""),
)
private const val PREFS = "ph_bulwark"
private const val KEY_SERVER = "server_id"

class MainActivity : ComponentActivity() {

    private var ocrOn by mutableStateOf(false)

    override fun onResume() {
        super.onResume()
        ocrOn = isAccessibilityEnabled()   // refresh status when returning from Settings
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ocrOn = isAccessibilityEnabled()
        val managed = Enrollment.isProvisioned(this)
        setContent {
            MaterialTheme(colorScheme = Colors) {
                Surface(Modifier.fillMaxSize(), color = Mist) {
                    Dashboard(
                        ocrOn = ocrOn,
                        managed = managed,
                        onGrantOcr = { startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) },
                        savedServer = getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_SERVER, "uk")!!,
                        onPickServer = { id ->
                            getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY_SERVER, id).apply()
                        },
                    )
                }
            }
        }
    }

    private fun isAccessibilityEnabled(): Boolean {
        val flat = Settings.Secure.getString(contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: return false
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
    onGrantOcr: () -> Unit,
    savedServer: String,
    onPickServer: (String) -> Unit,
) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Header()
        if (managed) ManagedBadge()

        // The working protection today.
        StatusCard(
            step = "1",
            title = "On-device chat safety",
            body = "Checks end-to-end chats (WhatsApp, Signal, Messenger) on the device for grooming + adult content. This is the protection that's live today.",
            active = ocrOn,
            cta = if (ocrOn) "Open accessibility settings" else "Turn on protection",
            onClick = onGrantOcr,
        )

        ServerCard(savedServer, onPickServer)

        // Honest about the filtering VPN (forwarding engine not shipped → would blackhole).
        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFFFFF6E6)),
        ) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Network filtering VPN — in development", color = Warn, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                Text(
                    "The transparent VPN filter isn't ready yet — enabling it now would cut the device's internet. Use on-device protection above for now; we'll switch this on once the forwarding engine ships.",
                    color = Slate, style = MaterialTheme.typography.bodyMedium,
                )
            }
        }

        PrivacyNote()
    }
}

@Composable
private fun Header() {
    Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Box(Modifier.size(96.dp).clip(CircleShape).background(Navy), contentAlignment = Alignment.Center) {
            Image(
                painter = painterResource(R.drawable.ic_shield_foreground),
                contentDescription = "PH Bulwark shield",
                modifier = Modifier.size(96.dp),
                colorFilter = ColorFilter.tint(Color.White),
            )
        }
        Text("PH Bulwark", color = Navy, fontSize = 30.sp, fontWeight = FontWeight.ExtraBold)
        Text("CHILD SAFETY · BY PREDATOR HUNTERS", color = Slate, fontSize = 11.sp, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun ManagedBadge() {
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(14.dp), colors = CardDefaults.cardColors(containerColor = Color(0xFFE7F4EE))) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Text("🛡️", fontSize = 22.sp); Spacer(Modifier.size(12.dp))
            Text("Protected device — PH Bulwark can't be removed without you, and you're alerted if it's turned off.",
                color = Good, fontWeight = FontWeight.Medium, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun StatusCard(step: String, title: String, body: String, active: Boolean, cta: String, onClick: () -> Unit) {
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(18.dp), colors = CardDefaults.cardColors(containerColor = Color.White), elevation = CardDefaults.cardElevation(2.dp)) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(34.dp).clip(CircleShape).background(Mist), contentAlignment = Alignment.Center) { Text(step, color = Navy, fontWeight = FontWeight.Bold) }
                Spacer(Modifier.size(12.dp))
                Text(title, color = Ink, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.fillMaxWidth().weight(1f))
                StatusPill(active)
            }
            Text(body, color = Slate, style = MaterialTheme.typography.bodyMedium)
            Button(onClick = onClick, modifier = Modifier.fillMaxWidth().height(48.dp), shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = if (active) Sky else Navy, contentColor = Color.White)) {
                Text(cta, fontWeight = FontWeight.SemiBold)
            }
        }
    }
}

@Composable
private fun StatusPill(active: Boolean) {
    val bg = if (active) Color(0xFFE7F4EE) else Color(0xFFFDECEC)
    val fg = if (active) Good else Color(0xFFC0392B)
    Box(Modifier.clip(RoundedCornerShape(50)).background(bg).padding(horizontal = 10.dp, vertical = 4.dp)) {
        Text(if (active) "● Active" else "● Off", color = fg, fontSize = 12.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun ServerCard(saved: String, onPick: (String) -> Unit) {
    var sel by remember { mutableStateOf(saved) }
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(18.dp), colors = CardDefaults.cardColors(containerColor = Color.White), elevation = CardDefaults.cardElevation(2.dp)) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Server / country", color = Ink, fontSize = 18.sp, fontWeight = FontWeight.Bold)
            Text("Where your child's data is routed + analysed. UK keeps data in London.", color = Slate, style = MaterialTheme.typography.bodySmall)
            SERVERS.forEach { opt ->
                Row(
                    Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp))
                        .background(if (sel == opt.id) Mist else Color.White)
                        .clickable { sel = opt.id; onPick(opt.id) }
                        .padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Box(Modifier.size(20.dp).clip(CircleShape).background(if (sel == opt.id) Navy else Color(0xFFD3DEE7)), contentAlignment = Alignment.Center) {
                        if (sel == opt.id) Text("✓", color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                    Spacer(Modifier.size(12.dp))
                    Text(opt.label, color = Ink, style = MaterialTheme.typography.bodyMedium, fontWeight = if (sel == opt.id) FontWeight.SemiBold else FontWeight.Normal)
                }
            }
        }
    }
}

@Composable
private fun PrivacyNote() {
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(14.dp), colors = CardDefaults.cardColors(containerColor = NavyDeep)) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Private by design", color = Sky, fontWeight = FontWeight.Bold, fontSize = 13.sp)
            Text("Message content is analysed on the device and never leaves it — you only ever receive redacted alerts. End-to-end + pinned apps are checked only by on-device text, never the network.",
                color = Color(0xFFCFE0EC), fontSize = 12.sp, style = MaterialTheme.typography.bodySmall)
        }
    }
}
