package co.libertyware.aegis

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Divider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import co.libertyware.aegis.admin.Enrollment
import co.libertyware.aegis.vpn.AegisVpnService

/**
 * Parent-facing dashboard: enable the filtering VPN, grant the on-device OCR
 * (accessibility) permission, and (later) review alerts + the honest coverage
 * matrix served from the Rust core / home cluster.
 */
class MainActivity : ComponentActivity() {

    // VpnService.prepare() shows the system VPN-consent dialog; on OK we start.
    private val vpnConsent = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { startService(Intent(this, AegisVpnService::class.java)) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val managed = Enrollment.isProvisioned(this)
        setContent {
            MaterialTheme {
                Surface(Modifier.fillMaxSize()) {
                    Dashboard(
                        onEnableVpn = ::enableVpn,
                        onGrantOcr = ::openAccessibilitySettings,
                        managed = managed,
                    )
                }
            }
        }
    }

    companion object {
        /** Set when MainActivity is launched right after Device Owner provisioning. */
        const val EXTRA_FROM_PROVISIONING = "from_provisioning"
    }

    private fun enableVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) vpnConsent.launch(intent)        // ask consent first
        else startService(Intent(this, AegisVpnService::class.java))
    }

    private fun openAccessibilitySettings() {
        startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
    }
}

@Composable
private fun Dashboard(onEnableVpn: () -> Unit, onGrantOcr: () -> Unit, managed: Boolean = false) {
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Aegis — child-safety filter", style = MaterialTheme.typography.headlineSmall)

        if (managed) {
            Text(
                "✓ This device is managed by Aegis (Device Owner). Protection can't be " +
                    "removed without the guardian, and the guardian is alerted if it's turned off.",
                style = MaterialTheme.typography.bodyMedium,
            )
        }

        Text("1. Turn on the filtering VPN. It blocks adult content in real time and emails you " +
            "when it steps in or detects grooming signals.")
        Button(onClick = onEnableVpn) { Text("Enable filtering VPN") }

        Text("2. Grant on-screen text access so end-to-end chats (WhatsApp, Signal, Messenger) " +
            "can be checked on-device — the network can't read those.")
        Button(onClick = onGrantOcr) { Text("Grant accessibility (on-device OCR)") }

        Divider()
        Text(
            "Coverage is honest: end-to-end / pinned apps are only checked via on-device text " +
                "capture, never the network. Message content stays on the device; you only ever " +
                "receive redacted alerts.",
            style = MaterialTheme.typography.bodySmall,
        )
    }
}
