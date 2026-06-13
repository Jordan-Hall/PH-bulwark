package co.predatorhunters.bulwark

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import co.predatorhunters.bulwark.admin.Enrollment
import co.predatorhunters.bulwark.core.RustBridge
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

// ---------------------------------------------------------------------------
// Child SOS — the "I need help right now" action on the status dashboard.
//
// Hard-to-mis-trigger by design: TWO deliberate taps (SOS → an explicit
// "Yes — send" confirm), with a visible Cancel. Honest by design: the server
// ack says whether a guardian path actually took the alert; when none did, the
// child is told to call 999 or a trusted adult instead of being falsely
// reassured. CONTENT-FREE: the SOS carries this device's identity + the time —
// no location, no messages, no media.
// ---------------------------------------------------------------------------

internal sealed interface SosStage {
    data object Idle : SosStage
    data object Confirm : SosStage
    data object Sending : SosStage
    data class Sent(val delivered: Boolean) : SosStage
    data class Failed(val message: String) : SosStage
}

internal sealed interface SosOutcome {
    data class Sent(val delivered: Boolean) : SosOutcome
    data class Failed(val message: String) : SosOutcome
}

private const val SOS_FALLBACK_ADVICE =
    "If you are in danger, call 999 or tell a trusted adult."

internal fun parseSosResult(json: String): SosOutcome {
    val obj = runCatching { JSONObject(json) }.getOrElse {
        return SosOutcome.Failed("The SOS reply couldn't be read. $SOS_FALLBACK_ADVICE")
    }
    return if (obj.optBoolean("ok", false)) {
        SosOutcome.Sent(delivered = obj.optBoolean("delivered", false))
    } else {
        SosOutcome.Failed(
            obj.optString("error", "Couldn't send the SOS right now.") +
                " " + SOS_FALLBACK_ADVICE,
        )
    }
}

/** Network round-trip — call from a background dispatcher only. */
internal fun sendSos(ctx: Context): SosOutcome {
    val enrollment = Enrollment.record(ctx)
        ?: return SosOutcome.Failed(
            "This device isn't paired with a guardian yet. $SOS_FALLBACK_ADVICE",
        )
    return runCatching {
        RustBridge.ensureLoaded()
        parseSosResult(
            RustBridge.raiseSos(
                enrollment.clusterEndpoint,
                enrollment.deviceId,
                RustBridge.clusterCaPath(ctx),
                enrollment.deviceToken,
            ),
        )
    }.getOrElse {
        SosOutcome.Failed("Couldn't send the SOS right now. $SOS_FALLBACK_ADVICE")
    }
}

@Composable
internal fun SosCard() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var stage by remember { mutableStateOf<SosStage>(SosStage.Idle) }

    val fire: () -> Unit = {
        stage = SosStage.Sending
        scope.launch {
            val outcome = withContext(Dispatchers.IO) { sendSos(ctx) }
            stage = when (outcome) {
                is SosOutcome.Sent -> SosStage.Sent(outcome.delivered)
                is SosOutcome.Failed -> SosStage.Failed(outcome.message)
            }
        }
    }

    Card(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(1.dp),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Need help right now?", color = Ink, fontSize = 16.sp, fontWeight = FontWeight.Bold)
            when (val s = stage) {
                SosStage.Idle -> {
                    Text(
                        "SOS sends an urgent alert to your guardian with this device's name and the time. Nothing else is shared.",
                        color = Slate,
                        fontSize = 13.sp,
                    )
                    Button(
                        onClick = { stage = SosStage.Confirm },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(56.dp),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Danger, contentColor = Color.White),
                    ) {
                        Text("SOS — alert my guardian", fontWeight = FontWeight.ExtraBold, fontSize = 16.sp)
                    }
                }
                SosStage.Confirm -> {
                    Text(
                        "Send the SOS now? Your guardian will be alerted right away.",
                        color = Ink,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Medium,
                    )
                    Button(
                        onClick = fire,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(56.dp),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Danger, contentColor = Color.White),
                    ) {
                        Text("Yes — send the SOS now", fontWeight = FontWeight.ExtraBold, fontSize = 16.sp)
                    }
                    OutlinedButton(
                        onClick = { stage = SosStage.Idle },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(44.dp),
                        shape = RoundedCornerShape(12.dp),
                    ) {
                        Text("Cancel", color = Slate, fontWeight = FontWeight.Medium)
                    }
                }
                SosStage.Sending -> {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(Modifier.size(18.dp), color = Danger, strokeWidth = 2.dp)
                        Spacer(Modifier.width(10.dp))
                        Text("Sending your SOS…", color = Ink, fontSize = 14.sp, fontWeight = FontWeight.Medium)
                    }
                }
                is SosStage.Sent -> {
                    Text(
                        if (s.delivered) {
                            "✓ Your guardian has been alerted."
                        } else {
                            "✓ SOS sent — but no guardian app is connected right now. $SOS_FALLBACK_ADVICE"
                        },
                        color = if (s.delivered) Good else Warn,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold,
                    )
                    OutlinedButton(
                        onClick = { stage = SosStage.Idle },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(44.dp),
                        shape = RoundedCornerShape(12.dp),
                    ) {
                        Text("Done", color = Slate, fontWeight = FontWeight.Medium)
                    }
                }
                is SosStage.Failed -> {
                    Text(s.message, color = Danger, fontSize = 13.sp, fontWeight = FontWeight.Medium)
                    Button(
                        onClick = fire,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(50.dp),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Danger, contentColor = Color.White),
                    ) {
                        Text("Try again", fontWeight = FontWeight.Bold)
                    }
                    OutlinedButton(
                        onClick = { stage = SosStage.Idle },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(44.dp),
                        shape = RoundedCornerShape(12.dp),
                    ) {
                        Text("Cancel", color = Slate, fontWeight = FontWeight.Medium)
                    }
                }
            }
        }
    }
}
