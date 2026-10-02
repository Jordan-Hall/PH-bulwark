package co.predatorhunters.bulwark

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import co.predatorhunters.bulwark.admin.EnrollmentRecord

private val DashboardBlue = Color(0xFF174F70)
private val DashboardBlueDeep = Color(0xFF082D45)
private val DashboardSky = Color(0xFF42A9DD)
private val DashboardMint = Color(0xFFE8F6ED)
private val DashboardAmber = Color(0xFFFFF3D8)
private val DashboardSurface = Color(0xFFFBFCFD)
private val DashboardOutline = Color(0xFFE3E9ED)

@Composable
internal fun PremiumStatusDashboard(
    state: SetupState,
    enrollment: EnrollmentRecord?,
    deviceId: String,
    onOpenAccessibility: () -> Unit,
    onStartVpn: () -> Unit,
    onReconfigure: () -> Unit,
    onOpenBrowser: () -> Unit,
    canProvisionManaged: Boolean,
    onProvisionManaged: () -> Unit,
) {
    val context = LocalContext.current
    val active = state.protectionActive
    val pageBackground by animateColorAsState(
        targetValue = if (active) Color(0xFFF2F8F4) else Mist,
        animationSpec = tween(350),
        label = "dashboard-background",
    )

    Column(
        Modifier
            .fillMaxSize()
            .background(pageBackground)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 18.dp, vertical = 20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        ProtectionHero(active = active, reason = statusReason(context, state))
        if (enrollment != null) SosCard()
        ProtectionLayers(state)

        if (!state.isDeviceOwner) {
            ManagedDevicePrompt(
                canProvisionManaged = canProvisionManaged,
                onProvisionManaged = onProvisionManaged,
            )
        }

        RecoveryActions(
            state = state,
            onOpenAccessibility = onOpenAccessibility,
            onStartVpn = onStartVpn,
            onOpenBrowser = onOpenBrowser,
        )
        DeviceCard(enrollment, deviceId)

        OutlinedButton(
            onClick = onReconfigure,
            modifier = Modifier
                .fillMaxWidth()
                .height(50.dp),
            shape = RoundedCornerShape(16.dp),
            border = BorderStroke(1.dp, DashboardOutline),
        ) {
            Text(
                stringResource(R.string.dashboard_review),
                color = Navy,
                fontWeight = FontWeight.SemiBold,
            )
        }
        PrivacyCard()
        Spacer(Modifier.height(8.dp))
    }
}

@Composable
private fun ProtectionHero(active: Boolean, reason: String) {
    val accent = if (active) Color(0xFF8BE1A3) else Color(0xFFFFD36B)
    Box(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(28.dp))
            .background(
                Brush.linearGradient(
                    listOf(DashboardBlueDeep, DashboardBlue, Color(0xFF17698C)),
                ),
            )
            .padding(22.dp),
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Image(
                        painter = painterResource(R.drawable.bulwark_logo),
                        contentDescription = stringResource(R.string.cd_shield),
                        modifier = Modifier
                            .size(46.dp)
                            .clip(RoundedCornerShape(13.dp)),
                    )
                    Spacer(Modifier.width(12.dp))
                    Column {
                        Text(
                            stringResource(R.string.dashboard_brand),
                            color = Color.White.copy(alpha = 0.72f),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 1.7.sp,
                        )
                        Text(
                            stringResource(
                                if (active) R.string.dashboard_title_active
                                else R.string.dashboard_title_setup,
                            ),
                            color = Color.White,
                            fontSize = 24.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = (-0.4).sp,
                        )
                    }
                }
                Box(
                    Modifier
                        .clip(CircleShape)
                        .background(accent.copy(alpha = 0.17f))
                        .border(1.dp, accent.copy(alpha = 0.55f), CircleShape)
                        .padding(horizontal = 11.dp, vertical = 7.dp),
                ) {
                    Text(
                        if (active) "ON" else "CHECK",
                        color = accent,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.ExtraBold,
                        letterSpacing = 0.8.sp,
                    )
                }
            }
            Text(
                reason,
                color = Color.White.copy(alpha = 0.88f),
                fontSize = 14.sp,
                lineHeight = 20.sp,
            )
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                MiniSignal(
                    symbol = if (active) "✓" else "•",
                    label = if (active) "Protected" else "Setup",
                    active = active,
                    modifier = Modifier.weight(1f),
                )
                MiniSignal("◉", "Private", true, Modifier.weight(1f))
                MiniSignal("⌁", "On device", true, Modifier.weight(1f))
            }
        }
    }
}

@Composable
private fun MiniSignal(symbol: String, label: String, active: Boolean, modifier: Modifier) {
    Row(
        modifier
            .clip(RoundedCornerShape(13.dp))
            .background(Color.White.copy(alpha = 0.09f))
            .padding(horizontal = 10.dp, vertical = 9.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            symbol,
            color = if (active) Color(0xFF90E6AA) else Color(0xFFFFD36B),
            fontWeight = FontWeight.Bold,
        )
        Spacer(Modifier.width(6.dp))
        Text(
            label,
            color = Color.White.copy(alpha = 0.88f),
            fontSize = 11.sp,
            fontWeight = FontWeight.Medium,
            maxLines = 1,
        )
    }
}

@Composable
private fun ProtectionLayers(state: SetupState) {
    PremiumCard {
        Text("Protection layers", color = Ink, fontSize = 18.sp, fontWeight = FontWeight.Bold)
        Text(
            "What is actively protecting this device right now.",
            color = Slate,
            fontSize = 13.sp,
        )
        Spacer(Modifier.height(4.dp))
        ProtectionRow(
            "Aa",
            stringResource(R.string.summary_chat_safety),
            "On-screen messages are checked locally for grooming signals.",
            state.accessibilityOn,
        )
        ProtectionRow(
            "↗",
            stringResource(R.string.summary_filtering_on),
            "Web and app traffic is checked before unsafe content loads.",
            state.vpnRunning,
        )
        ProtectionRow(
            "◆",
            stringResource(R.string.summary_managed),
            "Managed-device trust keeps secure-site filtering reliable.",
            state.isDeviceOwner && state.caInstalled,
            optional = !state.isDeviceOwner,
        )
        ProtectionRow(
            "⌁",
            stringResource(R.string.summary_paired),
            "Redacted safety alerts can reach the linked guardian.",
            state.paired,
        )
    }
}

@Composable
private fun ProtectionRow(
    symbol: String,
    title: String,
    detail: String,
    active: Boolean,
    optional: Boolean = false,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .size(42.dp)
                .clip(RoundedCornerShape(13.dp))
                .background(if (active) DashboardMint else Color(0xFFF2F4F6)),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                symbol,
                color = if (active) Good else Slate,
                fontSize = 14.sp,
                fontWeight = FontWeight.ExtraBold,
            )
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(title, color = Ink, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
            Text(
                detail,
                color = Slate,
                fontSize = 12.sp,
                lineHeight = 16.sp,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Spacer(Modifier.width(8.dp))
        StatusPill(active, optional)
    }
}

@Composable
private fun StatusPill(active: Boolean, optional: Boolean) {
    val background = when {
        active -> DashboardMint
        optional -> Color(0xFFF1F3F5)
        else -> DashboardAmber
    }
    val foreground = when {
        active -> Color(0xFF2E7D45)
        optional -> Slate
        else -> Color(0xFF8A5B00)
    }
    val label = when {
        active -> stringResource(R.string.state_on)
        optional -> stringResource(R.string.state_optional)
        else -> stringResource(R.string.state_off)
    }
    Box(
        Modifier
            .clip(CircleShape)
            .background(background)
            .padding(horizontal = 9.dp, vertical = 5.dp),
    ) {
        Text(label, color = foreground, fontSize = 10.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun RecoveryActions(
    state: SetupState,
    onOpenAccessibility: () -> Unit,
    onStartVpn: () -> Unit,
    onOpenBrowser: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        if (!state.accessibilityOn) {
            PrimaryAction(
                "Aa",
                stringResource(R.string.dashboard_action_chat),
                "Finish the on-device message safety layer.",
                onOpenAccessibility,
            )
        }
        if (!state.vpnRunning) {
            PrimaryAction(
                "↗",
                stringResource(R.string.dashboard_action_filtering),
                "Start the filtering tunnel and verify it is ready.",
                onStartVpn,
            )
        }
        BrowserAction(onOpenBrowser)
    }
}

@Composable
private fun PrimaryAction(symbol: String, title: String, detail: String, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        modifier = Modifier
            .fillMaxWidth()
            .height(62.dp),
        shape = RoundedCornerShape(18.dp),
        colors = ButtonDefaults.buttonColors(containerColor = Navy, contentColor = Color.White),
        elevation = ButtonDefaults.buttonElevation(defaultElevation = 0.dp),
        contentPadding = PaddingValues(horizontal = 16.dp),
    ) {
        Text(symbol, fontSize = 18.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f), horizontalAlignment = Alignment.Start) {
            Text(title, fontSize = 14.sp, fontWeight = FontWeight.Bold)
            Text(
                detail,
                color = Color.White.copy(alpha = 0.72f),
                fontSize = 11.sp,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Text("›", fontSize = 24.sp, color = Color.White.copy(alpha = 0.75f))
    }
}

@Composable
private fun BrowserAction(onClick: () -> Unit) {
    Button(
        onClick = onClick,
        modifier = Modifier
            .fillMaxWidth()
            .height(62.dp),
        shape = RoundedCornerShape(18.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = Color(0xFFE7F4FA),
            contentColor = Navy,
        ),
        elevation = ButtonDefaults.buttonElevation(defaultElevation = 0.dp),
        contentPadding = PaddingValues(horizontal = 16.dp),
    ) {
        Box(
            Modifier
                .size(32.dp)
                .clip(CircleShape)
                .background(DashboardSky.copy(alpha = 0.16f)),
            contentAlignment = Alignment.Center,
        ) {
            Text("◎", color = DashboardBlue, fontSize = 17.sp, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f), horizontalAlignment = Alignment.Start) {
            Text("Open safe browser", fontSize = 14.sp, fontWeight = FontWeight.Bold)
            Text("Pages are checked before they are shown.", color = Slate, fontSize = 11.sp)
        }
        Text("›", fontSize = 24.sp, color = Navy.copy(alpha = 0.6f))
    }
}

@Composable
private fun ManagedDevicePrompt(canProvisionManaged: Boolean, onProvisionManaged: () -> Unit) {
    Box(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(22.dp))
            .background(DashboardAmber)
            .border(1.dp, Color(0xFFF2D896), RoundedCornerShape(22.dp))
            .padding(18.dp),
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier
                        .size(38.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(Color.White.copy(alpha = 0.72f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Text("◆", color = Warn, fontSize = 15.sp)
                }
                Spacer(Modifier.width(11.dp))
                Column {
                    Text(
                        stringResource(R.string.managed_title),
                        color = Ink,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                    )
                    Text("One last layer for secure-site filtering", color = Color(0xFF7B641E), fontSize = 12.sp)
                }
            }
            Text(
                "Managed-device setup lets PH Bulwark trust its local inspection certificate, so HTTPS filtering works without breaking sites.",
                color = Ink.copy(alpha = 0.82f),
                fontSize = 13.sp,
                lineHeight = 18.sp,
            )
            if (canProvisionManaged) {
                Button(
                    onClick = onProvisionManaged,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(46.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Navy),
                    elevation = ButtonDefaults.buttonElevation(defaultElevation = 0.dp),
                ) {
                    Text(stringResource(R.string.managed_cta), fontWeight = FontWeight.SemiBold)
                }
            } else {
                Text(
                    "Open Review setup below for the managed-device steps.",
                    color = Color(0xFF7B641E),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                )
            }
        }
    }
}

@Composable
private fun DeviceCard(enrollment: EnrollmentRecord?, fallbackDeviceId: String) {
    PremiumCard {
        Row(
            Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column {
                Text(
                    stringResource(R.string.dashboard_this_device),
                    color = Ink,
                    fontSize = 17.sp,
                    fontWeight = FontWeight.Bold,
                )
                Text("Connection and pairing", color = Slate, fontSize = 12.sp)
            }
            Box(
                Modifier
                    .clip(CircleShape)
                    .background(DashboardMint)
                    .padding(horizontal = 9.dp, vertical = 5.dp),
            ) {
                Text("PRIVATE", color = Color(0xFF2E7D45), fontSize = 9.sp, fontWeight = FontWeight.ExtraBold)
            }
        }
        Spacer(Modifier.height(4.dp))
        DeviceLine(
            stringResource(R.string.dashboard_detail_device),
            compactId(enrollment?.deviceId ?: fallbackDeviceId),
        )
        enrollment?.let {
            DeviceLine(stringResource(R.string.dashboard_detail_child), compactId(it.childId))
            DeviceLine(stringResource(R.string.dashboard_detail_server), compactEndpoint(it.clusterEndpoint))
            if (it.deviceOwnerProvisioned) {
                DeviceLine(
                    stringResource(R.string.dashboard_management),
                    stringResource(R.string.dashboard_management_active),
                )
            }
        }
    }
}

@Composable
private fun DeviceLine(label: String, value: String) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, color = Slate, fontSize = 12.sp, modifier = Modifier.weight(0.38f))
        Text(
            value,
            color = Ink,
            fontSize = 12.sp,
            fontWeight = FontWeight.Medium,
            textAlign = TextAlign.End,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(0.62f),
        )
    }
}

@Composable
private fun PrivacyCard() {
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(18.dp))
            .background(Color(0xFFEAF4F8))
            .padding(15.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .size(36.dp)
                .clip(CircleShape)
                .background(Color.White.copy(alpha = 0.8f)),
            contentAlignment = Alignment.Center,
        ) {
            Text("◉", color = DashboardBlue, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.width(11.dp))
        Column {
            Text(
                stringResource(R.string.footer_title),
                color = Navy,
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
            )
            Text(stringResource(R.string.footer_body), color = Slate, fontSize = 11.sp)
        }
    }
}

@Composable
private fun PremiumCard(content: @Composable () -> Unit) {
    Card(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(containerColor = DashboardSurface),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        border = BorderStroke(1.dp, DashboardOutline),
    ) {
        Column(
            Modifier.padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            content()
        }
    }
}

private fun compactId(value: String): String {
    val clean = value.trim()
    return when {
        clean.length <= 14 -> clean.ifBlank { "—" }
        else -> "${clean.take(6)}…${clean.takeLast(5)}"
    }
}

private fun compactEndpoint(value: String): String = value
    .trim()
    .removePrefix("https://")
    .removePrefix("http://")
    .trimEnd('/')
    .ifBlank { "—" }
