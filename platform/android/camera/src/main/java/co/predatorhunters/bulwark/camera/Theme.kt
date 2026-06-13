package co.predatorhunters.bulwark.camera

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// ---------------------------------------------------------------------------
// Brand palette — mirrors the child app's single source of truth
// (platform/android/app/.../Onboarding.kt). Values are duplicated because this
// is a separate APK; keep both in sync if the brand ever changes.
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

private val Colors = lightColorScheme(
    primary = Navy,
    onPrimary = Color.White,
    secondary = Sky,
    background = Mist,
    onBackground = Ink,
    surface = Color.White,
    onSurface = Ink,
)

@Composable
internal fun BulwarkCameraTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = Colors, content = content)
}
