package co.predatorhunters.bulwark.camera

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// High-contrast, calm camera palette. The viewfinder stays near-black so controls
// read instantly without washing out the preview, while safety/status accents
// remain distinct and accessible.
internal val Navy = Color(0xFF123E5A)
internal val NavyDeep = Color(0xFF071B2A)
internal val Sky = Color(0xFF62C8FF)
internal val Mist = Color(0xFFF4F7F8)
internal val Ink = Color(0xFF07131D)
internal val Slate = Color(0xFF687783)
internal val Good = Color(0xFF69D38A)
internal val Warn = Color(0xFFFFC65C)
internal val Danger = Color(0xFFFF6B61)

private val Colors = darkColorScheme(
    primary = Sky,
    onPrimary = Ink,
    secondary = Good,
    onSecondary = Ink,
    background = Ink,
    onBackground = Color.White,
    surface = NavyDeep,
    onSurface = Color.White,
    surfaceVariant = Navy,
    onSurfaceVariant = Mist,
    error = Danger,
    onError = Ink,
)

private val CameraTypography = Typography(
    headlineSmall = TextStyle(
        fontSize = 24.sp,
        lineHeight = 29.sp,
        fontWeight = FontWeight.SemiBold,
        letterSpacing = (-0.4).sp,
    ),
    titleMedium = TextStyle(
        fontSize = 16.sp,
        lineHeight = 21.sp,
        fontWeight = FontWeight.SemiBold,
        letterSpacing = (-0.1).sp,
    ),
    bodyMedium = TextStyle(
        fontSize = 14.sp,
        lineHeight = 20.sp,
        fontWeight = FontWeight.Normal,
    ),
    labelLarge = TextStyle(
        fontSize = 14.sp,
        lineHeight = 18.sp,
        fontWeight = FontWeight.SemiBold,
        letterSpacing = 0.1.sp,
    ),
)

private val CameraShapes = Shapes(
    extraSmall = RoundedCornerShape(10.dp),
    small = RoundedCornerShape(14.dp),
    medium = RoundedCornerShape(20.dp),
    large = RoundedCornerShape(28.dp),
    extraLarge = RoundedCornerShape(36.dp),
)

@Composable
internal fun BulwarkCameraTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = Colors,
        typography = CameraTypography,
        shapes = CameraShapes,
        content = content,
    )
}
