package co.predatorhunters.bulwark.camera

import androidx.camera.core.ImageCapture
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.math.roundToInt
import kotlinx.coroutines.delay

// ---------------------------------------------------------------------------
// Surface tokens — a single dark camera language layered over the live preview.
// Warm-neutral glass panels, a bright Sky accent, generous radii. Every control
// is an in-window composable (no Dialog/Popup) so FLAG_SECURE always covers it.
// ---------------------------------------------------------------------------
internal object Cam {
    val Glass = Color(0xCC0A2C44)          // frosted navy panel
    val GlassSoft = Color(0x990A2C44)
    val Hairline = Color(0x33FFFFFF)
    val OnGlass = Color(0xFFEAF2F8)
    val OnGlassDim = Color(0xCCB9CBD8)
    val Accent = Sky
    val AccentSoft = Color(0x333AA0DC)
    val RecordRed = Color(0xFFE5484D)
}

/**
 * Top control bar: flash control on the left, an at-a-glance safety chip in the
 * centre, and the live zoom readout on the right. Sits inside a soft top scrim.
 */
@Composable
internal fun TopBar(
    gateLoading: Boolean,
    gateReady: Boolean,
    flashMode: Int,
    onCycleFlash: () -> Unit,
    zoomRatio: Float,
    showFlash: Boolean,
    onSafetyClick: () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    Row(
        modifier
            .fillMaxWidth()
            .padding(horizontal = 18.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (showFlash) {
            FlashButton(flashMode = flashMode, onClick = onCycleFlash)
        } else {
            Spacer(Modifier.size(44.dp))
        }
        Spacer(Modifier.weight(1f))
        SafetyChip(gateLoading = gateLoading, gateReady = gateReady, onClick = onSafetyClick)
        Spacer(Modifier.weight(1f))
        ZoomReadout(zoomRatio = zoomRatio)
    }
}

@Composable
private fun SafetyChip(gateLoading: Boolean, gateReady: Boolean, onClick: () -> Unit = {}) {
    val label = when {
        gateLoading -> stringResource(R.string.status_check_loading)
        gateReady -> stringResource(R.string.status_check_ready)
        else -> stringResource(R.string.gate_unavailable_title)
    }
    val tint = if (gateReady) Good else Warn
    val pulse by animateFloatAsState(
        if (gateReady) 1f else 0.55f,
        animationSpec = tween(900),
        label = "safetyPulse",
    )
    Row(
        Modifier
            .clip(RoundedCornerShape(50))
            .background(Cam.Glass)
            .border(1.dp, Cam.Hairline, RoundedCornerShape(50))
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.size(7.dp).alpha(pulse).clip(CircleShape).background(tint))
        Spacer(Modifier.width(8.dp))
        Text(
            label,
            color = Cam.OnGlass,
            fontSize = 12.sp,
            fontWeight = FontWeight.Medium,
            letterSpacing = 0.2.sp,
        )
    }
}

@Composable
private fun ZoomReadout(zoomRatio: Float) {
    val text = formatZoom(zoomRatio)
    Box(
        Modifier
            .widthIn(min = 44.dp)
            .clip(RoundedCornerShape(50))
            .background(Cam.GlassSoft)
            .padding(horizontal = 12.dp, vertical = 7.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(text, color = Cam.OnGlass, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun FlashButton(flashMode: Int, onClick: () -> Unit) {
    val (glyph, cdRes) = when (flashMode) {
        ImageCapture.FLASH_MODE_ON -> "⚡" to R.string.flash_on        // lightning
        ImageCapture.FLASH_MODE_AUTO -> "A⚡" to R.string.flash_auto
        else -> "⚡̸" to R.string.flash_off                        // struck-through
    }
    val cd = stringResource(cdRes)
    val active = flashMode != ImageCapture.FLASH_MODE_OFF
    Box(
        Modifier
            .size(44.dp)
            .clip(CircleShape)
            .background(if (active) Cam.AccentSoft else Cam.GlassSoft)
            .border(1.dp, if (active) Cam.Accent else Cam.Hairline, CircleShape)
            .clickable(onClick = onClick)
            .semantics { contentDescription = cd },
        contentAlignment = Alignment.Center,
    ) {
        Text(glyph, color = if (active) Cam.Accent else Cam.OnGlassDim, fontSize = 15.sp)
    }
}

// ---------------------------------------------------------------------------
// Zoom chips — Samsung/Pixel quick-zoom pills (e.g. .5x / 1x / 2x).
// ---------------------------------------------------------------------------
@Composable
internal fun ZoomChips(
    stops: List<Float>,
    current: Float,
    onSelect: (Float) -> Unit,
    modifier: Modifier = Modifier,
) {
    if (stops.size < 2) return
    Row(
        modifier
            .clip(RoundedCornerShape(50))
            .background(Cam.Glass)
            .border(1.dp, Cam.Hairline, RoundedCornerShape(50))
            .padding(4.dp),
        horizontalArrangement = Arrangement.spacedBy(2.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        stops.forEach { stop ->
            val selected = isNearestStop(stop, current, stops)
            val cd = stringResource(R.string.cd_zoom, formatZoom(stop))
            val bg by animateFloatAsState(if (selected) 1f else 0f, label = "chipBg")
            Box(
                Modifier
                    .size(if (selected) 40.dp else 34.dp)
                    .clip(CircleShape)
                    .background(Cam.Accent.copy(alpha = bg * 0.9f))
                    .clickable { onSelect(stop) }
                    .semantics { contentDescription = cd },
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    formatZoom(stop),
                    color = if (selected) Color.White else Cam.OnGlassDim,
                    fontSize = if (selected) 13.sp else 12.sp,
                    fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Filter strip — horizontally scrollable color "looks" (still modes only).
// Each tile is a small color swatch baked from the look's own ColorMatrix so the
// child sees the look before they pick it; selection is a bright Accent ring.
// ---------------------------------------------------------------------------
@Composable
internal fun FilterStrip(
    selected: CameraFilter,
    onSelect: (CameraFilter) -> Unit,
    modifier: Modifier = Modifier,
) {
    val scroll = rememberScrollState()
    Row(
        modifier
            .fillMaxWidth()
            .horizontalScroll(scroll)
            .padding(horizontal = 16.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        CameraFilter.strip.forEach { filter ->
            FilterTile(
                filter = filter,
                selected = filter == selected,
                onClick = { onSelect(filter) },
            )
        }
    }
}

@Composable
private fun FilterTile(filter: CameraFilter, selected: Boolean, onClick: () -> Unit) {
    val ring by animateDpAsState(if (selected) 3.dp else 0.dp, label = "filterRing")
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Box(
            Modifier
                .size(54.dp)
                .clip(RoundedCornerShape(16.dp))
                .background(filterSwatch(filter))
                .border(ring, Cam.Accent, RoundedCornerShape(16.dp))
                .border(1.dp, Cam.Hairline, RoundedCornerShape(16.dp))
                .clickable(onClick = onClick),
        )
        Spacer(Modifier.height(6.dp))
        Text(
            stringResource(filter.label),
            color = if (selected) Cam.Accent else Cam.OnGlassDim,
            fontSize = 11.sp,
            fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
        )
    }
}

/** A representative gradient for a look's swatch (purely decorative, no capture). */
private fun filterSwatch(filter: CameraFilter): Brush {
    val stops = when (filter) {
        CameraFilter.None -> listOf(Color(0xFF6FB3D6), Color(0xFF2E5C73))
        CameraFilter.Vivid -> listOf(Color(0xFFFF7AA2), Color(0xFF3AA0DC), Color(0xFF7BE0B0))
        CameraFilter.Mono -> listOf(Color(0xFFE4E4E4), Color(0xFF6B6B6B))
        CameraFilter.Warm -> listOf(Color(0xFFFFD18A), Color(0xFFD98A4E))
        CameraFilter.Cool -> listOf(Color(0xFF9FD8FF), Color(0xFF4A77B0))
        CameraFilter.Fade -> listOf(Color(0xFFE8DFD2), Color(0xFFB7A98F))
        CameraFilter.Noir -> listOf(Color(0xFFBFBFBF), Color(0xFF111111))
    }
    return Brush.linearGradient(stops)
}

// ---------------------------------------------------------------------------
// Mode carousel — the swipeable Samsung-style mode rail under the shutter.
// The settled page drives the bound use-cases; the rail simply mirrors it so a
// tap and a swipe stay in sync. The selected mode sits centred + emphasised.
// ---------------------------------------------------------------------------
@Composable
internal fun ModeCarousel(
    modes: List<CameraMode>,
    selected: CameraMode,
    enabled: Boolean,
    onSelect: (CameraMode) -> Unit,
    modifier: Modifier = Modifier,
) {
    val scroll = rememberScrollState()
    Row(
        modifier
            .fillMaxWidth()
            .horizontalScroll(scroll)
            .alpha(if (enabled) 1f else 0.4f),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // Centring pads so the first/last labels can reach the middle.
        Spacer(Modifier.width(120.dp))
        modes.forEach { mode ->
            val isSel = mode == selected
            val scale by animateFloatAsState(
                if (isSel) 1f else 0.92f,
                spring(stiffness = Spring.StiffnessMediumLow),
                label = "modeScale",
            )
            Box(
                Modifier
                    .padding(horizontal = 6.dp)
                    .clip(RoundedCornerShape(50))
                    .clickable(enabled = enabled) { onSelect(mode) }
                    .padding(horizontal = 14.dp, vertical = 8.dp),
            ) {
                Text(
                    stringResource(mode.label).uppercase(),
                    color = if (isSel) Cam.Accent else Cam.OnGlassDim,
                    fontSize = 13.sp,
                    fontWeight = if (isSel) FontWeight.Bold else FontWeight.Medium,
                    letterSpacing = 1.2.sp,
                    modifier = Modifier.scale(scale),
                )
            }
        }
        Spacer(Modifier.width(120.dp))
    }
}

// ---------------------------------------------------------------------------
// The shutter — a single button that MORPHS between still and video states.
//   * still:        white disc inside an accent ring;
//   * video idle:    red disc inside the ring (ready to record);
//   * video recording: the red disc collapses to a rounded square ("stop").
// Disabled (gate not ready / preview flagged) dims and de-saturates.
// ---------------------------------------------------------------------------
@Composable
internal fun MorphShutter(
    mode: CameraMode,
    recording: Boolean,
    enabled: Boolean,
    busy: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val isVideo = mode.isVideo
    val cd = stringResource(
        when {
            isVideo && recording -> R.string.cd_record_stop
            isVideo -> R.string.cd_record_start
            else -> R.string.cd_shutter
        },
    )
    val ringColor = if (enabled) Color.White else Cam.OnGlassDim
    // Inner shape: full circle normally, rounded square while recording.
    val innerRadius by animateDpAsState(
        if (recording) 9.dp else 34.dp,
        spring(dampingRatio = Spring.DampingRatioMediumBouncy),
        label = "shutterRadius",
    )
    val innerSize by animateDpAsState(if (recording) 32.dp else 62.dp, label = "shutterSize")
    val innerColor = when {
        !enabled -> Cam.OnGlassDim.copy(alpha = 0.5f)
        isVideo -> Cam.RecordRed
        else -> Color.White
    }
    val pressScale by animateFloatAsState(if (busy) 0.9f else 1f, label = "shutterPress")
    val interaction = remember { MutableInteractionSource() }

    // A brief in-place "pop" each time the PHOTO<->VIDEO mode flips — the shutter
    // itself visibly reacts to the switch (scaling up, then springing back) on top
    // of the white<->red morph. NO translation: the shutter stays dead-centre (the
    // mode strip is the switch; the shutter only indicates the mode by its colour).
    // Skip the very first composition so the shutter doesn't pop on screen entry.
    var modePop by remember { mutableStateOf(1f) }
    var primed by remember { mutableStateOf(false) }
    LaunchedEffect(isVideo) {
        if (primed) {
            modePop = 1.18f
            delay(140)
            modePop = 1f
        }
        primed = true
    }
    val popScale by animateFloatAsState(
        modePop,
        spring(dampingRatio = Spring.DampingRatioMediumBouncy, stiffness = Spring.StiffnessMedium),
        label = "shutterModePop",
    )

    Box(
        modifier
            .size(82.dp)
            .scale(pressScale * popScale)
            .semantics { contentDescription = cd },
        contentAlignment = Alignment.Center,
    ) {
        // Outer ring.
        Box(
            Modifier
                .size(82.dp)
                .clip(CircleShape)
                .border(5.dp, ringColor, CircleShape)
                .clickable(
                    enabled = enabled,
                    interactionSource = interaction,
                    indication = null,
                    onClick = onClick,
                ),
        )
        // Inner morphing fill — crossfades white<->red across the mode switch.
        val crossfadeColor by animateColorAsState(
            innerColor,
            tween(260),
            label = "shutterInnerColor",
        )
        Box(
            Modifier
                .size(innerSize)
                .clip(RoundedCornerShape(innerRadius))
                .background(crossfadeColor),
        )
    }
}

// ---------------------------------------------------------------------------
// Side controls flanking the shutter: the gallery thumbnail (last safe capture)
// and the front/back flip. Kept symmetric so the shutter stays centred.
// ---------------------------------------------------------------------------
@Composable
internal fun GalleryThumb(
    bitmap: ImageBitmap?,
    modifier: Modifier = Modifier,
) {
    Box(
        modifier
            .size(52.dp)
            .clip(RoundedCornerShape(14.dp))
            .background(Cam.GlassSoft)
            .border(1.5.dp, Cam.Hairline, RoundedCornerShape(14.dp)),
        contentAlignment = Alignment.Center,
    ) {
        if (bitmap != null) {
            Image(
                bitmap = bitmap,
                contentDescription = stringResource(R.string.cd_last_shot),
                modifier = Modifier.size(52.dp).clip(RoundedCornerShape(14.dp)),
                contentScale = ContentScale.Crop,
            )
        } else {
            Text("🖼", fontSize = 18.sp, color = Cam.OnGlassDim) // framed picture
        }
    }
}

@Composable
internal fun FlipButton(onClick: () -> Unit, modifier: Modifier = Modifier) {
    val cd = stringResource(R.string.cd_flip)
    Box(
        modifier
            .size(52.dp)
            .clip(CircleShape)
            .background(Cam.GlassSoft)
            .border(1.dp, Cam.Hairline, CircleShape)
            .clickable(onClick = onClick)
            .semantics { contentDescription = cd },
        contentAlignment = Alignment.Center,
    ) {
        Text("🔄", fontSize = 20.sp, color = Cam.OnGlass) // counterclockwise arrows
    }
}

// ---------------------------------------------------------------------------
// Tap-to-focus ring — a brief animated reticle at the tapped point.
// ---------------------------------------------------------------------------
@Composable
internal fun FocusRing(point: Offset, visible: Boolean) {
    val scale by animateFloatAsState(
        if (visible) 1f else 1.4f,
        spring(dampingRatio = Spring.DampingRatioMediumBouncy),
        label = "focusScale",
    )
    val alpha by animateFloatAsState(if (visible) 1f else 0f, tween(220), label = "focusAlpha")
    if (alpha <= 0.01f) return
    // The Canvas is 76.dp; offset so its centre lands on the tap point (px).
    Canvas(
        Modifier
            .size(76.dp)
            .offset { IntOffset((point.x - 114).roundToInt(), (point.y - 114).roundToInt()) }
            .scale(scale)
            .alpha(alpha),
    ) {
        val stroke = Stroke(width = 3f, cap = StrokeCap.Round)
        val r = size.minDimension / 2.4f
        val c = Offset(size.width / 2, size.height / 2)
        drawCircle(color = Sky, radius = r, style = stroke, center = c)
        drawCircle(color = Sky.copy(alpha = 0.25f), radius = r * 0.18f, center = c)
    }
}

// ---------------------------------------------------------------------------
// Pro tray — manual controls (Panasonic-style). Exposure compensation is always
// available; an ISO slider is shown when the activity reports a sensitivity
// range. Each is a labelled glass slider that writes straight to CameraControl.
// ---------------------------------------------------------------------------
@Composable
internal fun ProTray(
    exposureIndex: Int,
    exposureRange: IntRange,
    onExposure: (Int) -> Unit,
    isoValue: Int?,
    isoRange: IntRange?,
    onIso: (Int?) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
            .clip(RoundedCornerShape(20.dp))
            .background(Cam.Glass)
            .border(1.dp, Cam.Hairline, RoundedCornerShape(20.dp))
            .padding(horizontal = 18.dp, vertical = 14.dp),
    ) {
        ProSlider(
            label = stringResource(R.string.pro_exposure),
            value = exposureIndex.toFloat(),
            range = exposureRange.first.toFloat()..exposureRange.last.toFloat(),
            steps = (exposureRange.last - exposureRange.first - 1).coerceAtLeast(0),
            readout = formatEv(exposureIndex, exposureRange),
            onValue = { onExposure(it.roundToInt()) },
            enabled = exposureRange.first != exposureRange.last,
        )
        if (isoRange != null) {
            Spacer(Modifier.height(10.dp))
            ProSlider(
                label = stringResource(R.string.pro_iso),
                value = (isoValue ?: isoRange.first).toFloat(),
                range = isoRange.first.toFloat()..isoRange.last.toFloat(),
                steps = 0,
                readout = isoValue?.let { "$it" } ?: stringResource(R.string.pro_auto),
                onValue = { onIso(it.roundToInt()) },
                enabled = true,
            )
        }
    }
}

@Composable
private fun ProSlider(
    label: String,
    value: Float,
    range: ClosedFloatingPointRange<Float>,
    steps: Int,
    readout: String,
    onValue: (Float) -> Unit,
    enabled: Boolean,
) {
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                label,
                color = Cam.OnGlass,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                letterSpacing = 0.6.sp,
                modifier = Modifier.width(64.dp),
            )
            Spacer(Modifier.width(4.dp))
            Box(Modifier.weight(1f)) {
                Slider(
                    value = value.coerceIn(range.start, range.endInclusive),
                    onValueChange = onValue,
                    valueRange = range,
                    steps = steps,
                    enabled = enabled,
                    colors = SliderDefaults.colors(
                        thumbColor = Cam.Accent,
                        activeTrackColor = Cam.Accent,
                        inactiveTrackColor = Cam.Hairline,
                    ),
                )
            }
            Spacer(Modifier.width(8.dp))
            Text(
                readout,
                color = Cam.OnGlassDim,
                fontSize = 12.sp,
                fontWeight = FontWeight.Medium,
                textAlign = TextAlign.End,
                modifier = Modifier.width(48.dp),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Recording timer pill (mm:ss) shown while a video take is in progress.
// ---------------------------------------------------------------------------
@Composable
internal fun RecordTimer(elapsedMs: Long, modifier: Modifier = Modifier) {
    val total = elapsedMs / 1000
    val text = "%02d:%02d".format(total / 60, total % 60)
    Row(
        modifier
            .clip(RoundedCornerShape(50))
            .background(Cam.Glass)
            .border(1.dp, Cam.Hairline, RoundedCornerShape(50))
            .padding(horizontal = 14.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.size(8.dp).clip(CircleShape).background(Cam.RecordRed))
        Spacer(Modifier.width(8.dp))
        Text(text, color = Cam.OnGlass, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------
internal fun formatZoom(ratio: Float): String {
    return if (ratio < 1f) {
        // .5x style for ultra-wide.
        val s = (ratio * 10).roundToInt() / 10f
        "${trimZero(s)}x"
    } else {
        val rounded = (ratio * 10).roundToInt() / 10f
        if (rounded % 1f == 0f) "${rounded.toInt()}x" else "${trimZero(rounded)}x"
    }
}

private fun trimZero(v: Float): String {
    val s = "%.1f".format(v)
    return s.trimEnd('0').trimEnd('.')
}

private fun isNearestStop(stop: Float, current: Float, stops: List<Float>): Boolean {
    val nearest = stops.minByOrNull { kotlin.math.abs(it - current) } ?: return false
    return nearest == stop
}

private fun formatEv(index: Int, range: IntRange): String {
    if (range.first == range.last) return "0"
    val sign = if (index > 0) "+" else ""
    return "$sign$index"
}
