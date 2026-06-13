package co.predatorhunters.bulwark.camera

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.os.SystemClock
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.UseCase
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import java.util.concurrent.Executors
import kotlinx.coroutines.delay

/** Outcome surfaced to the child after an action. Calm, never shaming. */
private enum class Notice { BlockedNsfw, CheckFailed, SaveFailed, Saved }

/** Min interval between live preview scores (CPU ViT ~100-300 ms on a Pixel 7). */
private const val PREVIEW_SCORE_INTERVAL_MS = 700L

/** Max long edge of the decode used to score a capture (model input is 384). */
private const val SCORING_MAX_DIM = 1024

/**
 * The camera: PreviewView + shutter, with two protective layers.
 *
 * 1. PREVIEW SHIELD (advisory): a throttled [ImageAnalysis] stream scores live
 *    frames; a flagged scene pauses the shutter with a calm explanation.
 * 2. CAPTURE GATE (authoritative): the shutter uses the IN-MEMORY capture
 *    callback — the full-quality frame is scored BEFORE anything is written.
 *    A blocked frame never touches disk and nothing about it is kept.
 *
 * FAIL-CLOSED: no loaded gate or an unscorable frame means no capture/save —
 * the camera never takes an unchecked photo (filters-always-active rule).
 */
@Composable
internal fun CameraScreen(
    gate: NsfwGate?,
    gateLoading: Boolean,
    captureForResult: Boolean,
    onSaveToGallery: (ByteArray) -> Boolean,
    onDeliverResult: (ByteArray, Int) -> Unit,
    onCancel: () -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current

    var hasPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED,
        )
    }
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted -> hasPermission = granted }
    LaunchedEffect(Unit) {
        if (!hasPermission) permissionLauncher.launch(Manifest.permission.CAMERA)
    }

    var lensFacing by remember { mutableStateOf(CameraSelector.LENS_FACING_BACK) }
    var previewFlagged by remember { mutableStateOf(false) }
    var capturing by remember { mutableStateOf(false) }
    var notice by remember { mutableStateOf<Notice?>(null) }

    val previewView = remember { PreviewView(context) }
    val imageCapture = remember {
        ImageCapture.Builder()
            .setCaptureMode(ImageCapture.CAPTURE_MODE_MINIMIZE_LATENCY)
            .build()
    }
    val workerExecutor = remember { Executors.newSingleThreadExecutor() }
    DisposableEffect(Unit) { onDispose { workerExecutor.shutdown() } }

    // Bind the camera; re-runs when permission lands, the lens flips, or the
    // gate becomes ready (the preview shield needs the gate).
    DisposableEffect(hasPermission, lensFacing, gate) {
        var disposed = false
        var provider: ProcessCameraProvider? = null
        if (hasPermission) {
            val future = ProcessCameraProvider.getInstance(context)
            future.addListener({
                val p = future.get()
                if (disposed) return@addListener
                provider = p
                val preview = Preview.Builder().build()
                    .also { it.setSurfaceProvider(previewView.surfaceProvider) }
                val useCases = mutableListOf<UseCase>(preview, imageCapture)
                if (gate != null) {
                    val analysis = ImageAnalysis.Builder()
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_RGBA_8888)
                        .build()
                    analysis.setAnalyzer(
                        workerExecutor,
                        PreviewShieldAnalyzer(gate) { flagged -> previewFlagged = flagged },
                    )
                    useCases += analysis
                }
                runCatching {
                    p.unbindAll()
                    p.bindToLifecycle(
                        lifecycleOwner,
                        CameraSelector.Builder().requireLensFacing(lensFacing).build(),
                        *useCases.toTypedArray(),
                    )
                }
            }, ContextCompat.getMainExecutor(context))
        }
        onDispose {
            disposed = true
            provider?.unbindAll()
        }
    }

    // Transient notices auto-dismiss; the BLOCKED explanation stays until "OK".
    LaunchedEffect(notice) {
        val n = notice
        if (n != null && n != Notice.BlockedNsfw) {
            delay(3500)
            if (notice == n) notice = null
        }
    }

    val gateReady = gate != null && !gateLoading
    val shutterEnabled =
        hasPermission && gateReady && !previewFlagged && !capturing && notice != Notice.BlockedNsfw

    fun takePhoto() {
        val g = gate ?: return
        if (!shutterEnabled) return
        capturing = true
        imageCapture.takePicture(
            workerExecutor,
            object : ImageCapture.OnImageCapturedCallback() {
                override fun onCaptureSuccess(image: ImageProxy) {
                    // ENTIRELY IN MEMORY: the frame is scored BEFORE anything is
                    // written anywhere. A blocked frame never touches disk.
                    val (jpeg, rotation) = image.use {
                        it.jpegBytes() to it.imageInfo.rotationDegrees
                    }
                    val verdict = runCatching { g.score(decodeForScoring(jpeg, rotation)) }
                    notice = when {
                        // Could not score -> FAIL CLOSED: not saved.
                        verdict.isFailure -> Notice.CheckFailed
                        g.shouldBlock(verdict.getOrThrow()) -> Notice.BlockedNsfw
                        captureForResult -> {
                            onDeliverResult(jpeg, rotation) // finishes the activity
                            null
                        }
                        onSaveToGallery(jpeg) -> Notice.Saved
                        else -> Notice.SaveFailed
                    }
                    capturing = false
                }

                override fun onError(exception: ImageCaptureException) {
                    notice = Notice.CheckFailed
                    capturing = false
                }
            },
        )
    }

    Box(Modifier.fillMaxSize().background(Ink)) {
        if (hasPermission) {
            AndroidView(factory = { previewView }, modifier = Modifier.fillMaxSize())
        } else {
            PermissionExplainer(
                onGrant = { permissionLauncher.launch(Manifest.permission.CAMERA) },
                onCancel = onCancel,
            )
        }

        // Preview shield: the live scene looks unsafe -> pause + explain.
        if (hasPermission && previewFlagged && notice != Notice.BlockedNsfw) {
            Scrim {
                OverlayCard(
                    title = stringResource(R.string.preview_shield_title),
                    body = stringResource(R.string.preview_shield_body),
                )
            }
        }

        if (hasPermission) {
            Column(
                Modifier.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                StatusPill(gateLoading = gateLoading, gateReady = gateReady)
                Spacer(Modifier.weight(1f))
                notice?.let { n -> if (n != Notice.BlockedNsfw) NoticeBanner(n) }
                Spacer(Modifier.height(12.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (captureForResult) {
                        TextButton(onClick = onCancel) {
                            Text(stringResource(R.string.action_cancel), color = Color.White)
                        }
                    } else {
                        Spacer(Modifier.width(64.dp))
                    }
                    Spacer(Modifier.weight(1f))
                    ShutterButton(enabled = shutterEnabled, onClick = ::takePhoto)
                    Spacer(Modifier.weight(1f))
                    OutlinedButton(onClick = {
                        lensFacing = if (lensFacing == CameraSelector.LENS_FACING_BACK) {
                            CameraSelector.LENS_FACING_FRONT
                        } else {
                            CameraSelector.LENS_FACING_BACK
                        }
                    }) {
                        Text(stringResource(R.string.cd_flip), color = Color.White, fontSize = 12.sp)
                    }
                }
                Spacer(Modifier.height(10.dp))
                Text(
                    stringResource(R.string.privacy_footnote),
                    color = Color(0xFFCFE0EC),
                    fontSize = 12.sp,
                    textAlign = TextAlign.Center,
                )
            }
        }

        // Gate loading / unavailable: the camera NEVER captures unchecked.
        if (hasPermission && gateLoading) {
            Scrim {
                CircularProgressIndicator(color = Sky)
                Spacer(Modifier.height(16.dp))
                Text(
                    stringResource(R.string.status_check_loading),
                    color = Color.White,
                    fontSize = 15.sp,
                    textAlign = TextAlign.Center,
                )
            }
        } else if (hasPermission && gate == null) {
            Scrim {
                OverlayCard(
                    title = stringResource(R.string.gate_unavailable_title),
                    body = stringResource(R.string.gate_unavailable_body),
                )
            }
        }

        // The calm capture-blocked explanation (stays until "OK").
        if (notice == Notice.BlockedNsfw) {
            Scrim {
                OverlayCard(
                    title = stringResource(R.string.blocked_title),
                    body = stringResource(R.string.blocked_body),
                    buttonLabel = stringResource(R.string.action_ok),
                    onButton = { notice = null },
                )
            }
        }
    }
}

/** Honest slice-1 video stub — registered intent entry point, no recording. */
@Composable
internal fun VideoStubScreen(onDone: () -> Unit) {
    Column(
        Modifier.fillMaxSize().background(Mist).padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            stringResource(R.string.video_stub_title),
            color = Ink,
            fontSize = 20.sp,
            fontWeight = FontWeight.SemiBold,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        Text(
            stringResource(R.string.video_stub_body),
            color = Slate,
            fontSize = 14.sp,
            textAlign = TextAlign.Center,
            lineHeight = 20.sp,
        )
        Spacer(Modifier.height(20.dp))
        Button(onClick = onDone) { Text(stringResource(R.string.action_ok)) }
    }
}

// ---------------------------------------------------------------------------
// Live preview shield analyzer
// ---------------------------------------------------------------------------

/**
 * Scores throttled live preview frames. Advisory only — the authoritative gate
 * is the capture-time score in takePhoto (a momentarily-safe preview frame can
 * never sneak a flagged capture through). Enters the flagged state on a single
 * flagged frame (protective), exits after two consecutive safe frames (no
 * flicker at the threshold boundary). A per-frame hiccup keeps the last state.
 */
private class PreviewShieldAnalyzer(
    private val gate: NsfwGate,
    private val onFlagged: (Boolean) -> Unit,
) : ImageAnalysis.Analyzer {
    private var lastRunMs = 0L
    private var safeStreak = 0
    private var flagged = false

    override fun analyze(image: ImageProxy) {
        val now = SystemClock.elapsedRealtime()
        if (now - lastRunMs < PREVIEW_SCORE_INTERVAL_MS) {
            image.close()
            return
        }
        lastRunMs = now
        val bitmap = runCatching {
            val rotation = image.imageInfo.rotationDegrees
            image.toBitmap().rotatedBy(rotation)
        }.getOrNull()
        image.close()
        if (bitmap == null) return
        val score = runCatching { gate.score(bitmap) }.getOrNull() ?: return
        if (gate.shouldBlock(score)) {
            safeStreak = 0
            if (!flagged) {
                flagged = true
                onFlagged(true)
            }
        } else {
            safeStreak++
            if (flagged && safeStreak >= 2) {
                flagged = false
                onFlagged(false)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Capture helpers
// ---------------------------------------------------------------------------

/** ImageCapture JPEG output is a single plane of JPEG bytes (EXIF included). */
private fun ImageProxy.jpegBytes(): ByteArray {
    val buf = planes[0].buffer
    val bytes = ByteArray(buf.remaining())
    buf.get(bytes)
    return bytes
}

/** Downsampled, upright decode of a captured JPEG for scoring. */
private fun decodeForScoring(jpeg: ByteArray, rotationDegrees: Int): Bitmap {
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeByteArray(jpeg, 0, jpeg.size, bounds)
    var sample = 1
    while (maxOf(bounds.outWidth, bounds.outHeight) / (sample * 2) >= SCORING_MAX_DIM) sample *= 2
    val opts = BitmapFactory.Options().apply { inSampleSize = sample }
    val bmp = BitmapFactory.decodeByteArray(jpeg, 0, jpeg.size, opts)
        ?: throw IllegalStateException("could not decode captured frame")
    return bmp.rotatedBy(rotationDegrees)
}

// ---------------------------------------------------------------------------
// Small UI pieces (existing app's calm visual language)
// ---------------------------------------------------------------------------

@Composable
private fun StatusPill(gateLoading: Boolean, gateReady: Boolean) {
    val label = when {
        gateLoading -> stringResource(R.string.status_check_loading)
        gateReady -> stringResource(R.string.status_check_ready)
        else -> stringResource(R.string.gate_unavailable_title)
    }
    val tint = if (gateReady) Good else Warn
    Row(
        Modifier
            .clip(RoundedCornerShape(50))
            .background(NavyDeep.copy(alpha = 0.75f))
            .padding(horizontal = 14.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.size(8.dp).clip(CircleShape).background(tint))
        Spacer(Modifier.width(8.dp))
        Text(label, color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun ShutterButton(enabled: Boolean, onClick: () -> Unit) {
    val cd = stringResource(R.string.cd_shutter)
    Box(
        Modifier
            .size(78.dp)
            .clip(CircleShape)
            .border(4.dp, if (enabled) Sky else Slate, CircleShape)
            .padding(8.dp)
            .clip(CircleShape)
            .background(if (enabled) Color.White else Slate)
            .clickable(enabled = enabled, onClick = onClick)
            .semantics { contentDescription = cd },
    )
}

@Composable
private fun Scrim(content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier
            .fillMaxSize()
            .background(NavyDeep.copy(alpha = 0.93f))
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
        content = content,
    )
}

@Composable
private fun OverlayCard(
    title: String,
    body: String,
    buttonLabel: String? = null,
    onButton: () -> Unit = {},
) {
    Card(
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
    ) {
        Column(Modifier.padding(22.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                title,
                color = Ink,
                fontSize = 18.sp,
                fontWeight = FontWeight.SemiBold,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(10.dp))
            Text(body, color = Slate, fontSize = 14.sp, textAlign = TextAlign.Center, lineHeight = 20.sp)
            if (buttonLabel != null) {
                Spacer(Modifier.height(16.dp))
                Button(onClick = onButton) { Text(buttonLabel) }
            }
        }
    }
}

@Composable
private fun NoticeBanner(notice: Notice) {
    val (text, tint) = when (notice) {
        Notice.Saved -> stringResource(R.string.saved_body) to Good
        Notice.CheckFailed -> stringResource(R.string.check_failed_body) to Warn
        Notice.SaveFailed -> stringResource(R.string.save_failed_body) to Warn
        Notice.BlockedNsfw -> return // modal overlay, not a banner
    }
    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = NavyDeep.copy(alpha = 0.9f)),
    ) {
        Row(
            Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(Modifier.size(8.dp).clip(CircleShape).background(tint))
            Spacer(Modifier.width(8.dp))
            Text(text, color = Color.White, fontSize = 13.sp)
        }
    }
}

@Composable
private fun PermissionExplainer(onGrant: () -> Unit, onCancel: () -> Unit) {
    Column(
        Modifier.fillMaxSize().background(Mist).padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            stringResource(R.string.permission_title),
            color = Ink,
            fontSize = 20.sp,
            fontWeight = FontWeight.SemiBold,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        Text(
            stringResource(R.string.permission_body),
            color = Slate,
            fontSize = 14.sp,
            textAlign = TextAlign.Center,
            lineHeight = 20.sp,
        )
        Spacer(Modifier.height(20.dp))
        Button(onClick = onGrant) { Text(stringResource(R.string.action_grant_permission)) }
        Spacer(Modifier.height(8.dp))
        TextButton(onClick = onCancel) { Text(stringResource(R.string.action_cancel), color = Slate) }
    }
}
