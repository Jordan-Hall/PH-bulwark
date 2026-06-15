package co.predatorhunters.bulwark.camera

import android.Manifest
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.Build
import android.os.SystemClock
import android.provider.MediaStore
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraControl
import androidx.camera.core.CameraInfo
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.UseCase
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.video.FallbackStrategy
import androidx.camera.video.FileOutputOptions
import androidx.camera.video.Quality
import androidx.camera.video.QualitySelector
import androidx.camera.video.Recorder
import androidx.camera.video.Recording
import androidx.camera.video.VideoCapture
import androidx.camera.video.VideoRecordEvent
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
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
import androidx.compose.material3.Slider
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
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
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
import java.io.File
import java.util.concurrent.Executors
import kotlin.math.abs
import kotlin.math.atan2
import kotlin.math.roundToInt
import kotlinx.coroutines.delay

/** Outcome surfaced to the child after an action. Calm, never shaming. */
private enum class Notice { BlockedNsfw, CheckFailed, SaveFailed, Saved }

/** Min interval between live preview scores (CPU ViT ~100-300 ms on a Pixel 7). */
private const val PREVIEW_SCORE_INTERVAL_MS = 300L

/** Max long edge of the decode used to score a capture (model input is 384). */
private const val SCORING_MAX_DIM = 512

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

    fun isGranted(perm: String) =
        ContextCompat.checkSelfPermission(context, perm) == PackageManager.PERMISSION_GRANTED
    var hasPermission by remember { mutableStateOf(isGranted(Manifest.permission.CAMERA)) }
    var hasAudioPermission by remember { mutableStateOf(isGranted(Manifest.permission.RECORD_AUDIO)) }
    // ONE prompt for both — camera + (optional) mic together, not two annoying
    // sequential dialogs. Mic denial just yields silent video; camera denial
    // shows the explainer. Audio never affects safety (the gate scores frames).
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { result ->
        result[Manifest.permission.CAMERA]?.let { hasPermission = it }
        result[Manifest.permission.RECORD_AUDIO]?.let { hasAudioPermission = it }
    }
    LaunchedEffect(Unit) {
        val needed = buildList {
            if (!hasPermission) add(Manifest.permission.CAMERA)
            if (!hasAudioPermission) add(Manifest.permission.RECORD_AUDIO)
        }
        if (needed.isNotEmpty()) permissionLauncher.launch(needed.toTypedArray())
    }

    var lensFacing by remember { mutableStateOf(CameraSelector.LENS_FACING_BACK) }
    var previewFlagged by remember { mutableStateOf(false) }
    var capturing by remember { mutableStateOf(false) }
    var notice by remember { mutableStateOf<Notice?>(null) }
    var selectedFilter by remember { mutableStateOf(CameraFilter.None) }
    var filtersOpen by remember { mutableStateOf(false) }
    var exposureIndex by remember { mutableStateOf(0) }
    var rollDegrees by remember { mutableStateOf(0f) }
    var levelVisible by remember { mutableStateOf(false) }
    var levelMoveTick by remember { mutableStateOf(0) }
    var lastThumb by remember { mutableStateOf<Bitmap?>(null) }
    var controlsVisible by remember { mutableStateOf(true) }
    var tapCount by remember { mutableStateOf(0) }
    var mode by remember { mutableStateOf(CameraMode.default) }
    var cameraControl by remember { mutableStateOf<CameraControl?>(null) }
    var cameraInfo by remember { mutableStateOf<CameraInfo?>(null) }
    var flashMode by remember { mutableStateOf(ImageCapture.FLASH_MODE_OFF) }
    var zoomRatio by remember { mutableStateOf(1f) }
    var recording by remember { mutableStateOf(false) }
    var activeRecording by remember { mutableStateOf<Recording?>(null) }

    val previewView = remember {
        PreviewView(context).apply {
            // COMPATIBLE (TextureView) — the default PERFORMANCE mode renders the
            // camera into a separate SurfaceView overlay that setRenderEffect can't
            // touch, so the live filter preview wouldn't show. TextureView renders
            // into the view layer, so the filter RenderEffect actually applies.
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
        }
    }
    val imageCapture = remember {
        ImageCapture.Builder()
            .setCaptureMode(ImageCapture.CAPTURE_MODE_MINIMIZE_LATENCY)
            .build()
    }
    val videoCapture = remember {
        VideoCapture.withOutput(
            Recorder.Builder()
                .setQualitySelector(
                    QualitySelector.from(
                        Quality.HD,
                        FallbackStrategy.lowerQualityOrHigherThan(Quality.SD),
                    ),
                )
                .build(),
        )
    }
    val workerExecutor = remember { Executors.newSingleThreadExecutor() }
    val mainExecutor = remember { ContextCompat.getMainExecutor(context) }
    DisposableEffect(Unit) { onDispose { workerExecutor.shutdown() } }

    // Horizon level: read device roll from the gravity sensor so the on-screen
    // level line shows when the shot is tilted (and turns green when level).
    DisposableEffect(Unit) {
        val sm = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
        val sensor = sm.getDefaultSensor(Sensor.TYPE_GRAVITY)
            ?: sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
        val listener = object : SensorEventListener {
            override fun onSensorChanged(e: SensorEvent) {
                val newRoll = Math.toDegrees(
                    atan2(e.values[0].toDouble(), e.values[1].toDouble()),
                ).toFloat()
                // Only reveal the level guide while the camera is actually moving.
                if (abs(newRoll - rollDegrees) > 0.4f) {
                    levelVisible = true
                    levelMoveTick++
                }
                rollDegrees = newRoll
            }
            override fun onAccuracyChanged(s: Sensor?, accuracy: Int) {}
        }
        if (sensor != null) sm.registerListener(listener, sensor, SensorManager.SENSOR_DELAY_UI)
        onDispose { sm.unregisterListener(listener) }
    }

    // Bind the camera; re-runs when permission lands, the lens flips, or the
    // gate becomes ready (the preview shield needs the gate).
    DisposableEffect(hasPermission, lensFacing, gate, mode.isVideo) {
        var disposed = false
        var provider: ProcessCameraProvider? = null
        if (hasPermission) {
            val future = ProcessCameraProvider.getInstance(context)
            future.addListener({
                val p = future.get()
                if (disposed) return@addListener
                provider = p
                val preview = Preview.Builder().build()
                // Video mode binds VideoCapture in place of ImageCapture (CameraX
                // can't run both alongside analysis); the live preview-shield
                // analyzer stays bound in BOTH modes so the safety layer holds.
                val captureUseCase: UseCase = if (mode.isVideo) videoCapture else imageCapture
                val useCases = mutableListOf<UseCase>(preview, captureUseCase)
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
                    val camera = p.bindToLifecycle(
                        lifecycleOwner,
                        CameraSelector.Builder().requireLensFacing(lensFacing).build(),
                        *useCases.toTypedArray(),
                    )
                    // Attach the preview surface AFTER unbind+bind. Setting it
                    // before unbindAll (while the old use case still held the
                    // surface) left the preview BLACK on the Photo->Video swap
                    // until a full rebind (the flip-twice workaround).
                    preview.setSurfaceProvider(previewView.surfaceProvider)
                    cameraControl = camera.cameraControl
                    cameraInfo = camera.cameraInfo
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

    // Controls auto-hide after idle for a clear view; a tap on the preview or any
    // control resets the timer, and any notice forces them back so it's seen.
    LaunchedEffect(
        controlsVisible, tapCount, mode, selectedFilter, zoomRatio,
        flashMode, exposureIndex, filtersOpen, capturing,
    ) {
        if (controlsVisible) {
            delay(5000)
            controlsVisible = false
        }
    }
    LaunchedEffect(notice) { if (notice != null) controlsVisible = true }

    // The level guide shows only while moving, then fades after ~1.2s of stillness.
    LaunchedEffect(levelMoveTick) {
        delay(1200)
        levelVisible = false
    }

    // Apply the selected mode's Camera2 scene hints (Night / Portrait / Pro)
    // whenever the mode changes or the camera (re)binds. Best-effort — a device
    // that can't honor a hint simply ignores it (see CameraMode.applySceneHints).
    LaunchedEffect(mode, cameraControl) {
        cameraControl?.let { CameraMode.applySceneHints(mode, it) }
    }

    // Flash applies to the still ImageCapture; zoom drives the bound camera's
    // control. Both are capture/display settings only — neither affects the RAW
    // frame the safety gate scores.
    // Flash ON drives a continuous TORCH (a real, visible light) via the camera
    // control, AND sets the capture flash; AUTO/OFF leave the torch off and let
    // the capture decide. Re-applied on (re)bind since the control changes.
    LaunchedEffect(flashMode, cameraControl) {
        imageCapture.flashMode = flashMode
        cameraControl?.enableTorch(flashMode == ImageCapture.FLASH_MODE_ON)
    }

    // Pro exposure (EV): apply the slider to the live camera; reset to neutral on
    // leaving Pro so the other modes stay fully automatic.
    LaunchedEffect(exposureIndex, cameraControl) {
        runCatching { cameraControl?.setExposureCompensationIndex(exposureIndex) }
    }
    LaunchedEffect(mode.isPro) { if (!mode.isPro) exposureIndex = 0 }
    LaunchedEffect(zoomRatio, cameraControl) { cameraControl?.setZoomRatio(zoomRatio) }

    // Live safety layer for video: if the preview scene is flagged WHILE
    // recording, stop immediately. The finalized clip is then re-scanned and
    // (being unsafe) discarded — nothing reaches the gallery.
    LaunchedEffect(previewFlagged) {
        if (previewFlagged && recording) activeRecording?.stop()
    }

    val gateReady = gate != null && !gateLoading
    // While recording, the shutter stays live so it can STOP (the live analyzer
    // auto-stops on a flag); otherwise it's the still/start-recording gate.
    val shutterEnabled = hasPermission && gateReady && notice != Notice.BlockedNsfw &&
        !capturing && (recording || !previewFlagged)

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
                        else -> {
                            // SAFE capture only: bake the selected look into the SAVED
                            // file so it matches the preview. Applied HERE, after the
                            // gate scored the RAW frame — a filter can never change what
                            // the gate sees. None returns the original bytes unchanged.
                            val outJpeg = applyFilterToJpeg(jpeg, rotation, selectedFilter)
                            val outRotation = if (selectedFilter == CameraFilter.None) rotation else 0
                            when {
                                captureForResult -> {
                                    onDeliverResult(outJpeg, outRotation) // finishes the activity
                                    null
                                }
                                onSaveToGallery(outJpeg) -> {
                                    lastThumb = decodeThumb(outJpeg, outRotation)
                                    Notice.Saved
                                }
                                else -> Notice.SaveFailed
                            }
                        }
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

    // Video: record to an APP-PRIVATE temp file, then VideoGate.rescan EVERY
    // sampled frame before publishing. A single flagged frame (or any failure)
    // deletes the temp and publishes nothing — the clip is never user-visible
    // until a fully-clean re-scan (VideoGate's documented two-layer contract).
    fun finalizeRecording(event: VideoRecordEvent.Finalize, temp: File) {
        recording = false
        activeRecording = null
        if (event.hasError()) {
            temp.delete()
            notice = Notice.SaveFailed
            return
        }
        val g = gate
        if (g == null) {
            temp.delete()
            notice = Notice.CheckFailed
            return
        }
        capturing = true // re-scan in progress: gate the shutter, show busy
        workerExecutor.execute {
            val result = VideoGate.rescan(temp, g)
            val published = result == VideoGate.Result.Clean && publishVideoToGallery(context, temp)
            temp.delete()
            mainExecutor.execute {
                notice = when (result) {
                    VideoGate.Result.Clean -> if (published) Notice.Saved else Notice.SaveFailed
                    VideoGate.Result.Blocked -> Notice.BlockedNsfw
                    VideoGate.Result.CheckFailed -> Notice.CheckFailed
                }
                capturing = false
            }
        }
    }

    fun toggleRecording() {
        if (recording) {
            activeRecording?.stop()
            return
        }
        if (!shutterEnabled || gate == null) return
        val temp = File(context.cacheDir, "rec_${System.currentTimeMillis()}.mp4")
        val pending = videoCapture.output
            .prepareRecording(context, FileOutputOptions.Builder(temp).build())
        // Record sound when the optional mic permission is granted; otherwise the
        // clip is silent. Audio never affects safety — the gate scores video
        // FRAMES only. withAudioEnabled() would SecurityException without the grant.
        if (hasAudioPermission) pending.withAudioEnabled()
        activeRecording = pending.start(mainExecutor) { event ->
                when (event) {
                    is VideoRecordEvent.Start -> recording = true
                    is VideoRecordEvent.Finalize -> finalizeRecording(event, temp)
                    else -> Unit
                }
            }
    }

    // Open the device gallery (where saved photos can be viewed AND edited with
    // the system editor) — the in-app thumbnail/editor builds on this next.
    fun openGallery() {
        runCatching {
            context.startActivity(
                Intent(Intent.ACTION_VIEW).apply {
                    setDataAndType(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, "image/*")
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                },
            )
        }
    }

    fun flipCamera() {
        if (recording) return
        lensFacing = if (lensFacing == CameraSelector.LENS_FACING_BACK) {
            CameraSelector.LENS_FACING_FRONT
        } else {
            CameraSelector.LENS_FACING_BACK
        }
    }

    Box(Modifier.fillMaxSize().background(Ink)) {
        if (hasPermission) {
            AndroidView(
                factory = { previewView },
                modifier = Modifier.fillMaxSize(),
                // Live filter preview: the selected look as a RenderEffect on the
                // PreviewView (API 31+; older devices preview unfiltered — the SAVED
                // photo is still filtered). A display transform only; it never
                // touches what the safety gate scores (the gate scores the RAW frame).
                update = { pv ->
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        pv.setRenderEffect(selectedFilter.renderEffect())
                    }
                },
            )
        } else {
            PermissionExplainer(
                onGrant = {
                    permissionLauncher.launch(
                        arrayOf(Manifest.permission.CAMERA, Manifest.permission.RECORD_AUDIO),
                    )
                },
                onCancel = onCancel,
            )
        }

        // Tap the preview to reveal the auto-hidden controls; double-tap flips the
        // camera (no button needed). Sits below the controls in z-order, so taps on
        // a control still reach the control.
        if (hasPermission) {
            Box(
                Modifier
                    .fillMaxSize()
                    .pointerInput(Unit) {
                        detectTapGestures(
                            onTap = {
                                controlsVisible = true
                                tapCount++
                            },
                            onDoubleTap = { flipCamera() },
                        )
                    },
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

        // Visible safety check: while a photo is scored or a clip re-scanned, show
        // "Checking…" so the gate's work is visible. The shot/clip is saved ONLY
        // after this clears — never before (this IS the deliberate safety delay).
        if (hasPermission && capturing) {
            CheckingOverlay()
        }

        // Horizon level guide — only while actively moving the camera (and not
        // while checking/flagged/blocked). Shows the tilt angle; green when level.
        if (hasPermission && levelVisible && !capturing && !previewFlagged &&
            notice != Notice.BlockedNsfw
        ) {
            LevelIndicator(rollDegrees)
        }

        // Readable control zone: a soft bottom-up gradient so the controls stay
        // legible over any scene (Samsung/Pixel-style), without hiding the shot.
        if (hasPermission && controlsVisible) {
            Box(
                Modifier
                    .fillMaxWidth()
                    .height(320.dp)
                    .align(Alignment.BottomCenter)
                    .background(
                        Brush.verticalGradient(listOf(Color.Transparent, Ink.copy(alpha = 0.72f))),
                    ),
            )
        }

        if (hasPermission && controlsVisible) {
            Column(
                Modifier.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                TopBar(
                    gateLoading = gateLoading,
                    gateReady = gateReady,
                    flashMode = flashMode,
                    onCycleFlash = { flashMode = nextFlashMode(flashMode) },
                    zoomRatio = zoomRatio,
                    showFlash = lensFacing == CameraSelector.LENS_FACING_BACK &&
                        cameraInfo?.hasFlashUnit() == true,
                )
                Spacer(Modifier.weight(1f))
                notice?.let { n -> if (n != Notice.BlockedNsfw) NoticeBanner(n) }
                Spacer(Modifier.height(12.dp))
                // Filters live BEHIND a toggle (the ✦ button left of the shutter)
                // so they stop cluttering the view — revealed only when wanted.
                if (mode.supportsFilters && filtersOpen) {
                    FilterStrip(selected = selectedFilter, onSelect = { selectedFilter = it })
                    Spacer(Modifier.height(12.dp))
                }
                // Mode carousel. Only the still modes (Photo / Portrait / Night /
                // Pro) are offered for now — each applies real Camera2 scene hints;
                // Video recording is a follow-up (VideoGate scaffold is in place).
                ModeCarousel(
                    // Video is offered only when saving to the gallery — the
                    // "return a result" contract (onDeliverResult) is photo-only.
                    modes = remember(captureForResult) {
                        if (captureForResult) CameraMode.strip.filter { it.isStill } else CameraMode.strip
                    },
                    selected = mode,
                    enabled = !capturing && !recording,
                    onSelect = { mode = it },
                )
                Spacer(Modifier.height(12.dp))
                // Pro exposure (EV) slider — the real manual control that makes Pro
                // differ from Photo (shown only when the lens reports an EV range).
                if (mode.isPro) {
                    val evRange = cameraInfo?.exposureState?.exposureCompensationRange
                    if (evRange != null && evRange.upper > evRange.lower) {
                        ProExposureSlider(
                            index = exposureIndex,
                            range = evRange.lower..evRange.upper,
                            onChange = { exposureIndex = it },
                        )
                        Spacer(Modifier.height(12.dp))
                    }
                }
                // Quick-zoom pills (1x / 2x / 5x, clamped to the lens's range).
                // ZoomChips renders nothing if the camera offers <2 usable stops.
                ZoomChips(
                    stops = remember(cameraInfo) {
                        val maxZoom = cameraInfo?.zoomState?.value?.maxZoomRatio ?: 1f
                        listOf(1f, 2f, 5f).filter { it <= maxZoom }
                    },
                    current = zoomRatio,
                    onSelect = { zoomRatio = it },
                )
                Spacer(Modifier.height(12.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (captureForResult) {
                        TextButton(onClick = onCancel) {
                            Text(stringResource(R.string.action_cancel), color = Color.White)
                        }
                    } else {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            GalleryButton(thumb = lastThumb, onOpen = { openGallery() })
                            if (mode.supportsFilters) {
                                Spacer(Modifier.width(10.dp))
                                FilterToggle(
                                    open = filtersOpen,
                                    onToggle = { filtersOpen = !filtersOpen },
                                )
                            }
                        }
                    }
                    Spacer(Modifier.weight(1f))
                    MorphShutter(
                        mode = mode,
                        recording = recording,
                        enabled = shutterEnabled,
                        busy = capturing,
                        onClick = { if (mode.isVideo) toggleRecording() else takePhoto() },
                    )
                    Spacer(Modifier.weight(1f))
                    FlipButton(enabled = !recording, onClick = { flipCamera() })
                }
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

/** Horizon level: a center line that tilts with the device, green when level. */
@Composable
private fun LevelIndicator(rollDegrees: Float) {
    val level = abs(rollDegrees) < 1.5f
    val color = if (level) Good else Color.White.copy(alpha = 0.85f)
    Column(
        Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        // The actual tilt angle (or "Level" when square).
        Text(
            if (level) "Level" else "${abs(rollDegrees.roundToInt())}°",
            color = color,
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold,
        )
        Spacer(Modifier.height(10.dp))
        Box(contentAlignment = Alignment.Center) {
            // Faint fixed reference tick at dead-centre.
            Box(Modifier.width(34.dp).height(2.dp).background(Color.White.copy(alpha = 0.3f)))
            // The device horizon — rotates with roll; longer + green when level.
            Box(
                Modifier
                    .width(if (level) 150.dp else 96.dp)
                    .height(2.dp)
                    .rotate(rollDegrees)
                    .background(color),
            )
        }
    }
}

/** Pro manual exposure (EV) slider — the control that makes Pro differ from Photo. */
@Composable
private fun ProExposureSlider(index: Int, range: IntRange, onChange: (Int) -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text("EV", color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.width(10.dp))
        Slider(
            value = index.toFloat(),
            onValueChange = { onChange(it.roundToInt()) },
            valueRange = range.first.toFloat()..range.last.toFloat(),
            steps = (range.last - range.first - 1).coerceAtLeast(0),
            modifier = Modifier.weight(1f),
        )
        Spacer(Modifier.width(10.dp))
        Text(
            if (index > 0) "+$index" else "$index",
            color = Color.White,
            fontSize = 12.sp,
            modifier = Modifier.width(30.dp),
        )
    }
}

/** "Checking…" — the visible safety pause while a capture is scored / re-scanned. */
@Composable
private fun CheckingOverlay() {
    Box(
        Modifier.fillMaxSize().background(Ink.copy(alpha = 0.25f)),
        contentAlignment = Alignment.Center,
    ) {
        Row(
            Modifier
                .clip(RoundedCornerShape(50))
                .background(Ink.copy(alpha = 0.88f))
                .padding(horizontal = 22.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            CircularProgressIndicator(
                color = Sky,
                strokeWidth = 2.dp,
                modifier = Modifier.size(18.dp),
            )
            Spacer(Modifier.width(12.dp))
            Text(
                stringResource(R.string.checking_safety),
                color = Color.White,
                fontSize = 14.sp,
                fontWeight = FontWeight.Medium,
            )
        }
    }
}

/** Opens the device gallery; shows the last shot as a thumbnail once there is one. */
@Composable
private fun GalleryButton(thumb: Bitmap?, onOpen: () -> Unit) {
    Box(
        Modifier
            .size(56.dp)
            .clip(RoundedCornerShape(14.dp))
            .background(Color.White.copy(alpha = 0.12f))
            .border(1.dp, Color.White.copy(alpha = 0.4f), RoundedCornerShape(14.dp))
            .clickable(onClick = onOpen),
        contentAlignment = Alignment.Center,
    ) {
        if (thumb != null) {
            Image(
                bitmap = thumb.asImageBitmap(),
                contentDescription = null,
                contentScale = ContentScale.Crop,
                modifier = Modifier.fillMaxSize(),
            )
        } else {
            Text("▦", color = Color.White, fontSize = 24.sp)
        }
    }
}

/** Flip front/back camera — an icon button (double-tap the preview does this too). */
@Composable
private fun FlipButton(enabled: Boolean, onClick: () -> Unit) {
    Box(
        Modifier
            .size(56.dp)
            .clip(CircleShape)
            .background(Color.White.copy(alpha = if (enabled) 0.12f else 0.05f))
            .border(1.dp, Color.White.copy(alpha = if (enabled) 0.4f else 0.15f), CircleShape)
            .clickable(enabled = enabled, onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Text("⟲", color = Color.White.copy(alpha = if (enabled) 1f else 0.4f), fontSize = 26.sp)
    }
}

/** Compact toggle (left of the shutter) that shows/hides the filter strip. */
@Composable
private fun FilterToggle(open: Boolean, onToggle: () -> Unit) {
    Box(
        Modifier
            .size(56.dp)
            .clip(CircleShape)
            .background(if (open) Sky.copy(alpha = 0.25f) else Color.White.copy(alpha = 0.12f))
            .border(1.dp, if (open) Sky else Color.White.copy(alpha = 0.4f), CircleShape)
            .clickable(onClick = onToggle),
        contentAlignment = Alignment.Center,
    ) {
        Text("✦", color = if (open) Sky else Color.White, fontSize = 22.sp)
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

/**
 * Bake [filter] into a captured JPEG for SAVE (full-res, upright). A filter is a
 * display COLOR transform applied ONLY to a SAFE capture AFTER the gate scored the
 * RAW frame — it can never push content past the safety check. [CameraFilter.None]
 * returns the original bytes unchanged (EXIF intact). For a real look the bitmap is
 * decoded, rotated upright, color-transformed, and re-encoded (orientation baked in,
 * so callers pass rotation 0). Any decode/encode failure returns the original bytes
 * — a photo is never lost over a filter error.
 */
/** A small upright thumbnail of a saved capture for the gallery button. */
private fun decodeThumb(jpeg: ByteArray, rotationDegrees: Int): Bitmap? = runCatching {
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeByteArray(jpeg, 0, jpeg.size, bounds)
    var sample = 1
    while (maxOf(bounds.outWidth, bounds.outHeight) / (sample * 2) >= 160) sample *= 2
    val opts = BitmapFactory.Options().apply { inSampleSize = sample }
    BitmapFactory.decodeByteArray(jpeg, 0, jpeg.size, opts)?.rotatedBy(rotationDegrees)
}.getOrNull()

/** OFF → AUTO → ON → OFF cycle for the flash toggle. */
private fun nextFlashMode(current: Int): Int = when (current) {
    ImageCapture.FLASH_MODE_OFF -> ImageCapture.FLASH_MODE_AUTO
    ImageCapture.FLASH_MODE_AUTO -> ImageCapture.FLASH_MODE_ON
    else -> ImageCapture.FLASH_MODE_OFF
}

private fun applyFilterToJpeg(jpeg: ByteArray, rotationDegrees: Int, filter: CameraFilter): ByteArray {
    if (filter == CameraFilter.None) return jpeg
    return runCatching {
        val decoded = BitmapFactory.decodeByteArray(jpeg, 0, jpeg.size) ?: return jpeg
        val baked = filter.apply(decoded.rotatedBy(rotationDegrees))
        val out = java.io.ByteArrayOutputStream()
        baked.compress(Bitmap.CompressFormat.JPEG, 95, out)
        out.toByteArray()
    }.getOrDefault(jpeg)
}

/**
 * Publish a re-scanned-clean recording to the gallery (MediaStore Movies): copy
 * the app-private temp into a pending entry, then clear IS_PENDING. The caller
 * deletes the temp afterwards and only ever calls this AFTER a clean [VideoGate]
 * re-scan — an unsafe clip is never published.
 */
private fun publishVideoToGallery(context: Context, temp: File): Boolean = runCatching {
    val resolver = context.contentResolver
    val values = ContentValues().apply {
        put(MediaStore.Video.Media.DISPLAY_NAME, "PHBulwark_${System.currentTimeMillis()}.mp4")
        put(MediaStore.Video.Media.MIME_TYPE, "video/mp4")
        put(MediaStore.Video.Media.RELATIVE_PATH, "Movies/PH Bulwark")
        put(MediaStore.Video.Media.IS_PENDING, 1)
    }
    val uri = resolver.insert(MediaStore.Video.Media.EXTERNAL_CONTENT_URI, values)
        ?: return@runCatching false
    resolver.openOutputStream(uri)?.use { out -> temp.inputStream().use { it.copyTo(out) } }
        ?: return@runCatching false
    values.clear()
    values.put(MediaStore.Video.Media.IS_PENDING, 0)
    resolver.update(uri, values, null, null)
    true
}.getOrDefault(false)

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
