package co.predatorhunters.bulwark.camera

import android.hardware.camera2.CaptureRequest
import androidx.annotation.OptIn
import androidx.annotation.StringRes
import androidx.camera.camera2.interop.Camera2CameraControl
import androidx.camera.camera2.interop.CaptureRequestOptions
import androidx.camera.camera2.interop.ExperimentalCamera2Interop
import androidx.camera.core.CameraControl
import androidx.camera.core.ImageCapture

/**
 * The camera's shooting modes, shown in a swipeable carousel (Samsung-style).
 *
 * Each mode is a REAL capture-pipeline difference, not just a label:
 *
 *  * [Photo]   — balanced still capture (minimize latency).
 *  * [Portrait]— subject-isolation framing; biases the sensor toward a shallow
 *               look via the Camera2 FACE_PRIORITY scene mode + quality capture.
 *  * [Night]   — low-light: the NIGHT scene mode + maximize-quality capture so a
 *               dim scene gets the longer, cleaner exposure path.
 *  * [Video]   — switches the bound use-cases to VideoCapture (see CameraScreen);
 *               filters and the still-only controls hide.
 *  * [Pro]     — manual controls (Panasonic-style): exposure compensation always,
 *               plus optional manual ISO / shutter through Camera2 when the device
 *               reports them. Everything degrades gracefully on hardware that
 *               can't honor a request.
 *
 * SAFETY IS MODE-INDEPENDENT: every mode routes captures through the same
 * [NsfwGate] before anything is written (the gate is bound as ImageAnalysis in
 * still modes and VideoCapture is re-scanned in video mode). A mode only changes
 * how the frame is exposed/encoded — never whether it is checked.
 */
internal enum class CameraMode(
    @StringRes val label: Int,
    /** True for the still-photo modes that use ImageCapture + the filter strip. */
    val isStill: Boolean,
) {
    Photo(R.string.mode_photo, isStill = true),
    Portrait(R.string.mode_portrait, isStill = true),
    Night(R.string.mode_night, isStill = true),
    Video(R.string.mode_video, isStill = false),
    Pro(R.string.mode_pro, isStill = true),
    ;

    /** True only for the dedicated video mode (the shutter morphs to record). */
    val isVideo: Boolean get() = this == Video

    /** Whether the live filter strip applies to this mode (stills only). */
    val supportsFilters: Boolean get() = isStill

    /** Whether the manual Pro tray is shown. */
    val isPro: Boolean get() = this == Pro

    /** ImageCapture capture-mode tuned per still mode. */
    fun captureMode(): Int = when (this) {
        Night, Portrait -> ImageCapture.CAPTURE_MODE_MAXIMIZE_QUALITY
        else -> ImageCapture.CAPTURE_MODE_MINIMIZE_LATENCY
    }

    companion object {
        /**
         * Display order for the mode strip — the single, standard photo/video/mode
         * switch (iOS/Samsung pattern). Photo first (the default) with Video right
         * beside it, then the specialised still modes. Selecting Video morphs the
         * shutter to record; there is no separate flanking PHOTO/VIDEO label.
         */
        val stripOrder: List<CameraMode> = listOf(Photo, Video, Portrait, Night, Pro)
        val default: CameraMode = Photo

        /**
         * Apply this mode's baseline Camera2 capture-request hints. Best-effort:
         * a device that doesn't support a hint simply ignores it, and any error
         * is swallowed (a mode must never break the camera). [exposureIndex] is
         * the Pro tray's exposure-compensation slider value (0 = neutral).
         */
        @OptIn(ExperimentalCamera2Interop::class)
        fun applySceneHints(
            mode: CameraMode,
            cameraControl: CameraControl,
            isoOverride: Int? = null,
        ) {
            val c2 = runCatching { Camera2CameraControl.from(cameraControl) }.getOrNull() ?: return
            val opts = CaptureRequestOptions.Builder()
            when (mode) {
                CameraMode.Night -> {
                    opts.setCaptureRequestOption(
                        CaptureRequest.CONTROL_SCENE_MODE,
                        CaptureRequest.CONTROL_SCENE_MODE_NIGHT,
                    )
                    opts.setCaptureRequestOption(
                        CaptureRequest.CONTROL_MODE,
                        CaptureRequest.CONTROL_MODE_USE_SCENE_MODE,
                    )
                }
                CameraMode.Portrait -> {
                    opts.setCaptureRequestOption(
                        CaptureRequest.CONTROL_SCENE_MODE,
                        CaptureRequest.CONTROL_SCENE_MODE_FACE_PRIORITY,
                    )
                    opts.setCaptureRequestOption(
                        CaptureRequest.CONTROL_MODE,
                        CaptureRequest.CONTROL_MODE_USE_SCENE_MODE,
                    )
                }
                CameraMode.Pro -> {
                    // Manual ISO when the Pro tray supplies one; otherwise leave
                    // the sensor on auto so exposure compensation still applies.
                    if (isoOverride != null) {
                        opts.setCaptureRequestOption(
                            CaptureRequest.CONTROL_AE_MODE,
                            CaptureRequest.CONTROL_AE_MODE_OFF,
                        )
                        opts.setCaptureRequestOption(CaptureRequest.SENSOR_SENSITIVITY, isoOverride)
                    } else {
                        opts.setCaptureRequestOption(
                            CaptureRequest.CONTROL_AE_MODE,
                            CaptureRequest.CONTROL_AE_MODE_ON,
                        )
                    }
                }
                else -> {
                    // Photo / Video: clear back to fully automatic.
                    opts.setCaptureRequestOption(
                        CaptureRequest.CONTROL_MODE,
                        CaptureRequest.CONTROL_MODE_AUTO,
                    )
                }
            }
            runCatching { c2.setCaptureRequestOptions(opts.build()) }
        }
    }
}
