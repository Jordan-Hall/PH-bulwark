package co.predatorhunters.bulwark.camera

import android.content.ContentValues
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * PH Bulwark Camera — a usable camera for the child's own device where every
 * capture is checked by the on-device [NsfwGate] BEFORE anything is written.
 *
 * Modes (from the launching intent):
 *  * launcher / ACTION_STILL_IMAGE_CAMERA -> normal camera, safe photos go to
 *    MediaStore ("Pictures/PH Bulwark");
 *  * ACTION_IMAGE_CAPTURE -> photo-for-result: a safe capture is written to the
 *    caller's EXTRA_OUTPUT (or returned as the standard "data" thumbnail);
 *    a blocked capture is never delivered;
 *  * ACTION_VIDEO_CAPTURE / VIDEO_CAMERA -> calm "video is coming soon" stub
 *    returning RESULT_CANCELED (an unfiltered video path is not allowed).
 */
class CameraActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Screenshot / screen-record protection: FLAG_SECURE blacks this window
        // out of screenshots, screen recordings, the recents thumbnail, and
        // non-secure displays/casting. Set BEFORE setContent so no frame is
        // ever capturable. Compose note: this is a WINDOW flag — everything in
        // this activity is covered, but a Compose Dialog creates a NEW window
        // that does NOT inherit it, so this app deliberately uses in-window
        // overlays only (any future Dialog must set
        // DialogProperties(securePolicy = SecureFlagPolicy.SecureOn)).
        // HONEST LIMIT: FLAG_SECURE cannot stop a second physical device from
        // photographing the screen.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )

        val action = intent?.action
        val captureForResult = action == MediaStore.ACTION_IMAGE_CAPTURE
        val videoRequested = action == MediaStore.ACTION_VIDEO_CAPTURE ||
            action == MediaStore.INTENT_ACTION_VIDEO_CAMERA
        val outputUri = if (captureForResult) readOutputUri() else null

        setContent {
            BulwarkCameraTheme {
                Surface(Modifier.fillMaxSize(), color = Mist) {
                    if (videoRequested) {
                        VideoStubScreen(
                            onDone = {
                                setResult(RESULT_CANCELED)
                                finish()
                            },
                        )
                    } else {
                        var gate by remember { mutableStateOf<NsfwGate?>(null) }
                        var gateLoading by remember { mutableStateOf(true) }
                        LaunchedEffect(Unit) {
                            gate = withContext(Dispatchers.IO) { NsfwGate.obtain(applicationContext) }
                            gateLoading = false
                        }
                        CameraScreen(
                            gate = gate,
                            gateLoading = gateLoading,
                            captureForResult = captureForResult,
                            onSaveToGallery = ::saveToGallery,
                            onDeliverResult = { jpeg, rotation ->
                                deliverCaptureResult(jpeg, rotation, outputUri)
                            },
                            onCancel = {
                                if (captureForResult) setResult(RESULT_CANCELED)
                                finish()
                            },
                        )
                    }
                }
            }
        }
    }

    private fun readOutputUri(): Uri? = if (Build.VERSION.SDK_INT >= 33) {
        intent.getParcelableExtra(MediaStore.EXTRA_OUTPUT, Uri::class.java)
    } else {
        @Suppress("DEPRECATION")
        intent.getParcelableExtra(MediaStore.EXTRA_OUTPUT)
    }

    /**
     * SAFE captures only (the gate has already passed these bytes): write to
     * MediaStore under "Pictures/PH Bulwark" with the IS_PENDING handshake.
     * Returns false on any failure — the UI tells the child to try again.
     */
    private fun saveToGallery(jpeg: ByteArray): Boolean = try {
        val values = ContentValues().apply {
            put(MediaStore.Images.Media.DISPLAY_NAME, "PHB_${System.currentTimeMillis()}.jpg")
            put(MediaStore.Images.Media.MIME_TYPE, "image/jpeg")
            put(MediaStore.Images.Media.RELATIVE_PATH, "${Environment.DIRECTORY_PICTURES}/PH Bulwark")
            put(MediaStore.Images.Media.IS_PENDING, 1)
        }
        val collection = MediaStore.Images.Media.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)
        val uri = contentResolver.insert(collection, values)
        if (uri == null) {
            false
        } else {
            val written = contentResolver.openOutputStream(uri)?.use { it.write(jpeg); true } ?: false
            if (written) {
                values.clear()
                values.put(MediaStore.Images.Media.IS_PENDING, 0)
                contentResolver.update(uri, values, null, null)
                true
            } else {
                contentResolver.delete(uri, null, null)
                false
            }
        }
    } catch (_: Throwable) {
        false
    }

    /**
     * The ACTION_IMAGE_CAPTURE result contract, for SAFE captures only:
     * write to EXTRA_OUTPUT when the caller provided one, else return the
     * standard small "data" thumbnail. Any failure cancels (never partial).
     */
    private fun deliverCaptureResult(jpeg: ByteArray, rotationDegrees: Int, outputUri: Uri?) {
        try {
            if (outputUri != null) {
                val written =
                    contentResolver.openOutputStream(outputUri)?.use { it.write(jpeg); true } ?: false
                setResult(if (written) RESULT_OK else RESULT_CANCELED)
            } else {
                val thumb = thumbnail(jpeg, rotationDegrees)
                setResult(RESULT_OK, Intent("inline-data").putExtra("data", thumb))
            }
        } catch (_: Throwable) {
            setResult(RESULT_CANCELED)
        }
        finish()
    }

    /** Small upright bitmap for the no-EXTRA_OUTPUT contract (binder-size safe). */
    private fun thumbnail(jpeg: ByteArray, rotationDegrees: Int): Bitmap {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(jpeg, 0, jpeg.size, bounds)
        var sample = 1
        while (maxOf(bounds.outWidth, bounds.outHeight) / (sample * 2) >= 320) sample *= 2
        val opts = BitmapFactory.Options().apply { inSampleSize = sample }
        val bmp = BitmapFactory.decodeByteArray(jpeg, 0, jpeg.size, opts)
            ?: throw IllegalStateException("could not decode thumbnail")
        return bmp.rotatedBy(rotationDegrees)
    }
}
