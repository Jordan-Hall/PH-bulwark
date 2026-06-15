package co.predatorhunters.bulwark.camera

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Rect
import android.graphics.RectF
import androidx.camera.core.CameraInfo
import androidx.camera.core.CameraSelector
import androidx.camera.core.ConcurrentCamera
import androidx.camera.core.Preview
import androidx.camera.core.UseCaseGroup
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.LifecycleOwner

/**
 * Front + back cameras LIVE at once (Samsung "dual" / director's-view) via
 * CameraX [ConcurrentCamera]. Hardware-gated and STRICTLY additive: when the
 * device can't run two cameras concurrently — or a concurrent bind fails — the
 * Dual option is hidden/disabled and the normal single-camera path is untouched
 * (the toggle just never appears). Nothing here can crash the single path.
 *
 * SAFETY (the whole point of this app): a dual capture is gated EXACTLY like a
 * single one, and in fact more strictly. The composite (back full-frame + front
 * PiP inset) cannot be scored as one image without weakening the gate — the
 * front inset would shrink to ~120 px once [NsfwGate] scales the whole frame to
 * 384, so flagged inset content could score under threshold. Instead each source
 * bitmap is scored INDEPENDENTLY at full gate resolution (see [gateDualSources]);
 * BOTH must pass before anything is composited or written. Fail-closed: a null /
 * unscorable / flagged source means NO save, same posture as the single path.
 */
internal object DualCamera {

    /**
     * A concurrent combination that pairs a BACK lens with a FRONT lens, if the
     * device offers one. CameraX reports the supported concurrent camera-info
     * groupings; we just need one that contains both facings so the PiP can show
     * back + front together.
     */
    fun isSupported(provider: ProcessCameraProvider): Boolean =
        runCatching { findDualCombo(provider) != null }.getOrDefault(false)

    /**
     * True if [provider] lists a concurrent combination containing both a back
     * and a front lens. Returns null when concurrent dual isn't available (no
     * combos, or no combo with both facings) — the caller then hides the toggle.
     */
    private fun findDualCombo(provider: ProcessCameraProvider): List<CameraInfo>? {
        val combos = runCatching { provider.availableConcurrentCameraInfos }
            .getOrNull() ?: return null
        return combos.firstOrNull { combo ->
            combo.any { it.lensFacing == CameraSelector.LENS_FACING_BACK } &&
                combo.any { it.lensFacing == CameraSelector.LENS_FACING_FRONT }
        }
    }

    /**
     * Bind the back + front cameras concurrently, each with its own
     * [UseCaseGroup] (no target resolution — concurrent mode caps resolution, so
     * let CameraX choose). Returns the live [ConcurrentCamera] on success, or
     * null on ANY failure (unsupported, bind rejected, etc.) so the caller falls
     * back to the single-camera path. The single path is never disturbed here.
     *
     * NSFW live shield: the caller attaches an
     * [androidx.camera.core.ImageAnalysis] to [backGroup] so the advisory
     * preview-shield keeps scoring while dual is on. If concurrent limits can't
     * accept that extra use case, this bind simply returns null and the caller
     * drops to single-camera; the authoritative capture gate ([gateDualSources])
     * protects every save either way.
     */
    fun bind(
        provider: ProcessCameraProvider,
        lifecycleOwner: LifecycleOwner,
        backPreview: Preview,
        frontPreview: Preview,
        backGroup: UseCaseGroup,
        frontGroup: UseCaseGroup,
    ): ConcurrentCamera? = runCatching {
        provider.unbindAll()
        val back = ConcurrentCamera.SingleCameraConfig(
            CameraSelector.Builder().requireLensFacing(CameraSelector.LENS_FACING_BACK).build(),
            backGroup,
            lifecycleOwner,
        )
        val front = ConcurrentCamera.SingleCameraConfig(
            CameraSelector.Builder().requireLensFacing(CameraSelector.LENS_FACING_FRONT).build(),
            frontGroup,
            lifecycleOwner,
        )
        provider.bindToLifecycle(listOf(back, front))
    }.getOrNull()

    /**
     * AUTHORITATIVE dual capture gate. Scores each source bitmap on its own at
     * full gate resolution — STRICTLY stronger than scoring the composite (the
     * front inset is never down-shrunk before scoring). Returns [Notice.Saved]
     * only when BOTH sources score safe; otherwise the matching fail-closed
     * notice. NOTHING is written here — the caller composites + saves ONLY on a
     * null return (meaning "both safe, proceed").
     *
     * @return a fail-closed [Notice] to surface, or null when both sources are
     *   safe (the caller then composites + saves).
     */
    fun gateDualSources(gate: NsfwGate, back: Bitmap?, front: Bitmap?): Notice? {
        // A missing live frame is unscorable -> fail closed (do not save).
        if (back == null || front == null) return Notice.CheckFailed
        for (src in listOf(back, front)) {
            val verdict = runCatching { gate.score(src) }
            when {
                verdict.isFailure -> return Notice.CheckFailed
                gate.shouldBlock(verdict.getOrThrow()) -> return Notice.BlockedNsfw
            }
        }
        return null // both safe — caller may composite + save
    }

    /**
     * Composite the two SAFE source frames into the saved PiP image: [large]
     * fills the frame, [small] is drawn as a rounded inset in a corner (the same
     * picture-in-picture the child sees live). Called ONLY after
     * [gateDualSources] cleared both sources, so neither pixel here was unscored.
     */
    fun composite(large: Bitmap, small: Bitmap): Bitmap {
        val out = Bitmap.createBitmap(large.width, large.height, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(out)
        canvas.drawBitmap(large, 0f, 0f, null)
        // Inset ~30% of the long edge, with a small margin, bottom-right.
        val insetW = (large.width * 0.30f)
        val insetH = insetW * (small.height.toFloat() / small.width.toFloat())
        val margin = large.width * 0.04f
        val left = large.width - insetW - margin
        val top = large.height - insetH - margin
        val dst = RectF(left, top, left + insetW, top + insetH)
        val radius = insetW * 0.10f
        val paint = Paint(Paint.ANTI_ALIAS_FLAG)
        // Clip to a rounded rect so the inset matches the live PiP corner radius.
        canvas.save()
        val clipPath = android.graphics.Path().apply { addRoundRect(dst, radius, radius, android.graphics.Path.Direction.CW) }
        canvas.clipPath(clipPath)
        canvas.drawBitmap(small, Rect(0, 0, small.width, small.height), dst, paint)
        canvas.restore()
        // A subtle hairline border around the inset (display polish only).
        val border = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            style = Paint.Style.STROKE
            strokeWidth = large.width * 0.004f
            color = android.graphics.Color.argb(140, 255, 255, 255)
        }
        canvas.drawRoundRect(dst, radius, radius, border)
        return out
    }
}

/**
 * Live picture-in-picture layout for dual mode: [largePreview] fills the frame,
 * [smallPreview] is a rounded, tappable inset in the bottom-right. Tapping the
 * inset swaps which camera is large (via [onSwap]). Both [PreviewView]s are
 * created/owned by the caller (and kept stable across recompositions) so the
 * concurrent surfaces aren't torn down by Compose. No filter/RenderEffect is
 * ever applied here — the gate scores the raw frames the previews show.
 */
@Composable
internal fun DualPreviewLayout(
    largePreview: PreviewView,
    smallPreview: PreviewView,
    onSwap: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val swapCd = stringResource(R.string.cd_dual_swap)
    Box(modifier.fillMaxSize()) {
        AndroidView(factory = { largePreview }, modifier = Modifier.fillMaxSize())
        Box(
            Modifier
                .align(Alignment.BottomEnd)
                .padding(end = 16.dp, bottom = 150.dp)
                .size(width = 116.dp, height = 168.dp)
                .clip(RoundedCornerShape(18.dp))
                .background(Color.Black)
                .border(1.5.dp, Color.White.copy(alpha = 0.6f), RoundedCornerShape(18.dp))
                .clickable(onClick = onSwap)
                .semantics { contentDescription = swapCd },
        ) {
            AndroidView(factory = { smallPreview }, modifier = Modifier.fillMaxSize())
        }
    }
}
