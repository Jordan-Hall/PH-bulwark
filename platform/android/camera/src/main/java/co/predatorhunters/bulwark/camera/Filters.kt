package co.predatorhunters.bulwark.camera

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.ColorMatrix
import android.graphics.ColorMatrixColorFilter
import android.graphics.Paint
import android.graphics.RenderEffect
import android.graphics.Shader
import android.os.Build
import androidx.annotation.StringRes

/**
 * Samsung-style color "looks" for the camera.
 *
 * Each look is ONE [android.graphics.ColorMatrix] expressed once and reused two
 * ways so the preview and the saved photo match exactly:
 *  * the live preview applies it as a [RenderEffect] on the PreviewView (API 31+;
 *    older devices simply preview unfiltered — the SAVED photo is still filtered);
 *  * the saved JPEG bakes it into the bitmap with a [ColorMatrixColorFilter].
 *
 * SAFETY ORDERING (non-negotiable): a filter is a *display* color transform only.
 * It is applied to the live preview and baked into the output AFTER the NSFW gate
 * has already scored the RAW, unfiltered capture. A filter therefore can never
 * change what the safety check sees — it cannot push content past the classifier.
 * The live preview shield and the video frame sampling also score raw analyzer
 * frames, which are a separate camera use case the preview filter never touches.
 */
internal enum class CameraFilter(@StringRes val label: Int, val matrix: ColorMatrix?) {
    /** No transform — identity. The saved photo is the unaltered capture. */
    None(R.string.filter_none, null),

    /** Punchy saturation + a touch of contrast. */
    Vivid(R.string.filter_vivid, ColorMatrix().apply {
        setSaturation(1.5f)
        postConcat(contrast(1.12f))
    }),

    /** Neutral black & white. */
    Mono(R.string.filter_mono, ColorMatrix().apply { setSaturation(0f) }),

    /** Warm golden cast (lift reds, ease blues). */
    Warm(R.string.filter_warm, channelScale(r = 1.12f, g = 1.04f, b = 0.88f)),

    /** Cool blue cast. */
    Cool(R.string.filter_cool, channelScale(r = 0.90f, g = 1.02f, b = 1.14f)),

    /** Soft, low-contrast film fade. */
    Fade(R.string.filter_fade, ColorMatrix().apply {
        setSaturation(0.82f)
        postConcat(contrast(0.85f))
        postConcat(brightness(14f))
    }),

    /** High-contrast monochrome. */
    Noir(R.string.filter_noir, ColorMatrix().apply {
        setSaturation(0f)
        postConcat(contrast(1.35f))
    });

    /**
     * A [RenderEffect] for the PreviewView (null on the None look or below API 31).
     * Callers guard the API level; this returns null when no effect should apply.
     */
    fun renderEffect(): RenderEffect? {
        if (matrix == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return null
        return RenderEffect.createColorFilterEffect(ColorMatrixColorFilter(ColorMatrix(matrix)))
    }

    /**
     * Bake this look into [source], returning a new ARGB_8888 bitmap. The None
     * look returns the source unchanged. Used on SAFE captures only (after the
     * gate passes) so the saved file matches the previewed look.
     */
    fun apply(source: Bitmap): Bitmap {
        val m = matrix ?: return source
        val out = Bitmap.createBitmap(source.width, source.height, Bitmap.Config.ARGB_8888)
        val paint = Paint(Paint.FILTER_BITMAP_FLAG).apply {
            colorFilter = ColorMatrixColorFilter(ColorMatrix(m))
        }
        Canvas(out).drawBitmap(source, 0f, 0f, paint)
        return out
    }

    companion object {
        /** The strip order shown to the child. */
        val strip: List<CameraFilter> = entries.toList()

        /** Per-channel contrast around mid-grey (128). */
        private fun contrast(c: Float): ColorMatrix {
            val t = (1f - c) * 128f
            return ColorMatrix(
                floatArrayOf(
                    c, 0f, 0f, 0f, t,
                    0f, c, 0f, 0f, t,
                    0f, 0f, c, 0f, t,
                    0f, 0f, 0f, 1f, 0f,
                ),
            )
        }

        /** Uniform brightness add. */
        private fun brightness(b: Float): ColorMatrix = ColorMatrix(
            floatArrayOf(
                1f, 0f, 0f, 0f, b,
                0f, 1f, 0f, 0f, b,
                0f, 0f, 1f, 0f, b,
                0f, 0f, 0f, 1f, 0f,
            ),
        )

        /** Independent per-channel scale (color cast). */
        private fun channelScale(r: Float, g: Float, b: Float): ColorMatrix = ColorMatrix(
            floatArrayOf(
                r, 0f, 0f, 0f, 0f,
                0f, g, 0f, 0f, 0f,
                0f, 0f, b, 0f, 0f,
                0f, 0f, 0f, 1f, 0f,
            ),
        )
    }
}
