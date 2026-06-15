package co.predatorhunters.bulwark.camera

import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import androidx.annotation.StringRes
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * AR "funny face" stickers for the camera.
 *
 * A sticker is a small set of emoji [Part]s positioned RELATIVE to a detected
 * face box (from [FaceDetector]) — ears/crown above the box, glasses across the
 * upper third, a moustache in the lower third. The SAME [drawOn] routine renders
 * both the live preview (a Compose Canvas over the PreviewView) and the baked
 * full-res JPEG (a plain [android.graphics.Canvas]), so what the child sees is
 * what gets saved — exactly the preview/bake-parity discipline the colour filters
 * use.
 *
 * SAFETY ORDERING (non-negotiable, mirrors [CameraFilter]): a sticker is a pure
 * DISPLAY overlay. The live preview Canvas sits on top of the camera surface and
 * is never read back; the bake runs ONLY on a SAFE capture, AFTER [NsfwGate] has
 * already scored the RAW, unstickered frame. A sticker therefore can never change
 * what the safety check sees — the gate never scores a stickered frame.
 *
 * Cross-platform: emoji glyphs + box geometry only (no platform face SDK), so the
 * same look re-implements on a future Apple build with the same UltraFace boxes.
 */
internal enum class ArSticker(
    @StringRes val label: Int,
    /** Tile glyph shown in the selector strip. */
    val tile: String,
    private val parts: List<Part>,
) {
    /** No sticker — the AR overlay draws nothing. */
    None(R.string.ar_none, "🚫", emptyList()),

    /** Dog ears + nose. */
    Dog(
        R.string.ar_dog, "🐶",
        listOf(
            Part("🐶", relX = 0.5f, relY = -0.15f, scale = 0.7f), // floppy face above
            Part("🐽", relX = 0.5f, relY = 0.62f, scale = 0.34f), // snout, lower third
        ),
    ),

    /** Cool sunglasses across the eyes (upper third). */
    Shades(
        R.string.ar_shades, "🕶",
        listOf(Part("🕶", relX = 0.5f, relY = 0.34f, scale = 0.92f)),
    ),

    /** Curly moustache in the lower third. */
    Moustache(
        R.string.ar_moustache, "🥸",
        listOf(Part("〰", relX = 0.5f, relY = 0.72f, scale = 0.7f)),
    ),

    /** Golden crown above the head. */
    Crown(
        R.string.ar_crown, "👑",
        listOf(Part("👑", relX = 0.5f, relY = -0.18f, scale = 0.6f)),
    ),

    /** Bunny ears above the head. */
    Bunny(
        R.string.ar_bunny, "🐰",
        listOf(Part("🐰", relX = 0.5f, relY = -0.2f, scale = 0.62f)),
    ),

    /** Cat ears + whiskers. */
    Cat(
        R.string.ar_cat, "🐱",
        listOf(Part("🐱", relX = 0.5f, relY = -0.12f, scale = 0.66f)),
    ),
    ;

    val isNone: Boolean get() = this == None

    /**
     * One emoji placed relative to the face box.
     *  * [relX]/[relY] — anchor as a fraction of the box (0,0 = top-left corner,
     *    1,1 = bottom-right); values <0 or >1 sit outside the box (e.g. ears above).
     *  * [scale] — glyph height as a fraction of the box height.
     */
    data class Part(val glyph: String, val relX: Float, val relY: Float, val scale: Float)

    /**
     * Draw this sticker for [faces] onto [canvas]. Boxes are NORMALISED `[0,1]`
     * corners; [canvasW]/[canvasH] are the pixel size of the target surface (the
     * preview Canvas or the full-res bitmap), so the same call works for both.
     * Pure painting — never reads pixels back.
     */
    fun drawOn(canvas: Canvas, faces: List<RectF>, canvasW: Float, canvasH: Float) {
        if (parts.isEmpty() || faces.isEmpty()) return
        val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply { textAlign = Paint.Align.CENTER }
        for (face in faces) {
            val bx = face.left * canvasW
            val by = face.top * canvasH
            val bw = (face.right - face.left) * canvasW
            val bh = (face.bottom - face.top) * canvasH
            for (part in parts) {
                val size = (bh * part.scale).coerceAtLeast(1f)
                paint.textSize = size
                val cx = bx + part.relX * bw
                // relY anchors the glyph's VERTICAL CENTRE; convert to a text
                // baseline (drawText draws from the baseline up).
                val cy = by + part.relY * bh
                val fm = paint.fontMetrics
                val baseline = cy - (fm.ascent + fm.descent) / 2f
                canvas.drawText(part.glyph, cx, baseline, paint)
            }
        }
    }

    companion object {
        /** The strip order shown to the child. */
        val strip: List<ArSticker> = entries.toList()
    }
}

/**
 * Live-preview AR overlay: draws the selected [sticker] on each detected face.
 *
 * [faces] are normalised `[0,1]` boxes in UPRIGHT space (the analyzer rotates the
 * frame before detection). [mirrored] is true for the front camera, whose preview
 * is horizontally flipped — we mirror the boxes so a sticker tracks the child's
 * real position instead of sliding the wrong way (kids live in selfie mode).
 *
 * The Canvas fills the preview; PreviewView's default FILL_CENTER centre-crops, so
 * the linear [0,1]->px mapping is approximate — fine for fun stickers.
 */
@Composable
internal fun ArOverlay(
    sticker: ArSticker,
    faces: List<RectF>,
    mirrored: Boolean,
    modifier: Modifier = Modifier,
) {
    if (sticker.isNone || faces.isEmpty()) return
    androidx.compose.foundation.Canvas(modifier) {
        val mapped = if (mirrored) faces.map { mirrorX(it) } else faces
        drawIntoCanvas { c ->
            sticker.drawOn(c.nativeCanvas, mapped, size.width, size.height)
        }
    }
}

/** Mirror a normalised box across the vertical centre line. */
internal fun mirrorX(box: RectF): RectF = RectF(1f - box.right, box.top, 1f - box.left, box.bottom)

/**
 * Horizontally-scrollable AR sticker selector — the same visual language as the
 * colour [FilterStrip]: rounded glass tiles, a bright Accent ring on the pick.
 */
@Composable
internal fun ArStickerStrip(
    selected: ArSticker,
    onSelect: (ArSticker) -> Unit,
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
        ArSticker.strip.forEach { sticker ->
            ArStickerTile(
                sticker = sticker,
                selected = sticker == selected,
                onClick = { onSelect(sticker) },
            )
        }
    }
}

@Composable
private fun ArStickerTile(sticker: ArSticker, selected: Boolean, onClick: () -> Unit) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Box(
            Modifier
                .size(54.dp)
                .clip(RoundedCornerShape(16.dp))
                .background(if (selected) Cam.AccentSoft else Cam.GlassSoft)
                .border(if (selected) 3.dp else 1.dp, if (selected) Cam.Accent else Cam.Hairline, RoundedCornerShape(16.dp))
                .clickable(onClick = onClick),
            contentAlignment = Alignment.Center,
        ) {
            androidx.compose.material3.Text(sticker.tile, fontSize = 26.sp)
        }
        Spacer(Modifier.height(6.dp))
        androidx.compose.material3.Text(
            stringResource(sticker.label),
            color = if (selected) Cam.Accent else Cam.OnGlassDim,
            fontSize = 11.sp,
            fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
        )
    }
}
