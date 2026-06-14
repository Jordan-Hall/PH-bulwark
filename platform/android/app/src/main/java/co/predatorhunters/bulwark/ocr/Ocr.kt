package co.predatorhunters.bulwark.ocr

import android.content.Context
import android.graphics.Bitmap
import android.util.Log
import com.googlecode.tesseract.android.TessBaseAPI
import java.io.File

/**
 * Conventional on-device OCR — the FOSS replacement for the removed ML Kit
 * text-recognition.
 *
 * Uses **Tesseract** (`tesseract4android`, Apache-2.0) to extract text drawn as
 * BITMAPS that the accessibility view-tree cannot expose (canvas-rendered chat,
 * image captions, stylised text) and feeds it to the SAME `bulwark-text`
 * grooming detector the live-text path uses. This is plain glyph recognition —
 * **never a vision-LLM, never a classifier, never a proprietary SDK**.
 *
 * **Fail-OPEN.** If `eng.traineddata` was not provisioned (e.g. an offline
 * build), or init fails, [recognize] returns `null` and the caller silently
 * falls back to the view-tree text path. OCR is an ADDITIVE text source, never a
 * gate — its absence must never weaken or block the existing protection.
 *
 * In-memory only: the screenshot bitmap and the recognised text live only long
 * enough to reach the grooming detector; nothing is persisted (no-media
 * invariant). The engine is lazily initialised once and reused.
 */
object Ocr {
    private const val TAG = "BulwarkOcr"
    private const val LANG = "eng"

    @Volatile
    private var api: TessBaseAPI? = null

    /** `true` once init has been attempted (success or failure) — never retry a
     *  hard failure on every frame. */
    @Volatile
    private var initAttempted = false

    /** Lazily build the Tesseract engine, staging the bundled traineddata asset
     *  into app-private storage on first use. Returns `null` (fail-open) if the
     *  language data is missing or init fails. */
    @Synchronized
    private fun engine(ctx: Context): TessBaseAPI? {
        api?.let { return it }
        if (initAttempted) return null
        initAttempted = true
        return runCatching {
            // Tesseract expects <dataPath>/tessdata/<lang>.traineddata.
            val dataPath = File(ctx.filesDir, "tess")
            val tessdata = File(dataPath, "tessdata").apply { mkdirs() }
            val trained = File(tessdata, "$LANG.traineddata")
            if (!trained.exists() || trained.length() < 1_000_000L) {
                // Stage the build-time-fetched asset (absent → throws → fail-open).
                ctx.assets.open("tessdata/$LANG.traineddata").use { input ->
                    trained.outputStream().use { output -> input.copyTo(output) }
                }
            }
            val t = TessBaseAPI()
            check(t.init(dataPath.absolutePath, LANG)) { "TessBaseAPI.init returned false" }
            api = t
            Log.i(TAG, "Tesseract OCR ready ($LANG)")
            t
        }.onFailure {
            Log.i(TAG, "OCR unavailable — failing open (view-tree text path unaffected): ${it.message}")
        }.getOrNull()
    }

    /**
     * Recognise text in [bitmap]. Returns the trimmed text, or `null` on any
     * failure / when OCR is unavailable (fail-open). Never throws.
     */
    fun recognize(ctx: Context, bitmap: Bitmap): String? = runCatching {
        val t = engine(ctx) ?: return null
        synchronized(t) {
            t.setImage(bitmap)
            val text = t.utF8Text?.trim()
            // Release the native image reference promptly; keep the engine.
            runCatching { t.clear() }
            // CONTENT-FREE diagnostic: log the CHAR COUNT only so on-device
            // validation can confirm OCR is extracting text (and how much) without
            // ever logging the text itself (no-media invariant). 0 chars = OCR ran
            // but the frame held no readable glyphs.
            Log.i(TAG, "OCR extracted ${text?.length ?: 0} chars")
            text?.takeIf { it.isNotEmpty() }
        }
    }.onFailure { Log.i(TAG, "OCR recognise failed (fail-open): ${it.message}") }.getOrNull()
}
