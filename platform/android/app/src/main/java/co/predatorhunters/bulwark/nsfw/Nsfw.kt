package co.predatorhunters.bulwark.nsfw

import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Rect
import android.util.Log
import java.io.File
import java.nio.FloatBuffer
import kotlin.math.exp

/**
 * On-device sexual/explicit-imagery classifier for the accessibility agent —
 * the FOSS, no-VPN path that protects against adult images rendered on screen.
 *
 * Runs the SAME license-pinned classifier the engine bundles and the Camera app
 * uses (`crates/bulwark-vision/models/nsfw_detector.onnx` — AdamCodd
 * `vit-base-nsfw-detector`, Apache-2.0, int8 ONNX), copied into this APK's
 * assets at build time (`build.gradle.kts` `copyNsfwModel`) and executed with
 * ONNX Runtime Android (MIT). Pre/post-processing mirrors the engine
 * (`crates/bulwark-vision/src/preprocess.rs` — 384x384, `[-1,1]` "half"
 * normalization, NCHW; `postprocess.rs::nsfw_probability` — softmax, LAST class
 * = nsfw, sigmoid for a 1-logit head); the block threshold is
 * `VisionConfig::default().nsfw_threshold`. On-device detection therefore cannot
 * drift from the engine's / Camera's. A vision **classifier**, never an LLM.
 *
 * Execution provider follows the on-device-AI doctrine: try the NNAPI
 * accelerator, VALIDATE it with a warmup inference, else CPU. Both fully
 * on-device.
 *
 * **FAIL-OPEN** (the opposite of the Camera's [NsfwGate], which is the only
 * filter so it fails closed). Here the classifier is an ADDITIVE protection
 * layer on top of the view-tree text / OCR grooming paths and the VPN image
 * filter. If the model asset or runtime is missing, [obtain] returns `null`;
 * [score] catches every failure and returns `0.0f` (+ a content-free log) rather
 * than throwing — a dark classifier must NEVER crash the service or break the
 * live text protection.
 *
 * NO-MEDIA INVARIANT: frames and tile crops are scored in memory only and are
 * never persisted, hashed for storage, logged, or sent. The caller recycles
 * every bitmap. CSAM-specific reporting rides the separate engine hash/report
 * path — a single-probability classifier cannot single out illegal imagery, so
 * it is out of scope here; a high score covers the region and signals the
 * guardian via the existing redacted-alert path.
 */
class Nsfw private constructor(
    private val session: OrtSession,
    private val inputName: String,
    /** "nnapi" or "cpu" — content-free, used only for a one-time log line. */
    val engine: String,
) {

    /** True when [score] is at/above the engine-default block threshold. */
    fun shouldBlock(score: Float): Boolean = score >= BLOCK_THRESHOLD

    /**
     * NSFW probability in `[0,1]` for an upright bitmap, or `0.0f` on ANY failure
     * (fail-open — never throws). Synchronized: inference is the bottleneck, not
     * the lock (mirrors the engine's `Mutex<Session>`).
     */
    @Synchronized
    fun score(bitmap: Bitmap): Float = runCatching { infer(bitmap) }
        .onFailure { Log.i(TAG, "NSFW score failed (fail-open): ${it.message}") }
        .getOrDefault(0f)

    /**
     * Raw inference — **THROWS** on any failure (tensor/runtime/empty output).
     * The public [score] wraps this fail-open (returns `0f`); the warmup in
     * [create] calls it DIRECTLY so a built-but-unrunnable provider (e.g. an
     * NNAPI session that constructs but cannot run the model) is rejected and we
     * fall back to CPU — instead of caching a dark session whose every score is
     * `0f`, which would silently disable all image cover-up on that device.
     */
    private fun infer(bitmap: Bitmap): Float {
        val input = preprocess(bitmap)
        OnnxTensor.createTensor(ORT, FloatBuffer.wrap(input), SHAPE).use { tensor ->
            session.run(mapOf(inputName to tensor)).use { out ->
                val logits = extractLogits(out[0].value)
                check(logits.isNotEmpty()) { "model output was not scorable" }
                return nsfwProbability(logits)
            }
        }
    }

    /**
     * Localize sexual/explicit imagery by **tiling**. The bundled model is
     * whole-image (one probability, no bounding boxes), so we split [bitmap] into
     * an [grid]x[grid] grid, score each tile, and return the bounding box of the
     * flagged tiles **expanded by a one-tile margin** — never the whole frame.
     *
     * Returns the cover rectangle in **bitmap pixel coordinates** (the caller
     * maps it to overlay coordinates), or `null` when no tile is flagged. Every
     * tile crop is recycled immediately (no-media invariant). Fail-open: any
     * error yields `null` so nothing is covered and the text paths are unaffected.
     */
    fun localize(bitmap: Bitmap, grid: Int = TILE_GRID): Rect? = runCatching {
        val w = bitmap.width
        val h = bitmap.height
        if (w <= 0 || h <= 0 || grid < 1) return null

        var minCol = grid
        var minRow = grid
        var maxCol = -1
        var maxRow = -1
        for (row in 0 until grid) {
            for (col in 0 until grid) {
                // Integer tiling that exactly tiles the frame: the last row/col
                // absorbs the rounding remainder so no strip is left unscored.
                val left = col * w / grid
                val top = row * h / grid
                val right = (col + 1) * w / grid
                val bottom = (row + 1) * h / grid
                val tw = right - left
                val th = bottom - top
                if (tw <= 0 || th <= 0) continue
                val tile = Bitmap.createBitmap(bitmap, left, top, tw, th)
                val s = try {
                    score(tile)
                } finally {
                    if (tile !== bitmap) tile.recycle()
                }
                if (shouldBlock(s)) {
                    if (col < minCol) minCol = col
                    if (row < minRow) minRow = row
                    if (col > maxCol) maxCol = col
                    if (row > maxRow) maxRow = row
                }
            }
        }
        if (maxCol < 0) return null // no flagged tile

        // Expand by a one-tile margin (clamped to the grid), then convert the
        // grid box back to pixel coordinates, clamped to the bitmap bounds.
        val c0 = (minCol - TILE_MARGIN).coerceAtLeast(0)
        val r0 = (minRow - TILE_MARGIN).coerceAtLeast(0)
        val c1 = (maxCol + TILE_MARGIN).coerceAtMost(grid - 1)
        val r1 = (maxRow + TILE_MARGIN).coerceAtMost(grid - 1)
        Rect(
            c0 * w / grid,
            r0 * h / grid,
            ((c1 + 1) * w / grid).coerceAtMost(w),
            ((r1 + 1) * h / grid).coerceAtMost(h),
        )
    }.onFailure { Log.i(TAG, "NSFW localize failed (fail-open): ${it.message}") }
        .getOrNull()

    companion object {
        private const val TAG = "BulwarkNsfw"

        /** Per-tile NSFW block threshold. Higher than the engine default (0.7)
         *  because this path scores SMALL downscaled tile crops of a screenshot,
         *  where the int8 classifier is noisier — 0.7 over-flagged benign tiles
         *  (false covers). 0.85 cuts those while still catching explicit imagery;
         *  a device-validation tuning knob (with TILE_GRID + the lift hysteresis). */
        const val BLOCK_THRESHOLD = 0.85f

        /** N for the N×N localization grid (perf/accuracy knob — see the spec). */
        const val TILE_GRID = 4

        /** Tiles of margin added around the flagged region before covering. */
        const val TILE_MARGIN = 1

        /** `BUNDLED_NSFW_INPUT_SIZE` — the bundled ViT is 384x384. */
        private const val INPUT_SIZE = 384

        /** `Normalization::half()` — (x/255 - 0.5) / 0.5 per channel. */
        private const val MEAN = 0.5f
        private const val STD = 0.5f

        private const val ASSET_PATH = "model/nsfw_detector.onnx"
        private val SHAPE = longArrayOf(1, 3, INPUT_SIZE.toLong(), INPUT_SIZE.toLong())
        private val ORT: OrtEnvironment get() = OrtEnvironment.getEnvironment()

        @Volatile
        private var cached: Nsfw? = null

        /** `true` once creation has been attempted — a hard-missing model is not
         *  retried on every frame (the asset can't appear at runtime). */
        @Volatile
        private var attempted = false

        /**
         * Process-wide classifier (the model load is expensive — reuse across the
         * service lifetime). Returns `null` when the model cannot run on this
         * device (fail-open: the caller simply skips image scanning). A
         * successful creation is cached; a hard failure is remembered so we don't
         * re-extract a missing asset every tick.
         */
        fun obtain(context: Context): Nsfw? {
            cached?.let { return it }
            synchronized(this) {
                cached?.let { return it }
                if (attempted) return null
                attempted = true
                val n = create(context.applicationContext)
                if (n != null) cached = n
                return n
            }
        }

        private fun create(context: Context): Nsfw? {
            val model = runCatching { extractModel(context) }.getOrElse { e ->
                Log.i(TAG, "NSFW model asset absent — image scanning disabled (fail-open): ${e.message}")
                return null
            }
            // NNAPI first (doctrine: use the device accelerator when present),
            // then CPU. Each candidate must SURVIVE a warmup inference — an
            // accelerator session that builds but cannot run the model must not
            // win (same lesson as the engine's `time_warmup`).
            //
            // EXCEPT on a 32-bit process: ORT 1.22.0 has an ARM32 NNAPI SIGBUS
            // (microsoft/onnxruntime#25138) — a NATIVE crash that the fail-open
            // runCatching cannot catch and which would kill the service. So a
            // 32-bit process goes straight to CPU; only 64-bit tries NNAPI.
            val providers =
                if (android.os.Process.is64Bit()) booleanArrayOf(true, false) else booleanArrayOf(false)
            for (useNnapi in providers) {
                val n = runCatching { build(model, useNnapi) }.getOrNull() ?: continue
                val warm = runCatching {
                    val bmp = Bitmap.createBitmap(INPUT_SIZE, INPUT_SIZE, Bitmap.Config.ARGB_8888)
                    try {
                        // THROWING path: a provider that builds but can't run the
                        // model fails here and is rejected (→ CPU fallback).
                        n.infer(bmp)
                    } finally {
                        bmp.recycle()
                    }
                }
                if (warm.isSuccess) {
                    Log.i(TAG, "NSFW classifier ready (engine=${n.engine})") // content-free
                    return n
                }
                runCatching { n.session.close() }
            }
            Log.i(TAG, "NSFW classifier unavailable — image scanning disabled (fail-open)")
            return null
        }

        private fun build(model: File, nnapi: Boolean): Nsfw {
            val opts = OrtSession.SessionOptions()
            if (nnapi) opts.addNnapi()
            val session = ORT.createSession(model.absolutePath, opts)
            return Nsfw(session, session.inputNames.first(), if (nnapi) "nnapi" else "cpu")
        }

        /**
         * Copy the asset to an app-private file once (ORT maps a file path
         * natively — no large byte[] on the Java heap). The size marker guards
         * against a previously interrupted copy. noBackupFilesDir: never in
         * device backups. Throws when the asset is absent → [create] fails open.
         */
        private fun extractModel(context: Context): File {
            val dir = File(context.noBackupFilesDir, "nsfw").apply { mkdirs() }
            val target = File(dir, "nsfw_detector.onnx")
            val marker = File(dir, "nsfw_detector.size")
            if (target.isFile && marker.isFile &&
                marker.readText().trim() == target.length().toString()
            ) {
                return target
            }
            context.assets.open(ASSET_PATH).use { ins ->
                target.outputStream().use { outs -> ins.copyTo(outs, 1 shl 16) }
            }
            marker.writeText(target.length().toString())
            return target
        }

        // ---------------- pre/post-processing (engine parity) ----------------

        /** Mirrors preprocess.rs::to_nchw with Normalization::half(). */
        private fun preprocess(bitmap: Bitmap): FloatArray {
            val scaled = Bitmap.createScaledBitmap(bitmap, INPUT_SIZE, INPUT_SIZE, true)
            val px = IntArray(INPUT_SIZE * INPUT_SIZE)
            scaled.getPixels(px, 0, INPUT_SIZE, 0, 0, INPUT_SIZE, INPUT_SIZE)
            if (scaled !== bitmap) scaled.recycle()
            val plane = INPUT_SIZE * INPUT_SIZE
            val data = FloatArray(3 * plane)
            for (i in 0 until plane) {
                val c = px[i]
                data[i] = ((c shr 16 and 0xFF) / 255f - MEAN) / STD          // R
                data[plane + i] = ((c shr 8 and 0xFF) / 255f - MEAN) / STD   // G
                data[2 * plane + i] = ((c and 0xFF) / 255f - MEAN) / STD     // B
            }
            return data
        }

        private fun extractLogits(raw: Any?): FloatArray = when (raw) {
            is FloatArray -> raw
            is Array<*> -> raw.firstOrNull() as? FloatArray ?: floatArrayOf()
            else -> floatArrayOf()
        }

        /** Mirrors postprocess.rs::nsfw_probability (LAST class = nsfw). */
        private fun nsfwProbability(logits: FloatArray): Float = when (logits.size) {
            0 -> 0f
            1 -> sigmoid(logits[0])
            else -> softmax(logits).last()
        }.coerceIn(0f, 1f)

        private fun sigmoid(x: Float): Float = 1f / (1f + exp(-x))

        private fun softmax(xs: FloatArray): FloatArray {
            val max = xs.max()
            val exps = FloatArray(xs.size) { exp(xs[it] - max) }
            val sum = exps.sum()
            return if (sum == 0f) FloatArray(xs.size) else FloatArray(xs.size) { exps[it] / sum }
        }
    }
}
