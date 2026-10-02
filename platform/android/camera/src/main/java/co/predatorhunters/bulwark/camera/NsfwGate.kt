package co.predatorhunters.bulwark.camera

import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Matrix
import android.graphics.Paint
import android.graphics.Rect
import android.util.Log
import java.io.File
import java.nio.FloatBuffer
import kotlin.math.exp

/**
 * On-device-only NSFW capture gate.
 *
 * Runs the SAME license-pinned classifier the engine bundles
 * (`crates/bulwark-vision/models/nsfw_detector.onnx` — AdamCodd
 * `vit-base-nsfw-detector`, Apache-2.0, int8 ONNX), copied into this APK's
 * assets at build time (build.gradle.kts `copyNsfwModel`) and executed with
 * ONNX Runtime Android (MIT). Pre/post-processing mirrors
 * `crates/bulwark-vision/src/preprocess.rs` (384x384, `[-1,1]` "half"
 * normalization, NCHW) and `postprocess.rs::nsfw_probability` (softmax, LAST
 * class = nsfw; sigmoid for a 1-logit head); the block threshold is
 * `VisionConfig::default().nsfw_threshold`. Camera scoring therefore cannot
 * drift from the engine's.
 *
 * Execution provider follows the on-device-AI doctrine: try the NNAPI
 * accelerator, VALIDATE it with a warmup inference, else CPU. Both fully
 * on-device.
 *
 * PRIVACY (the point of this app): frames are scored in memory and dropped —
 * nothing is stored, hashed, logged, or sent. This APK declares no network
 * permission, so "nothing leaves the device" is enforced by the OS.
 * Deliberately NO reporting pipeline here: a child's own camera must not
 * exfiltrate (the detect/block/report posture belongs to the network filter).
 *
 * FAIL-CLOSED: this gate IS the filter, so callers treat "no gate" or "could
 * not score" as "do not capture / do not save" (the filters-always-active
 * rule). [score] throws instead of returning 0.0 for an unscorable frame.
 */
class NsfwGate private constructor(
    private val session: OrtSession,
    private val inputName: String,
    /** "nnapi" or "cpu" — content-free, used only for a one-time log line. */
    val engine: String,
) {

    /** True when [score] is at/above the engine-default block threshold. */
    fun shouldBlock(score: Float): Boolean = score >= BLOCK_THRESHOLD

    /**
     * NSFW probability in [0,1] for an upright bitmap. Synchronized: inference
     * is the bottleneck, not the lock (mirrors the engine's Mutex<Session>).
     * Throws when the frame cannot be scored — callers must block the capture
     * rather than pretend it was safe.
     */
    @Synchronized
    fun score(bitmap: Bitmap): Float {
        val input = preprocess(bitmap)
        OnnxTensor.createTensor(ORT, FloatBuffer.wrap(input), SHAPE).use { tensor ->
            session.run(mapOf(inputName to tensor)).use { out ->
                val logits = extractLogits(out[0].value)
                check(logits.isNotEmpty()) { "model output was not scorable" }
                return nsfwProbability(logits)
            }
        }
    }

    companion object {
        private const val TAG = "NsfwGate"

        /** `VisionConfig::default().nsfw_threshold` (crates/bulwark-vision). */
        const val BLOCK_THRESHOLD = 0.7f

        /** `BUNDLED_NSFW_INPUT_SIZE` — the bundled ViT is 384x384. */
        private const val INPUT_SIZE = 384

        /** `Normalization::half()` — (x/255 - 0.5) / 0.5 per channel. */
        private const val MEAN = 0.5f
        private const val STD = 0.5f

        private const val ASSET_PATH = "model/nsfw_detector.onnx"
        private val SHAPE = longArrayOf(1, 3, INPUT_SIZE.toLong(), INPUT_SIZE.toLong())
        private val ORT: OrtEnvironment get() = OrtEnvironment.getEnvironment()

        private class Scratch {
            val scaled = Bitmap.createBitmap(INPUT_SIZE, INPUT_SIZE, Bitmap.Config.ARGB_8888)
            val canvas = Canvas(scaled)
            val paint = Paint(Paint.FILTER_BITMAP_FLAG or Paint.DITHER_FLAG)
            val destination = Rect(0, 0, INPUT_SIZE, INPUT_SIZE)
            val pixels = IntArray(INPUT_SIZE * INPUT_SIZE)
            val input = FloatArray(3 * INPUT_SIZE * INPUT_SIZE)
        }

        private val scratch = ThreadLocal.withInitial { Scratch() }

        @Volatile
        private var cached: NsfwGate? = null

        /**
         * Process-wide gate (the model load is expensive — reuse across
         * activity recreations). Returns null when the model cannot run on
         * this device; a FAILED creation is NOT cached, so a later open
         * retries (a transient failure must not permanently kill the camera).
         */
        fun obtain(context: Context): NsfwGate? {
            cached?.let { return it }
            synchronized(this) {
                cached?.let { return it }
                val gate = create(context.applicationContext)
                if (gate != null) cached = gate
                return gate
            }
        }

        private fun create(context: Context): NsfwGate? {
            val model = runCatching { extractModel(context) }.getOrElse { e ->
                Log.w(TAG, "NSFW model asset could not be extracted", e)
                return null
            }
            // NNAPI first (doctrine: use the device accelerator when present),
            // then CPU. Each candidate must SURVIVE a warmup inference — an
            // accelerator session that builds but cannot run the model must
            // not win (same lesson as the engine's `time_warmup`).
            //
            // EXCEPT on a 32-bit process: ORT 1.22.0 has an ARM32 NNAPI SIGBUS
            // (microsoft/onnxruntime#25138) — a NATIVE crash not catchable by the
            // runCatching below, which would kill the capture process. So 32-bit
            // goes straight to CPU; only 64-bit tries NNAPI.
            val providers =
                if (android.os.Process.is64Bit()) booleanArrayOf(true, false) else booleanArrayOf(false)
            for (useNnapi in providers) {
                val gate = runCatching { build(model, useNnapi) }.getOrNull() ?: continue
                val warmBitmap = Bitmap.createBitmap(INPUT_SIZE, INPUT_SIZE, Bitmap.Config.ARGB_8888)
                val warm = runCatching { gate.score(warmBitmap) }
                warmBitmap.recycle()
                if (warm.isSuccess) {
                    Log.i(TAG, "NSFW gate ready (engine=${gate.engine})")
                    return gate
                }
                runCatching { gate.session.close() }
            }
            Log.w(TAG, "NSFW gate unavailable: no execution provider could run the model")
            return null
        }

        private fun build(model: File, nnapi: Boolean): NsfwGate {
            val opts = OrtSession.SessionOptions().apply {
                setOptimizationLevel(OrtSession.SessionOptions.OptLevel.ALL_OPT)
                setMemoryPatternOptimization(true)
                if (nnapi) {
                    addNnapi()
                } else {
                    val cores = Runtime.getRuntime().availableProcessors().coerceAtLeast(1)
                    setIntraOpNumThreads((cores / 2).coerceIn(1, 4))
                    setInterOpNumThreads(1)
                }
            }
            val session = ORT.createSession(model.absolutePath, opts)
            return NsfwGate(session, session.inputNames.first(), if (nnapi) "nnapi" else "cpu")
        }

        /**
         * Copy the asset to an app-private file once (ORT maps a file path
         * natively — no 88 MB byte[] on the Java heap). The size marker guards
         * against a previously interrupted copy. noBackupFilesDir: never in
         * device backups.
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
            val work = scratch.get()
            work.canvas.drawBitmap(bitmap, null, work.destination, work.paint)
            work.scaled.getPixels(
                work.pixels,
                0,
                INPUT_SIZE,
                0,
                0,
                INPUT_SIZE,
                INPUT_SIZE,
            )
            val plane = INPUT_SIZE * INPUT_SIZE
            for (i in 0 until plane) {
                val c = work.pixels[i]
                work.input[i] = ((c shr 16 and 0xFF) / 255f - MEAN) / STD
                work.input[plane + i] = ((c shr 8 and 0xFF) / 255f - MEAN) / STD
                work.input[2 * plane + i] = ((c and 0xFF) / 255f - MEAN) / STD
            }
            return work.input
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

/** Rotate a bitmap upright (CameraX reports rotation; BitmapFactory ignores EXIF). */
internal fun Bitmap.rotatedBy(degrees: Int): Bitmap {
    if (degrees == 0) return this
    val m = Matrix().apply { postRotate(degrees.toFloat()) }
    return Bitmap.createBitmap(this, 0, 0, width, height, m, true)
}
