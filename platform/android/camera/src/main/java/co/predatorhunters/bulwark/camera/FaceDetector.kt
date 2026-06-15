package co.predatorhunters.bulwark.camera

import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession
import android.content.Context
import android.graphics.Bitmap
import android.graphics.RectF
import android.os.Process
import android.util.Log
import java.io.File
import java.nio.FloatBuffer
import kotlin.math.max
import kotlin.math.min

/**
 * On-device FACE-BOX detector for the AR "funny face" sticker overlay.
 *
 * This is NOT a safety component — [NsfwGate] / [VideoGate] remain the sole
 * authoritative gates and are never touched here. This detector exists ONLY to
 * place fun stickers (ears, glasses, moustache, crown) on detected faces in the
 * live preview and to bake them into a SAFE saved photo. It returns plain
 * bounding BOXES — no identity, no recognition, nothing stored or sent.
 *
 * MODEL: UltraFace `version-RFB-320` (Linzaer "Ultra-Light-Fast-Generic-Face-
 * Detector-1MB", **MIT**, ~1.2 MB) bundled in this APK's assets
 * (`assets/model/face_detector.onnx`) and executed with the SAME ONNX Runtime
 * Android (MIT) the NSFW gate already uses. The model + this runtime both exist
 * cross-platform (ORT ships for iOS too), so the AR feature can be re-built on a
 * future Apple Network Extension / camera with the SAME weights — deliberately
 * no Google ML Kit / MediaPipe / Play Services dependency.
 *
 * I/O (verified from the onnx/models export):
 *  * input `input`  : NCHW `[1,3,240,320]`, RGB, normalised `(px - 127) / 128`.
 *  * output `scores`: `[1,4420,2]` softmax probs; index 1 = face confidence.
 *  * output `boxes` : `[1,4420,4]` already-decoded normalised corners
 *                     (xmin, ymin, xmax, ymax) in `[0,1]` of the input.
 * Post-processing applies a confidence threshold then greedy NMS so each face
 * yields ONE box (otherwise dozens of overlapping priors draw dozens of stickers).
 *
 * Execution provider follows the on-device-AI doctrine, mirroring [NsfwGate]:
 * try NNAPI (64-bit only — the ORT 1.22 ARM32 NNAPI SIGBUS is a native crash),
 * validate with a warmup, else CPU. Both fully on-device.
 *
 * BEST-EFFORT: unlike the safety gate this never fail-closes. If the model can't
 * load or a frame can't be scored, [detect] simply returns no boxes — the camera
 * works exactly as before, just without stickers on that frame.
 */
class FaceDetector private constructor(
    private val session: OrtSession,
    private val inputName: String,
    private val scoresName: String,
    private val boxesName: String,
    /** "nnapi" or "cpu" — content-free, one-time log line only. */
    val engine: String,
) {

    /** A detected face as normalised `[0,1]` corners of the scored bitmap. */
    data class Face(val box: RectF, val score: Float)

    /**
     * Detect faces in [bitmap] (expected UPRIGHT — caller rotates first, exactly
     * like the NSFW path). Returns normalised boxes in `[0,1]` w.r.t. the bitmap.
     * Synchronized like the gate: inference is the bottleneck, not the lock.
     * Never throws — a failed inference yields an empty list (best-effort).
     */
    @Synchronized
    fun detect(bitmap: Bitmap): List<Face> = runCatching {
        val input = preprocess(bitmap)
        OnnxTensor.createTensor(ORT, FloatBuffer.wrap(input), INPUT_SHAPE).use { tensor ->
            session.run(mapOf(inputName to tensor)).use { out ->
                val scores = out.get(scoresName).get().value as Array<*>      // [1][4420][2]
                val boxes = out.get(boxesName).get().value as Array<*>        // [1][4420][4]
                postprocess(scores[0] as Array<*>, boxes[0] as Array<*>)
            }
        }
    }.getOrElse { emptyList() }

    companion object {
        private const val TAG = "FaceDetector"

        private const val IN_W = 320
        private const val IN_H = 240
        /** UltraFace normalisation: (px - 127) / 128 (NOT the gate's 0.5/0.5). */
        private const val MEAN = 127f
        private const val STD = 128f
        /** Keep a box only above this face confidence. */
        private const val SCORE_THRESHOLD = 0.7f
        /** Greedy-NMS overlap above which the weaker box is dropped. */
        private const val IOU_THRESHOLD = 0.3f
        /** Plenty for a child's selfie/group shot; bounds the NMS work. */
        private const val MAX_FACES = 8

        private const val ASSET_PATH = "model/face_detector.onnx"
        private val INPUT_SHAPE = longArrayOf(1, 3, IN_H.toLong(), IN_W.toLong())
        private val ORT: OrtEnvironment get() = OrtEnvironment.getEnvironment()

        @Volatile
        private var cached: FaceDetector? = null

        /**
         * Process-wide detector (the model load is expensive — reuse it). Returns
         * null when the model cannot run on this device; a FAILED creation is NOT
         * cached so a later open retries. The camera works fine when this is null
         * — the AR strip simply shows nothing/places no sticker.
         */
        fun obtain(context: Context): FaceDetector? {
            cached?.let { return it }
            synchronized(this) {
                cached?.let { return it }
                val det = create(context.applicationContext)
                if (det != null) cached = det
                return det
            }
        }

        private fun create(context: Context): FaceDetector? {
            val model = runCatching { extractModel(context) }.getOrElse { e ->
                Log.w(TAG, "face model asset could not be extracted", e)
                return null
            }
            val providers =
                if (Process.is64Bit()) booleanArrayOf(true, false) else booleanArrayOf(false)
            for (useNnapi in providers) {
                val det = runCatching { build(model, useNnapi) }.getOrNull() ?: continue
                val warm = runCatching {
                    det.detect(Bitmap.createBitmap(IN_W, IN_H, Bitmap.Config.ARGB_8888))
                }
                if (warm.isSuccess) {
                    Log.i(TAG, "face detector ready (engine=${det.engine})") // content-free
                    return det
                }
                runCatching { det.session.close() }
            }
            Log.w(TAG, "face detector unavailable: no execution provider could run the model")
            return null
        }

        private fun build(model: File, nnapi: Boolean): FaceDetector {
            val opts = OrtSession.SessionOptions()
            if (nnapi) opts.addNnapi()
            val session = ORT.createSession(model.absolutePath, opts)
            val inputName = session.inputNames.first()
            // The export names the outputs "scores"/"boxes"; resolve defensively
            // by shape (last dim 2 = scores, 4 = boxes) so a re-export can't break us.
            val names = session.outputNames.toList()
            val scores = names.firstOrNull { it.equals("scores", true) } ?: names.first()
            val boxes = names.firstOrNull { it.equals("boxes", true) }
                ?: names.last()
            return FaceDetector(session, inputName, scores, boxes, if (nnapi) "nnapi" else "cpu")
        }

        /**
         * Copy the asset to an app-private file once (ORT maps a file path
         * natively). Mirrors [NsfwGate.extractModel]; the size marker guards a
         * previously interrupted copy; noBackupFilesDir keeps it out of backups.
         */
        private fun extractModel(context: Context): File {
            val dir = File(context.noBackupFilesDir, "face").apply { mkdirs() }
            val target = File(dir, "face_detector.onnx")
            val marker = File(dir, "face_detector.size")
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

        // ---------------- pre/post-processing ----------------

        /** Resize to 320x240, RGB, NCHW, normalised (px - 127) / 128. */
        private fun preprocess(bitmap: Bitmap): FloatArray {
            val scaled = Bitmap.createScaledBitmap(bitmap, IN_W, IN_H, true)
            val px = IntArray(IN_W * IN_H)
            scaled.getPixels(px, 0, IN_W, 0, 0, IN_W, IN_H)
            if (scaled !== bitmap) scaled.recycle()
            val plane = IN_W * IN_H
            val data = FloatArray(3 * plane)
            for (i in 0 until plane) {
                val c = px[i]
                data[i] = ((c shr 16 and 0xFF) - MEAN) / STD          // R
                data[plane + i] = ((c shr 8 and 0xFF) - MEAN) / STD   // G
                data[2 * plane + i] = ((c and 0xFF) - MEAN) / STD     // B
            }
            return data
        }

        /**
         * Threshold the per-prior face confidence (scores[i][1]) then greedy-NMS
         * the surviving normalised boxes so each real face yields one box.
         */
        private fun postprocess(scores: Array<*>, boxes: Array<*>): List<Face> {
            val candidates = ArrayList<Face>()
            val n = min(scores.size, boxes.size)
            for (i in 0 until n) {
                val s = scores[i] as? FloatArray ?: continue
                val conf = if (s.size >= 2) s[1] else continue
                if (conf < SCORE_THRESHOLD) continue
                val b = boxes[i] as? FloatArray ?: continue
                if (b.size < 4) continue
                val left = b[0].coerceIn(0f, 1f)
                val top = b[1].coerceIn(0f, 1f)
                val right = b[2].coerceIn(0f, 1f)
                val bottom = b[3].coerceIn(0f, 1f)
                if (right <= left || bottom <= top) continue
                candidates.add(Face(RectF(left, top, right, bottom), conf))
            }
            candidates.sortByDescending { it.score }
            val kept = ArrayList<Face>()
            for (cand in candidates) {
                if (kept.size >= MAX_FACES) break
                if (kept.none { iou(it.box, cand.box) > IOU_THRESHOLD }) kept.add(cand)
            }
            return kept
        }

        private fun iou(a: RectF, b: RectF): Float {
            val ix = max(0f, min(a.right, b.right) - max(a.left, b.left))
            val iy = max(0f, min(a.bottom, b.bottom) - max(a.top, b.top))
            val inter = ix * iy
            val areaA = (a.right - a.left) * (a.bottom - a.top)
            val areaB = (b.right - b.left) * (b.bottom - b.top)
            val union = areaA + areaB - inter
            return if (union <= 0f) 0f else inter / union
        }
    }
}
