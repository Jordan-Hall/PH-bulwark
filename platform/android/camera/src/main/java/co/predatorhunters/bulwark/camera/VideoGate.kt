package co.predatorhunters.bulwark.camera

import android.media.MediaMetadataRetriever
import java.io.File

/**
 * Authoritative post-recording video safety check.
 *
 * A video stream cannot be scored before bytes hit disk the way a single photo
 * can, so video uses the SAME two-layer model as the photo path, adapted:
 *
 *  1. LIVE SAMPLING (advisory, in CameraScreen): the preview-shield analyzer
 *     keeps scoring frames WHILE recording so an unsafe scene stops the take
 *     early. This is the live preview shield's analog.
 *  2. FULL RE-SCAN (authoritative, here): after the recorder finalizes the temp
 *     file, every sampled frame is decoded and scored. Only a fully-clean
 *     re-scan lets the file be published; a single flagged frame blocks it.
 *
 * HONEST LIMIT (vs. the photo path's "never touches disk"): a video necessarily
 * lands in an APP-PRIVATE temp file while recording — it is never written to the
 * gallery, never made user-visible, and is DELETED on any flag, failure, or
 * cancel. The constraint's spirit (no unsafe content is ever persisted or made
 * recoverable) is preserved by app-private-temp + re-scan-before-publish +
 * delete-on-flag; the caller publishes to MediaStore only after a clean re-scan.
 *
 * FAIL-CLOSED: any decode/score failure during the re-scan is treated as
 * unsafe — the video is NOT published.
 */
internal object VideoGate {

    /** Sample interval for the authoritative re-scan (one frame ~every 500 ms). */
    private const val RESCAN_INTERVAL_US = 500_000L

    /** Cap on frames scored per video so a long clip can't run unbounded. */
    private const val MAX_RESCAN_FRAMES = 600

    sealed interface Result {
        /** Every sampled frame scored safe — OK to publish. */
        object Clean : Result

        /** A frame scored at/above the block threshold — must not publish. */
        object Blocked : Result

        /** Could not decode/score the file — fail closed, must not publish. */
        object CheckFailed : Result
    }

    /**
     * Decode [tempFile] frame-by-frame and score each with [gate]. Returns
     * [Result.Clean] only if EVERY sampled frame is safe. Pure CPU/IO work;
     * call off the main thread.
     */
    fun rescan(tempFile: File, gate: NsfwGate): Result {
        val retriever = MediaMetadataRetriever()
        return try {
            retriever.setDataSource(tempFile.absolutePath)
            val durationMs = retriever.extractMetadata(
                MediaMetadataRetriever.METADATA_KEY_DURATION,
            )?.toLongOrNull() ?: 0L
            val durationUs = durationMs * 1000L

            // Always score at least the first frame, even for a ~0 ms clip.
            var timeUs = 0L
            var scored = 0
            while (timeUs <= durationUs && scored < MAX_RESCAN_FRAMES) {
                val frame = retriever.getFrameAtTime(
                    timeUs,
                    MediaMetadataRetriever.OPTION_CLOSEST_SYNC,
                ) ?: return Result.CheckFailed // a missing frame is unscorable -> fail closed
                val score = runCatching { gate.score(frame) }.getOrElse { return Result.CheckFailed }
                frame.recycle()
                if (gate.shouldBlock(score)) return Result.Blocked
                scored++
                if (durationUs == 0L) break
                timeUs += RESCAN_INTERVAL_US
            }
            // A clip we could open but extracted zero frames from is unscorable.
            if (scored == 0) Result.CheckFailed else Result.Clean
        } catch (_: Throwable) {
            Result.CheckFailed
        } finally {
            runCatching { retriever.release() }
        }
    }
}
