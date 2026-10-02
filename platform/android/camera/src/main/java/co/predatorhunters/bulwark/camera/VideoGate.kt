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
 *  2. FULL-SPAN RE-SCAN (authoritative, here): after the recorder finalizes the
 *     temp file, bounded samples are distributed across the entire duration.
 *     Only a fully-clean re-scan lets the file be published; a single flagged
 *     frame blocks it.
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

    /** Short clips are sampled about once per second after the live 300 ms gate. */
    private const val TARGET_RESCAN_INTERVAL_US = 1_000_000L

    /**
     * Bound post-record latency. Longer clips use the same number of samples but
     * spread them uniformly from the first frame through the final frame instead
     * of scanning only the beginning of the clip.
     */
    private const val MAX_RESCAN_FRAMES = 32

    /** Decode directly to model resolution instead of allocating full-res frames. */
    private const val RESCAN_DECODE_DIM = 384

    sealed interface Result {
        /** Every sampled frame scored safe — OK to publish. */
        object Clean : Result

        /** A frame scored at/above the block threshold — must not publish. */
        object Blocked : Result

        /** Could not decode/score the file — fail closed, must not publish. */
        object CheckFailed : Result
    }

    /**
     * Sample [tempFile] across its complete duration and score every selected
     * frame with [gate]. Returns [Result.Clean] only when all samples are safe.
     * Pure CPU/IO work; call off the main thread.
     */
    fun rescan(tempFile: File, gate: NsfwGate): Result {
        val retriever = MediaMetadataRetriever()
        return try {
            retriever.setDataSource(tempFile.absolutePath)
            val durationMs = retriever.extractMetadata(
                MediaMetadataRetriever.METADATA_KEY_DURATION,
            )?.toLongOrNull() ?: return Result.CheckFailed
            if (durationMs < 0L) return Result.CheckFailed
            val durationUs = durationMs.coerceAtMost(Long.MAX_VALUE / 1000L) * 1000L

            val desiredSamples = if (durationUs == 0L) {
                1
            } else {
                ((durationUs + TARGET_RESCAN_INTERVAL_US - 1L) / TARGET_RESCAN_INTERVAL_US + 1L)
                    .coerceAtMost(MAX_RESCAN_FRAMES.toLong())
                    .toInt()
            }
            val sampleCount = desiredSamples.coerceIn(1, MAX_RESCAN_FRAMES)

            for (index in 0 until sampleCount) {
                val timeUs = when {
                    sampleCount == 1 -> 0L
                    index == sampleCount - 1 -> durationUs
                    else -> (durationUs.toDouble() * index / (sampleCount - 1)).toLong()
                }
                val frame = retriever.getScaledFrameAtTime(
                    timeUs,
                    MediaMetadataRetriever.OPTION_CLOSEST_SYNC,
                    RESCAN_DECODE_DIM,
                    RESCAN_DECODE_DIM,
                ) ?: return Result.CheckFailed
                val score = try {
                    gate.score(frame)
                } catch (_: Throwable) {
                    return Result.CheckFailed
                } finally {
                    frame.recycle()
                }
                if (gate.shouldBlock(score)) return Result.Blocked
            }
            Result.Clean
        } catch (_: Throwable) {
            Result.CheckFailed
        } finally {
            runCatching { retriever.release() }
        }
    }
}
