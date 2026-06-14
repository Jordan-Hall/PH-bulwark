package co.predatorhunters.bulwark.browser

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.Log
import android.webkit.CookieManager
import android.webkit.JavascriptInterface
import co.predatorhunters.bulwark.core.RustBridge
import co.predatorhunters.bulwark.nsfw.Nsfw
import org.json.JSONObject
import java.net.URL
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

/**
 * The classify-and-censor brain behind the PH Bulwark Browser's JS bridge.
 *
 * The injected page script ([co.predatorhunters.bulwark] `res/raw/bulwark_browser.js`)
 * walks the FULL rendered DOM — visible AND off-viewport — and posts each text run
 * and image element here as `{ id, text|src, rect }`. This class routes that
 * content through the app's EXISTING on-device classifiers, treated as black boxes:
 *
 *  - text  -> [RustBridge.analyzeText] (the same grooming/harmful-text path the
 *             AccessibilityService uses) — returns a JSON verdict.
 *  - image -> [Nsfw] (the same on-device image-safety classifier) — needs PIXELS,
 *             so the URL is fetched and decoded to a [Bitmap] first.
 *
 * On a hit it calls back into the page via [onCensor] to drop an opaque cover over
 * that element's box (keyed by the element id the JS assigned). When a page is
 * PREDOMINANTLY flagged (by text-character ratio) it raises [onBlockPage] so the
 * activity can show a full-screen calm block notice.
 *
 * Off the main thread: [JavascriptInterface] callbacks arrive on a binder thread,
 * and the per-item classify work (text bridge call + image fetch/decode/score) is
 * handed to a single low-priority executor so neither the binder thread nor the UI
 * thread blocks (mirrors the AccessibilityService's `ocrExecutor`).
 *
 * Fail-OPEN throughout: a missing model, an undecodable image, or a bridge error
 * leaves content visible rather than crashing the browser. This is an ADDITIVE
 * pre-read safety pass, never the sole gate.
 *
 * No-media invariant: fetched image bytes and decoded bitmaps live in memory only
 * for the duration of one [Nsfw.score] call and are recycled immediately; nothing
 * is persisted, hashed for storage, or logged.
 */
class BrowserContentFilter(
    context: Context,
    /** Cover the element with [id] in the page (native -> JS callback). */
    private val onCensor: (id: String) -> Unit,
    /** The whole page is predominantly flagged — show the full-page block screen. */
    private val onBlockPage: () -> Unit,
) {
    private val appContext = context.applicationContext

    /** Per-item classify work runs here — never the binder/UI thread. */
    private val worker = Executors.newSingleThreadExecutor { r ->
        Thread(r, "bulwark-browser").apply { priority = Thread.MIN_PRIORITY }
    }

    /** Lazily-obtained image classifier (model load is expensive; cache it). */
    @Volatile
    private var nsfw: Nsfw? = null

    @Volatile
    private var nsfwAttempted = false

    /** De-dupe: classify each distinct text run / image URL at most once. */
    private val seenText = ConcurrentHashMap.newKeySet<Int>()
    private val seenImage = ConcurrentHashMap.newKeySet<String>()

    /** Running totals for the "predominantly flagged" page decision. */
    @Volatile
    private var totalTextChars = 0L

    @Volatile
    private var flaggedTextChars = 0L

    @Volatile
    private var pageBlocked = false

    /** Reset when a new URL begins loading so totals don't carry across pages. */
    fun reset() {
        seenText.clear()
        seenImage.clear()
        totalTextChars = 0
        flaggedTextChars = 0
        pageBlocked = false
    }

    /**
     * Bridge entry point — called from page script as `BulwarkBridge.onExtract(json)`.
     * Runs on a binder thread; we only parse here and dispatch the heavy work.
     */
    @JavascriptInterface
    fun onExtract(json: String) {
        worker.execute {
            runCatching { dispatch(json) }
                .onFailure { Log.i(TAG, "extract dispatch failed (fail-open): ${it.message}") }
        }
    }

    private fun dispatch(json: String) {
        val root = JSONObject(json)
        root.optJSONArray("text")?.let { arr ->
            for (i in 0 until arr.length()) {
                val o = arr.optJSONObject(i) ?: continue
                classifyText(o.optString("id"), o.optString("text"))
            }
        }
        root.optJSONArray("images")?.let { arr ->
            for (i in 0 until arr.length()) {
                val o = arr.optJSONObject(i) ?: continue
                classifyImage(o.optString("id"), o.optString("src"))
            }
        }
    }

    // ----------------------------- TEXT ------------------------------------

    private fun classifyText(id: String, text: String) {
        if (id.isEmpty() || text.length < 2) return
        if (!seenText.add(text.hashCode())) return // already classified this run

        totalTextChars += text.length
        val verdict = runCatching { RustBridge.analyzeText(BROWSER_APP, BROWSER_THREAD, text) }
            .getOrDefault("{\"error\":\"bridge unavailable\"}")

        if (isFlagged(verdict)) {
            flaggedTextChars += text.length
            onCensor(id)
            maybeBlockPage()
        }
    }

    // ----------------------------- IMAGE -----------------------------------

    private fun classifyImage(id: String, src: String) {
        if (id.isEmpty() || src.isEmpty()) return
        // TODO(hardening): blob:/data:/canvas-backed images and cross-origin
        // auth-gated fetches are skipped for now (decode/permission limits).
        if (!src.startsWith("http://", true) && !src.startsWith("https://", true)) return
        if (!seenImage.add(src)) return // classify each distinct URL once

        val classifier = obtainNsfw() ?: return // fail-open: no model -> no image scan
        val bitmap = fetchBitmap(src) ?: return // fail-open: undecodable -> skip
        try {
            val score = classifier.score(bitmap)
            if (classifier.shouldBlock(score)) onCensor(id)
        } finally {
            bitmap.recycle() // no-media invariant
        }
    }

    /**
     * Fetch + decode an image URL to a [Bitmap] for the classifier (which needs
     * pixels, not a URL). Best-effort cookie header so same-session images load.
     * Bounded timeouts; any failure returns null (fail-open).
     */
    private fun fetchBitmap(src: String): Bitmap? = runCatching {
        val conn = URL(src).openConnection().apply {
            connectTimeout = FETCH_TIMEOUT_MS
            readTimeout = FETCH_TIMEOUT_MS
            // TODO(hardening): auth/referer headers for gated CDNs.
            CookieManager.getInstance().getCookie(src)?.let {
                setRequestProperty("Cookie", it)
            }
            setRequestProperty("Accept", "image/*")
        }
        conn.getInputStream().use { input ->
            BitmapFactory.decodeStream(input)
        }
    }.onFailure { Log.v(TAG, "image fetch/decode skipped (fail-open): ${it.message}") }
        .getOrNull()

    private fun obtainNsfw(): Nsfw? {
        nsfw?.let { return it }
        synchronized(this) {
            nsfw?.let { return it }
            if (nsfwAttempted) return null
            nsfwAttempted = true
            nsfw = Nsfw.obtain(appContext)
            return nsfw
        }
    }

    // -------------------------- PAGE DECISION ------------------------------

    /**
     * Block the whole page when flagged text dominates what's on it. Uses the
     * cheap character ratio the bridge already accumulates (advisor's call): once
     * we've seen a meaningful amount of text and the flagged share crosses
     * [PAGE_BLOCK_RATIO], the activity shows a calm full-page block screen.
     */
    private fun maybeBlockPage() {
        if (pageBlocked) return
        val total = totalTextChars
        if (total < MIN_CHARS_FOR_PAGE_DECISION) return
        if (flaggedTextChars.toDouble() / total >= PAGE_BLOCK_RATIO) {
            pageBlocked = true
            onBlockPage()
        }
    }

    fun shutdown() {
        runCatching { worker.shutdownNow() }
    }

    companion object {
        private const val TAG = "BulwarkBrowser"

        /** App/thread labels for the text bridge. A constant per-surface thread id
         *  keeps the grooming state machine's history scoped to this browser
         *  surface (not shared with the chat-app threads). */
        private const val BROWSER_APP = "co.predatorhunters.bulwark.browser"
        private const val BROWSER_THREAD = "browser"

        private const val FETCH_TIMEOUT_MS = 8000

        /** Don't judge a page "predominantly flagged" until there's enough text to
         *  be meaningful (avoids blocking a near-empty page on one short hit). */
        private const val MIN_CHARS_FOR_PAGE_DECISION = 400L

        /** Flagged-text-character share at/above which the whole page is blocked. */
        private const val PAGE_BLOCK_RATIO = 0.4

        /**
         * Any non-SAFE, non-error verdict is worth covering — same parse the
         * AccessibilityService uses. (Borderline-vs-block nuance there gates the
         * disruptive full-screen slam; here covering a single span is cheap and
         * reversible, so we cover on any flag and reserve the full-page block for
         * the dominance ratio.)
         */
        private fun isFlagged(json: String): Boolean =
            !json.contains("\"category\":\"SAFE\"") && !json.contains("\"error\"")
    }
}
