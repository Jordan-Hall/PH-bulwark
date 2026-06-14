package co.predatorhunters.bulwark.accessibility

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityService.ScreenshotResult
import android.accessibilityservice.AccessibilityService.TakeScreenshotCallback
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Rect
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import android.view.Display
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.FrameLayout
import android.widget.TextView
import androidx.annotation.RequiresApi
import co.predatorhunters.bulwark.core.RustBridge
import co.predatorhunters.bulwark.nsfw.Nsfw
import co.predatorhunters.bulwark.ocr.Ocr
import co.predatorhunters.bulwark.tamper.TamperReporter

/**
 * The end-to-end / cert-pinned answer.
 *
 * Reads the text apps have ALREADY decrypted and rendered on screen (WhatsApp,
 * Signal, Messenger secret chats, Telegram, …) plus notification text, and feeds
 * it into the SAME deterministic grooming pipeline as network chat
 * ([RustBridge.analyzeText]). This is conventional text extraction from the
 * accessibility tree — NOT a model, NOT a vision-LLM.
 *
 * Requires the guardian to grant Accessibility in Settings (consent — see
 * docs/security/legal-consent.md). Only the apps in [MONITORED] are inspected;
 * captured text is analysed on-device and never leaves the device except as a
 * redacted guardian alert.
 */
class BulwarkAccessibilityService : AccessibilityService() {

    /** Current foreground app package (updated on every event) so a cover can be
     *  bound to the surface it was placed over. Never our own UI. */
    @Volatile
    private var lastForegroundPkg: String? = null

    /** The package a localized cover is currently placed over. A cover belongs to
     *  ONE surface: the instant the foreground window changes to a DIFFERENT app
     *  (app switch, notification shade, launcher), the cover is dropped, so it can
     *  never linger over the wrong screen or block the shade (the stale-cover bug
     *  that made the phone unusable). */
    @Volatile
    private var coverPkg: String? = null

    override fun onServiceConnected() {
        RustBridge.ensureLoaded()
        // Warm the NSFW classifier off the main thread so the first real frame
        // isn't delayed by the model load.
        ocrExecutor.execute { runCatching { Nsfw.obtain(this) } }
        Log.i(TAG, "Bulwark accessibility capture connected")
    }

    override fun onUnbind(intent: android.content.Intent?): Boolean {
        // Drop any cover when the service unbinds (settings toggle / shutdown) so
        // it can never be left stuck on screen.
        removeLocalizedOverlay()
        return super.onUnbind(intent)
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        event ?: return
        val pkg = event.packageName?.toString() ?: return
        // Track the live foreground app (skip our own UI) for surface-bound covers.
        // NOT from notification events: a background app posting a notification
        // fires TYPE_NOTIFICATION_STATE_CHANGED tagged with ITS OWN package while a
        // different app is on screen — treating that as the foreground would corrupt
        // the stale-surface guard and drop a legit scan of the real foreground (codex).
        if (pkg != packageName &&
            event.eventType != AccessibilityEvent.TYPE_NOTIFICATION_STATE_CHANGED
        ) {
            lastForegroundPkg = pkg
        }

        // SURFACE-BOUND COVER: when the foreground window changes to a DIFFERENT
        // app/surface than the one a cover was placed over, drop the cover at once
        // — it must never linger over another app, the launcher, or the
        // notification shade (which would block pull-down). Event-driven, no TTL.
        if (event.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            val cp = coverPkg
            if (cp != null && pkg != cp) removeLocalizedOverlay()
        }

        // Uninstall-guard: when the package installer / Settings opens, check
        // whether it's an attempt to remove US and, if so, alert + bounce away.
        if (event.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED &&
            pkg in UNINSTALL_SURFACES
        ) {
            guardAgainstUninstall()
            return
        }

        // TEXT/grooming is scoped to the monitored chat apps (the view-tree
        // text + OCR → grooming path). IMAGE NSFW is NOT: adult images appear in
        // browsers, WebViews, galleries and any other app, so the no-VPN
        // image-safety scan must run device-wide (codex: don't gate it on the
        // chat allowlist). Both share ONE throttled screenshot per tick.
        val monitored = pkg in MONITORED

        when (event.eventType) {
            AccessibilityEvent.TYPE_NOTIFICATION_STATE_CHANGED -> {
                if (monitored) {
                    val text = event.text.joinToString(" ").trim()
                    if (text.isNotEmpty()) submit(pkg, "notif", text)
                }
            }
            AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED,
            AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED,
            AccessibilityEvent.TYPE_VIEW_SCROLLED -> {
                // Re-scan on ANY on-screen change incl. scroll, so a cover tracks
                // the content as it moves and lifts the moment it scrolls away
                // (event-driven — no periodic polling, no timed auto-lift).
                if (monitored) {
                    // Monitored chat: view-tree TEXT → grooming, PLUS a throttled
                    // frame that runs BOTH image-NSFW and OCR. OCR runs even when the
                    // tree exposed text: a screen can show text in the tree AND text
                    // drawn into images/video the tree can't see (captions, memes,
                    // stylised chat), so gating OCR on an empty tree missed it.
                    val root = rootInActiveWindow ?: return
                    val text = collectText(root).trim()
                    val thread = threadIdFor(root, pkg)
                    if (text.isNotEmpty()) submit(pkg, thread, text)
                    maybeCapture(pkg, thread, ocrText = true)
                } else if (pkg != packageName) {
                    // Any OTHER foreground app (browser, YouTube, gallery, …): a
                    // throttled frame running BOTH image-NSFW AND OCR→grooming, so
                    // adult imagery and text-in-frames are caught device-wide — not
                    // just in the chat allowlist (which is the view-tree TEXT scope).
                    // Skips our own UI. Fail-open. Use a PER-SURFACE thread id (not a
                    // constant per-package one) so unrelated screens/videos don't
                    // share the grooming state machine's per-thread 7-day history.
                    val root = rootInActiveWindow
                    val thread = if (root != null) threadIdFor(root, pkg) else "scan:$pkg"
                    maybeCapture(pkg, thread, ocrText = true)
                }
            }
        }
    }

    // --- screen-frame scan: image NSFW (localized cover-up) + OCR fallback ---

    @Volatile
    private var lastCaptureAtMs = 0L

    /** Independent OCR sub-throttle: Tesseract is far heavier than the NSFW pass,
     *  so the image scan runs every capture but OCR only every [OCR_MIN_GAP_MS]. */
    @Volatile
    private var lastOcrAtMs = 0L

    /**
     * Low-priority single-thread executor for the screenshot callback, the NSFW
     * inference + tiling, and the Tesseract OCR pass, so none of that work runs
     * on the AccessibilityService main thread (which would stall subsequent
     * events / blocking overlays). UI actions triggered downstream
     * ([blockContent], [showLocalizedOverlay]) already main-post themselves.
     */
    private val ocrExecutor: java.util.concurrent.Executor =
        java.util.concurrent.Executors.newSingleThreadExecutor { r ->
            Thread(r, "bulwark-ocr").apply { priority = Thread.MIN_PRIORITY }
        }

    /**
     * Throttle gate for the screen-frame scan. Only on API 30+ (where
     * [takeScreenshot] exists). The NSFW image pass runs every capture (at most
     * once per [CAPTURE_MIN_GAP_MS] — the OS also rate-limits `takeScreenshot`
     * ~1/s); the heavier Tesseract OCR pass is sub-throttled to [OCR_MIN_GAP_MS]
     * so frequent NSFW re-scans don't drag in an OCR pass every tick.
     */
    private fun maybeCapture(pkg: String, thread: String, ocrText: Boolean) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return
        val now = SystemClock.elapsedRealtime()
        if (now - lastCaptureAtMs < CAPTURE_MIN_GAP_MS) return
        lastCaptureAtMs = now
        val doOcr = ocrText && (now - lastOcrAtMs >= OCR_MIN_GAP_MS)
        if (doOcr) lastOcrAtMs = now
        captureAndScan(pkg, thread, doOcr)
    }

    /**
     * Take one screen frame and run, off the main thread, the two on-device
     * detectors of the no-VPN path:
     *  - **Image NSFW** — score the frame for sexual/explicit imagery and, on a
     *    hit, cover ONLY the offending region (tiled localization), leaving the
     *    rest of the screen visible ([scanFrameForNsfw]).
     *  - **OCR (only when [ocrText])** — when the view-tree exposed no text,
     *    Tesseract-OCR the frame and feed any extracted text into the SAME
     *    grooming path as the view-tree text.
     *
     * The frame lives only in memory (no-media invariant) and is recycled
     * immediately; nothing is persisted, hashed for storage, or logged. Every
     * failure path is swallowed — this additive scan must never break the live
     * protection.
     */
    @RequiresApi(Build.VERSION_CODES.R)
    private fun captureAndScan(pkg: String, thread: String, ocrText: Boolean) {
        runCatching {
            takeScreenshot(
                Display.DEFAULT_DISPLAY,
                ocrExecutor,
                object : TakeScreenshotCallback {
                    override fun onSuccess(result: ScreenshotResult) {
                        val hb = result.hardwareBuffer
                        try {
                            val raw = Bitmap.wrapHardwareBuffer(hb, result.colorSpace)
                            // Software (readable) bitmap for both classifier + OCR.
                            val bmp = raw?.copy(Bitmap.Config.ARGB_8888, false)
                            raw?.recycle()
                            if (bmp != null) {
                                try {
                                    scanFrameForNsfw(pkg, bmp)
                                    if (ocrText) {
                                        val text = Ocr.recognize(this@BulwarkAccessibilityService, bmp)
                                        // Submit OCR text under the SAME thread as the
                                        // view-tree text (not a separate "ocr:" id), so
                                        // mixed tree+OCR signals in one conversation
                                        // (e.g. a secrecy message + an image caption
                                        // steering to another app) combine in the
                                        // grooming state machine's per-thread history.
                                        if (!text.isNullOrEmpty()) submit(pkg, thread, text)
                                    }
                                } finally {
                                    bmp.recycle()
                                }
                            }
                        } catch (t: Throwable) {
                            Log.i(TAG, "screen-frame scan failed (fail-open): ${t.message}")
                        } finally {
                            hb.close()
                        }
                    }

                    override fun onFailure(errorCode: Int) {
                        // Rate-limited / unavailable right now — ignore (fail-open).
                        Log.v(TAG, "takeScreenshot failed: $errorCode")
                    }
                },
            )
        }.onFailure { Log.i(TAG, "takeScreenshot threw (fail-open): ${it.message}") }
    }

    /**
     * Score [frame] for sexual/explicit imagery and, on a hit, cover ONLY the
     * offending region with a localized overlay so the rest of the screen stays
     * visible (the explicit ask — never full-screen for this path). The bundled
     * classifier is whole-image, so localization is by N×N tiling + a one-tile
     * margin ([Nsfw.localize]); the returned box is in frame-pixel coordinates and
     * mapped to overlay coordinates in [showLocalizedOverlay].
     *
     * When no flagged region is found, lift any existing localized overlay (the
     * content scrolled away / the frame is clean again).
     *
     * Fail-OPEN and in-memory: a missing model/runtime means no scan; the frame
     * and every tile crop are recycled and never persisted (no-media invariant).
     * A high score covers the region and signals the guardian via the existing
     * redacted-alert path; CSAM-specific reporting rides the separate engine
     * hash/report path (a single-probability classifier cannot single it out).
     */
    /** Consecutive clean scans since the last flagged one — drives the lift
     *  HYSTERESIS so a single noisy mis-score can't drop a cover. */
    @Volatile
    private var cleanScanCount = 0

    /** True between first-cover and lift — so the guardian is alerted ONCE per
     *  cover episode, not on every refresh tick. */
    @Volatile
    private var coverEpisodeActive = false

    private fun scanFrameForNsfw(pkg: String, frame: Bitmap) {
        val nsfw = Nsfw.obtain(this) ?: return // fail-open: no model → no image scan
        val region = nsfw.localize(frame) // null when no tile is flagged
        if (region != null && !region.isEmpty) {
            // STALE-SURFACE GUARD (worker-thread fast early-out): the screenshot +
            // inference take time, during which the foreground app can change. Skip
            // here if it already has — but the AUTHORITATIVE re-check and ALL
            // cover-state mutations (coverPkg, episode, alert) happen on the MAIN
            // thread inside showLocalizedOverlay, atomic with addView, so a callback
            // that passes this check then races an app switch can't cover the new
            // surface with the old region (codex).
            if (pkg != lastForegroundPkg) return
            showLocalizedOverlay(pkg, region, frame.width, frame.height)
        } else if (coverEpisodeActive) {
            // HYSTERESIS: do NOT drop the cover on a single clean frame — the
            // classifier is noisy per-frame and the offending content (esp. a
            // playing video) is often still on screen. Lift only after
            // CLEAN_LIFT_SCANS consecutive clean scans. This stops the cover
            // flickering/vanishing and the muted video audibly resuming.
            cleanScanCount++
            if (cleanScanCount >= CLEAN_LIFT_SCANS) {
                cleanScanCount = 0
                coverEpisodeActive = false
                Handler(Looper.getMainLooper()).post { removeLocalizedOverlay() }
            }
        }
    }

    private fun submit(pkg: String, thread: String, text: String) {
        val verdictJson = runCatching { RustBridge.analyzeText(pkg, thread, text) }
            .getOrDefault("{\"error\":\"bridge unavailable\"}")
        when {
            // HIGH-confidence / illegal -> disruptive on-screen block (+ alert).
            shouldBlock(verdictJson) -> {
                Log.w(TAG, "high-confidence harmful content in $pkg — blocking + alerting")
                blockContent()
                notifyGuardian(pkg, verdictJson)
            }
            // Borderline non-SAFE -> alert the guardian, but DON'T slam the screen.
            // The deterministic detector still fired and the parent is still told;
            // this just stops over-blocking benign-looking chat (the false-positive fix).
            isFlagged(verdictJson) -> {
                // Try a non-disruptive guardian alert. If it can't be delivered
                // (e.g. POST_NOTIFICATIONS not granted on Android 13+), FAIL SAFE:
                // block, so flagged content is never shown with no guardian signal.
                if (notifyGuardian(pkg, verdictJson)) {
                    Log.w(TAG, "borderline content in $pkg — guardian alerted (no block)")
                } else {
                    Log.w(TAG, "borderline content in $pkg — alert undeliverable, blocking (fail-safe)")
                    blockContent()
                }
            }
        }
    }

    /**
     * The disruptive on-screen block is reserved for HIGH-CONFIDENCE content: the
     * POLICY engine decided BLOCK, or it's suspected CSAM (illegal — always block).
     * Borderline grooming/adult verdicts are alerted, not blocked. The detector is
     * untouched (it still fired); only the *enforcement* is gated on confidence —
     * the deliberate fix for benign chat being slammed off the screen.
     */
    private fun shouldBlock(json: String): Boolean =
        json.contains("\"action\":\"BLOCK\"") || json.contains("\"CSAM")

    /** Any non-SAFE verdict — worth telling the guardian even if we don't block. */
    private fun isFlagged(json: String): Boolean =
        !json.contains("\"category\":\"SAFE\"") && !json.contains("\"error\"")

    /**
     * ENFORCE on the device: bounce off the harmful screen, cover it with a PH
     * Bulwark block notice, and sound an audible alert so it's unmistakable.
     * (Remote guardian alerting is wired with account linking.)
     */
    private fun blockContent() {
        Handler(Looper.getMainLooper()).post {
            performGlobalAction(GLOBAL_ACTION_HOME)
            playAlert()
            showBlockOverlay()
        }
    }

    private fun playAlert() {
        runCatching {
            val uri = android.media.RingtoneManager.getDefaultUri(android.media.RingtoneManager.TYPE_NOTIFICATION)
            android.media.RingtoneManager.getRingtone(applicationContext, uri)?.play()
        }
    }

    /**
     * Quietly alert the guardian about a flagged detection: a status-bar
     * notification carrying the policy's CONTENT-FREE reason (never the message
     * text). Best-effort + non-disruptive — the remote/parent-app alert rides the
     * account-linked path; this is the local signal so a borderline detection
     * isn't silent just because we chose not to block the screen.
     */
    private fun notifyGuardian(pkg: String, json: String): Boolean {
        return runCatching {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as android.app.NotificationManager
            // On Android 13+ the notification is silently dropped without the
            // POST_NOTIFICATIONS runtime grant. If alerts can't reach the guardian,
            // report failure so the caller fails SAFE (blocks) rather than passing
            // flagged content with no signal at all.
            if (!nm.areNotificationsEnabled()) return@runCatching false
            val channelId = "ph_bulwark_alerts"
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                nm.createNotificationChannel(
                    android.app.NotificationChannel(
                        channelId, "PH Bulwark alerts",
                        android.app.NotificationManager.IMPORTANCE_HIGH,
                    ),
                )
            }
            val reason = Regex("\"reason\":\"([^\"]*)\"").find(json)?.groupValues?.get(1)
                ?: "Flagged content detected"
            val builder = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                android.app.Notification.Builder(this, channelId)
            } else {
                @Suppress("DEPRECATION")
                android.app.Notification.Builder(this)
            }
            val notification = builder
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle("PH Bulwark — content flagged")
                .setContentText(reason)
                .setAutoCancel(true)
                .build()
            nm.notify(pkg.hashCode(), notification)
            true
        }.getOrDefault(false)
    }

    private var overlay: View? = null

    private fun showBlockOverlay() {
        if (overlay != null) return
        val wm = getSystemService(Context.WINDOW_SERVICE) as WindowManager
        val root = FrameLayout(this).apply { setBackgroundColor(0xFF0F3D5C.toInt()) }
        root.addView(
            TextView(this).apply {
                text = "🛡️\n\nBlocked by PH Bulwark\nThis content was flagged as unsafe."
                setTextColor(Color.WHITE); textSize = 22f; gravity = Gravity.CENTER
                setPadding(48, 48, 48, 48)
            },
            FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
                .apply { gravity = Gravity.CENTER },
        )
        val lp = WindowManager.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
            PixelFormat.OPAQUE,
        )
        runCatching { wm.addView(root, lp); overlay = root }
        Handler(Looper.getMainLooper()).postDelayed({ removeOverlay() }, 3000)
    }

    private fun removeOverlay() {
        overlay?.let { v -> runCatching { (getSystemService(Context.WINDOW_SERVICE) as WindowManager).removeView(v) } }
        overlay = null
    }

    /** Separate handle from the full-screen [overlay] so an image cover and a
     *  full-screen block never clobber each other's lifecycle. */
    private var regionOverlay: View? = null

    /** Main-thread handler for the localized overlay. There is deliberately NO
     *  timed backstop that re-scans while a cover is up: the cover is an opaque
     *  TYPE_ACCESSIBILITY_OVERLAY, so any `takeScreenshot` taken while it is
     *  attached captures the COVER (which always scores clean) instead of the
     *  underlying image — a re-scan-under-cover would falsely read clean and
     *  re-expose the static explicit content (codex). Static content therefore
     *  just STAYS covered; the cover lifts only on (a) a clean scan driven by a
     *  real on-screen change (content/scroll/text event — when no cover yet
     *  occludes the new frame) or (b) a surface/window change (app switch / shade
     *  / launcher → surface-bound removal). */
    private val regionHandler = Handler(Looper.getMainLooper())

    private val audioManager by lazy {
        getSystemService(Context.AUDIO_SERVICE) as android.media.AudioManager
    }
    private var audioFocusRequest: android.media.AudioFocusRequest? = null

    /**
     * Silence the offending media WHILE a localized cover is up. Covering an adult
     * video must stop its SOUND too — not just hide the picture — so we request
     * EXCLUSIVE-transient audio focus, which pauses the foreground player (any app
     * that respects focus, e.g. a video). Idempotent while held; released by
     * [restoreAudio] when the cover lifts.
     */
    private fun muteOffendingAudio() {
        if (audioFocusRequest != null) return
        runCatching {
            val attrs = android.media.AudioAttributes.Builder()
                .setUsage(android.media.AudioAttributes.USAGE_MEDIA)
                .setContentType(android.media.AudioAttributes.CONTENT_TYPE_MOVIE)
                .build()
            val req = android.media.AudioFocusRequest.Builder(
                android.media.AudioManager.AUDIOFOCUS_GAIN_TRANSIENT_EXCLUSIVE,
            ).setAudioAttributes(attrs).build()
            // Only record the request as HELD when focus was actually granted —
            // otherwise a covered video would stay audible AND every refresh would
            // early-return (non-null) without retrying. On failure we leave it null
            // so the next overlay tick tries again.
            if (audioManager.requestAudioFocus(req) ==
                android.media.AudioManager.AUDIOFOCUS_REQUEST_GRANTED
            ) {
                audioFocusRequest = req
            }
        }
    }

    /** Release the audio focus when the cover lifts so media may resume. */
    private fun restoreAudio() {
        audioFocusRequest?.let { req -> runCatching { audioManager.abandonAudioFocusRequest(req) } }
        audioFocusRequest = null
    }

    /**
     * Cover ONLY [regionPx] (in frame-pixel coordinates) with an opaque
     * `TYPE_ACCESSIBILITY_OVERLAY`, leaving the rest of the screen visible and
     * usable — the localized counterpart to [showBlockOverlay] for the no-VPN
     * image-safety path. NEVER full-screen.
     *
     * Coordinate mapping: the captured frame may not be the exact WindowManager
     * pixel size, so we scale [regionPx] by the real display size / frame size
     * ratio and position the window with an explicit TOP|LEFT origin + explicit
     * width/height (NOT MATCH_PARENT — the default CENTER gravity would mis-place
     * the box). The window is focusable-not but touchable so the covered region
     * can't be tapped through; the surrounding screen stays interactive because
     * the window is only the rectangle.
     */
    private fun showLocalizedOverlay(pkg: String, regionPx: Rect, frameW: Int, frameH: Int) {
        if (frameW <= 0 || frameH <= 0) return
        regionHandler.post {
            // AUTHORITATIVE surface re-check on the MAIN thread, atomic with the
            // addView below: if the foreground changed between the worker-thread
            // scan and now (the user switched apps / opened the shade), do NOT add a
            // cover for the old surface over the new one (codex). A pending
            // surface-bound removal for the new window runs before this post, so
            // lastForegroundPkg is already the new app here.
            if (pkg != lastForegroundPkg) return@post
            val wm = getSystemService(Context.WINDOW_SERVICE) as WindowManager
            val (dispW, dispH) = realDisplaySize(wm)
            val sx = dispW.toFloat() / frameW
            val sy = dispH.toFloat() / frameH
            val left = (regionPx.left * sx).toInt().coerceIn(0, dispW)
            val top = (regionPx.top * sy).toInt().coerceIn(0, dispH)
            val right = (regionPx.right * sx).toInt().coerceIn(0, dispW)
            val bottom = (regionPx.bottom * sy).toInt().coerceIn(0, dispH)
            val w = (right - left).coerceAtLeast(1)
            val h = (bottom - top).coerceAtLeast(1)

            // Reuse the existing region overlay if present; just move/resize it.
            val view = regionOverlay ?: FrameLayout(this).apply {
                setBackgroundColor(0xFF0F3D5C.toInt())
                addView(
                    TextView(this@BulwarkAccessibilityService).apply {
                        text = "🛡️ Covered by PH Bulwark"
                        setTextColor(Color.WHITE); textSize = 13f; gravity = Gravity.CENTER
                        setPadding(16, 16, 16, 16)
                    },
                    FrameLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT,
                    ).apply { gravity = Gravity.CENTER },
                )
            }
            val lp = WindowManager.LayoutParams(
                w, h,
                left, top,
                WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
                PixelFormat.OPAQUE,
            ).apply { gravity = Gravity.TOP or Gravity.START }

            val attached = runCatching {
                if (regionOverlay == null) {
                    wm.addView(view, lp)
                    regionOverlay = view
                } else {
                    wm.updateViewLayout(view, lp)
                }
            }.isSuccess
            // If WindowManager failed there is NO cover on screen — do not record a
            // phantom episode or grab exclusive audio focus, which would leave media
            // muted with no visible cover until some unrelated later event (codex).
            // Clean up any partial state and bail.
            if (!attached || regionOverlay == null) {
                removeLocalizedOverlay()
                return@post
            }
            // Cover is on screen for THIS surface — record cover state HERE on the
            // main thread (atomic with addView), so a stale worker callback or a
            // racing surface change can't desync coverPkg/episode from what's
            // actually displayed. Bind the cover to the surface (drop on app change)
            // and reset the clean streak.
            coverPkg = pkg
            cleanScanCount = 0
            if (!coverEpisodeActive) {
                coverEpisodeActive = true
                Log.w(TAG, "sexual/explicit imagery in $pkg — covering region (localized)")
                // Content-free guardian signal — once per episode, not per tick.
                notifyGuardian(pkg, "{\"reason\":\"Explicit image covered\"}")
            }
            // Stop the offending media's SOUND too (covering an adult video must
            // silence it, not just hide the picture). Idempotent while held.
            muteOffendingAudio()
        }
    }

    private fun removeLocalizedOverlay() {
        regionOverlay?.let { v -> runCatching { (getSystemService(Context.WINDOW_SERVICE) as WindowManager).removeView(v) } }
        regionOverlay = null
        // End the episode so the next cover re-alerts and the clean streak starts fresh.
        coverEpisodeActive = false
        cleanScanCount = 0
        coverPkg = null
        // Cover lifted → let media resume.
        restoreAudio()
    }

    /** Real display size in pixels (incl. system bars) — the frame `takeScreenshot`
     *  captures spans the full display, so this is the mapping target. */
    @Suppress("DEPRECATION")
    private fun realDisplaySize(wm: WindowManager): Pair<Int, Int> {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val b = wm.currentWindowMetrics.bounds
            return b.width() to b.height()
        }
        val p = android.graphics.Point()
        wm.defaultDisplay.getRealSize(p)
        return p.x to p.y
    }

    /**
     * On an installer / Settings screen, if the visible text is about removing the
     * Bulwark app, raise an `APP_UNINSTALL_ATTEMPT` alert and navigate Home. This is
     * FRICTION + DETECTION, not an absolute block — a determined user can still
     * proceed (and on Device Owner the uninstall is blocked outright), but the
     * guardian is always told.
     */
    private fun guardAgainstUninstall() {
        val root = rootInActiveWindow ?: return
        val screen = collectText(root).lowercase()
        // The app's user-facing label is "PH Bulwark"; the package id is ...bulwark.
        val mentionsApp = screen.contains("bulwark") || screen.contains("bulwark")
        val isUninstall = screen.contains("uninstall") || screen.contains("do you want to uninstall")
        if (mentionsApp && isUninstall) {
            Log.w(TAG, "uninstall attempt detected on PH Bulwark — alerting guardian")
            TamperReporter.report(this, TamperReporter.APP_UNINSTALL_ATTEMPT)
            performGlobalAction(GLOBAL_ACTION_HOME)
        }
    }

    private fun collectText(node: AccessibilityNodeInfo): String {
        val sb = StringBuilder()
        node.text?.let { sb.append(it).append(' ') }
        for (i in 0 until node.childCount) {
            node.getChild(i)?.let { sb.append(collectText(it)) }
        }
        return sb.toString()
    }

    /** Best-effort stable per-conversation id so the grooming state machine can
     *  correlate messages across a thread. Refined per app over time. */
    private fun threadIdFor(root: AccessibilityNodeInfo, pkg: String): String =
        "$pkg:${root.window?.title ?: root.hashCode()}"

    override fun onInterrupt() {}

    companion object {
        private const val TAG = "BulwarkA11y"

        /** Minimum gap between screenshots (OS rate-limits `takeScreenshot` ~1/s).
         *  Scans are EVENT-DRIVEN (content-change / text / scroll) — there is no
         *  periodic polling timer (deliberate: covering is reactive to on-screen
         *  changes only, never a background poll). */
        private const val CAPTURE_MIN_GAP_MS = 1000L

        /** OCR sub-throttle: Tesseract is heavy, so OCR runs at most this often even
         *  though the NSFW image pass runs on every capture. */
        private const val OCR_MIN_GAP_MS = 6000L

        /** Consecutive CLEAN scans before lifting a cover. 1 = lift as soon as one
         *  scan after a content change comes back clean (content scrolled away /
         *  changed) — the wide model gap (benign ≤0.64, explicit ≥0.89) makes a
         *  false-clean very unlikely, so no multi-scan hysteresis is needed. The
         *  cover is also dropped instantly on any app/window change (surface-bound). */
        private const val CLEAN_LIFT_SCANS = 1

        // Apps the network can't read (E2E / cert-pinned) → on-device capture path.
        private val MONITORED = setOf(
            "com.whatsapp",
            "org.thoughtcrime.securesms",   // Signal
            "com.facebook.orca",            // Messenger
            "com.instagram.android",
            "com.snapchat.android",
            "org.telegram.messenger",
        )

        // Surfaces an app-removal flows through — watched by the uninstall-guard.
        private val UNINSTALL_SURFACES = setOf(
            "com.google.android.packageinstaller",
            "com.android.packageinstaller",
            "com.android.settings",
        )
    }
}
