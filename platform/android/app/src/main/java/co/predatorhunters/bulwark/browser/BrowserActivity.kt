package co.predatorhunters.bulwark.browser

import android.annotation.SuppressLint
import android.os.Bundle
import android.view.WindowManager
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import co.predatorhunters.bulwark.Ink
import co.predatorhunters.bulwark.Mist
import co.predatorhunters.bulwark.Navy
import co.predatorhunters.bulwark.Sky
import co.predatorhunters.bulwark.core.RustBridge

private val Colors = lightColorScheme(
    primary = Navy,
    onPrimary = Color.White,
    secondary = Sky,
    background = Mist,
    onBackground = Ink,
    surface = Color.White,
    onSurface = Ink,
)

/**
 * The PH Bulwark Browser — a guarded in-app web view that can see a page's FULL
 * rendered content (including off-viewport) and pre-cover unsafe content BEFORE
 * the child reads it. This is the thing a plain VPN can't do for HTTPS without
 * Device Owner: the page is decrypted and rendered locally, so the injected
 * extraction script reads the live DOM and the app's existing on-device
 * classifiers check each text run and image as it loads.
 *
 * Pipeline (see [BrowserContentFilter] + `res/raw/bulwark_browser.js`):
 *   load URL -> inject extraction JS on page finish -> JS walks DOM (text + img,
 *   visible + off-screen) -> native classifiers -> on a hit, JS draws an opaque
 *   in-page cover over that element; a predominantly-flagged page shows a calm
 *   full-screen block notice.
 *
 * [WindowManager.LayoutParams.FLAG_SECURE] is set before `setContent` so the
 * window is excluded from screenshots, screen recording, the recents thumbnail,
 * and non-secure displays (same as the Camera activity). HONEST LIMIT: it can't
 * stop a second physical device photographing the screen.
 */
class BrowserActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No frame of inspected web content is ever capturable. Set before setContent.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        // The text classifier rides the JNI core — load it once up front so the
        // first analyzeText call can't UnsatisfiedLinkError.
        runCatching { RustBridge.ensureLoaded() }

        setContent {
            MaterialTheme(colorScheme = Colors) {
                Surface(Modifier.fillMaxSize(), color = Mist) {
                    BrowserScreen(onClose = ::finish)
                }
            }
        }
    }
}

private const val START_URL = "https://www.wikipedia.org/"

@Composable
private fun BrowserScreen(onClose: () -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var urlField by remember { mutableStateOf(START_URL) }
    var progress by remember { mutableStateOf(0) }
    var pageBlocked by remember { mutableStateOf(false) }
    var webView by remember { mutableStateOf<WebView?>(null) }

    // The injected page script (read once from res/raw).
    val injectedJs = remember {
        runCatching {
            context.resources.openRawResource(
                co.predatorhunters.bulwark.R.raw.bulwark_browser,
            ).bufferedReader().use { it.readText() }
        }.getOrDefault("")
    }

    // The classify-and-censor brain. onCensor / onBlockPage marshal back to the
    // UI thread (evaluateJavascript + Compose state must touch the main thread).
    val filter = remember {
        BrowserContentFilter(
            context = context,
            onCensor = { id ->
                webView?.post {
                    webView?.evaluateJavascript("window.__bulwarkCensor && __bulwarkCensor('$id')", null)
                }
            },
            onBlockPage = {
                webView?.post { pageBlocked = true }
            },
        )
    }

    BackHandler(enabled = true) {
        val wv = webView
        when {
            pageBlocked -> onClose()
            wv != null && wv.canGoBack() -> wv.goBack()
            else -> onClose()
        }
    }

    Column(Modifier.fillMaxSize()) {
        // --- URL / address bar ---------------------------------------------
        Row(
            Modifier
                .fillMaxWidth()
                .padding(8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedTextField(
                value = urlField,
                onValueChange = { urlField = it },
                singleLine = true,
                modifier = Modifier.weight(1f),
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Go),
                keyboardActions = KeyboardActions(onGo = {
                    pageBlocked = false
                    webView?.loadUrl(normalizeUrl(urlField))
                }),
            )
            Button(onClick = {
                pageBlocked = false
                webView?.loadUrl(normalizeUrl(urlField))
            }) { Text("Go") }
        }

        if (progress in 1..99) {
            LinearProgressIndicator(
                progress = { progress / 100f },
                modifier = Modifier.fillMaxWidth(),
            )
        }

        // --- WebView + (conditional) full-page block notice ----------------
        Box(Modifier.fillMaxSize()) {
            AndroidView(
                modifier = Modifier.fillMaxSize(),
                factory = { ctx ->
                    makeWebView(
                        ctx = ctx,
                        filter = filter,
                        injectedJs = injectedJs,
                        onProgress = { progress = it },
                        onUrlChanged = { urlField = it },
                        onPageStarted = { pageBlocked = false },
                    ).also { webView = it; it.loadUrl(START_URL) }
                },
            )

            if (pageBlocked) {
                PageBlockedNotice(
                    onBack = {
                        val wv = webView
                        if (wv != null && wv.canGoBack()) {
                            pageBlocked = false
                            wv.goBack()
                        } else {
                            onClose()
                        }
                    },
                )
            }
        }
    }
}

/**
 * Build the guarded WebView: JavaScript on (the extraction script needs it),
 * the [BrowserContentFilter] bound as `BulwarkBridge`, and a client that injects
 * the extraction JS on every page finish + resets the per-page filter state on
 * each new navigation.
 */
@SuppressLint("SetJavaScriptEnabled")
private fun makeWebView(
    ctx: android.content.Context,
    filter: BrowserContentFilter,
    injectedJs: String,
    onProgress: (Int) -> Unit,
    onUrlChanged: (String) -> Unit,
    onPageStarted: () -> Unit,
): WebView = WebView(ctx).apply {
    settings.javaScriptEnabled = true
    settings.domStorageEnabled = true
    settings.loadsImagesAutomatically = true
    // TODO(hardening): WebView.setWebContentsDebuggingEnabled(false) for release;
    // a curated allow/deny host list; safe-browsing; download handling.
    addJavascriptInterface(filter, "BulwarkBridge")

    webChromeClient = object : android.webkit.WebChromeClient() {
        override fun onProgressChanged(view: WebView?, newProgress: Int) {
            onProgress(newProgress)
        }
    }

    webViewClient = object : WebViewClient() {
        override fun onPageStarted(view: WebView?, url: String?, favicon: android.graphics.Bitmap?) {
            // New page -> drop the previous page's dedupe + flagged-ratio totals.
            filter.reset()
            onPageStarted()
            url?.let(onUrlChanged)
        }

        override fun onPageFinished(view: WebView?, url: String?) {
            // Inject the full-content extraction + censor bridge once the DOM exists.
            if (injectedJs.isNotEmpty()) view?.evaluateJavascript(injectedJs, null)
            url?.let(onUrlChanged)
        }

        // Keep navigations inside this guarded WebView (don't hand off to an
        // external browser, which would escape the content pre-check).
        override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
            val u = request?.url?.toString() ?: return false
            return if (u.startsWith("http://") || u.startsWith("https://")) {
                view?.loadUrl(u); true
            } else {
                true // swallow non-http(s) schemes (mailto:, intent:, …) — don't leave.
            }
        }
    }
}

/** Calm, child-appropriate full-page block screen (the "predominantly flagged" case). */
@Composable
private fun PageBlockedNotice(onBack: () -> Unit) {
    Surface(Modifier.fillMaxSize(), color = Navy) {
        Column(
            Modifier
                .fillMaxSize()
                .padding(32.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text("🛡️", fontSize = 56.sp)
            Text(
                "This page was blocked",
                color = Color.White,
                fontSize = 24.sp,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 16.dp),
            )
            Text(
                "PH Bulwark hid this page because it looked unsafe. Let's go somewhere else.",
                color = Color.White,
                fontSize = 16.sp,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 12.dp),
            )
            Button(onClick = onBack, modifier = Modifier.padding(top = 24.dp)) {
                Text("Go back")
            }
        }
    }
}

/** Accept a bare host ("example.com") or a full URL; default to https. */
private fun normalizeUrl(input: String): String {
    val t = input.trim()
    return when {
        t.isEmpty() -> START_URL
        t.startsWith("http://") || t.startsWith("https://") -> t
        else -> "https://$t"
    }
}
