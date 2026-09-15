package com.eratguard.pro.app

import android.annotation.SuppressLint
import android.graphics.Bitmap
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.webkit.CookieManager
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.compose.BackHandler
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import com.eratguard.pro.R
import com.eratguard.pro.screens.SmsCenterScreen
import kotlinx.coroutines.delay

private const val ERATGUARD_PANEL =
    "https://app.eratguard.com/dashboard"

@SuppressLint("SetJavaScriptEnabled")
@Composable
fun EratGuardApp() {

    var webView: WebView? by remember { mutableStateOf(null) }

    var showSplash by remember { mutableStateOf(true) }
    val splashStartedAt = remember { SystemClock.elapsedRealtime() }

    // Compose splash en az 10 saniye görünür.
    // WebView hazır değilse %99'da bekler; Render kullanıcıya gösterilmez.
    val minimumSplashMs = 13000L

    var progress by remember { mutableIntStateOf(0) }
    var statusText by remember {
        mutableStateOf("ERATGUARD ÇEKİRDEĞİ BAŞLATILIYOR...")
    }

    var webReady by remember { mutableStateOf(false) }

    var showNativeSms by remember { mutableStateOf(false) }

    val handler = remember {
        Handler(Looper.getMainLooper())
    }

    /*
     * Splash progress WebView progress'inden bağımsızdır.
     * 10 saniyede 0 -> 99 ilerler.
     * WebView gerçekten hazır olduğunda 100 olur ve kapanır.
     */
    LaunchedEffect(showSplash, webReady) {
        if (!showSplash) return@LaunchedEffect

        while (showSplash) {
            val elapsed =
                SystemClock.elapsedRealtime() - splashStartedAt

            val timedProgress =
                ((elapsed * 99L) / minimumSplashMs)
                    .coerceIn(0L, 99L)
                    .toInt()

            progress = timedProgress

            statusText =
                when {
                    elapsed < 2200L ->
                        "ERATGUARD ÇEKİRDEĞİ BAŞLATILIYOR..."

                    elapsed < 4800L ->
                        "YAPAY ZEKA MODÜLLERİ YÜKLENİYOR..."

                    elapsed < 7200L ->
                        "GÜVENLİK KATMANLARI DOĞRULANIYOR..."

                    elapsed < minimumSplashMs ->
                        "KORUMA ÇEKİRDEĞİ HAZIRLANIYOR..."

                    !webReady ->
                        "GÜVENLİ BAĞLANTI TAMAMLANIYOR..."

                    else ->
                        "ERATGUARD HAZIR"
                }

            if (elapsed >= minimumSplashMs && webReady) {
                progress = 100
                statusText = "ERATGUARD HAZIR"

                android.util.Log.i(
                    "ERATGUARD_TIMING",
                    "SPLASH_COMPLETE elapsed=${elapsed}ms"
                )

                delay(450L)
                showSplash = false
                break
            }

            delay(50L)
        }
    }

    if (showNativeSms) {
        SmsCenterScreen(
            onBack = {
                showNativeSms = false
            }
        )
        return
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF02070D))
    ) {

        AndroidView(
            modifier = Modifier.fillMaxSize(),

            factory = { context ->

                WebView(context).apply {

                    setBackgroundColor(
                        android.graphics.Color.rgb(2, 7, 13)
                    )

                    settings.javaScriptEnabled = true
                    settings.domStorageEnabled = true
                    settings.loadsImagesAutomatically = true
                    settings.useWideViewPort = true
                    settings.loadWithOverviewMode = false
                    settings.setSupportZoom(false)
                    settings.builtInZoomControls = false
                    settings.displayZoomControls = false

                    CookieManager
                        .getInstance()
                        .setAcceptCookie(true)

                    CookieManager
                        .getInstance()
                        .setAcceptThirdPartyCookies(this, true)

                    webChromeClient =
                        object : WebChromeClient() {
                            override fun onProgressChanged(
                                view: WebView?,
                                newProgress: Int
                            ) {
                                // WebView arka planda yüklenir.
                                // Splash progress zaman tabanlıdır.
                            }
                        }

                    webViewClient =
                        object : WebViewClient() {

                            override fun shouldOverrideUrlLoading(
                                view: WebView?,
                                request: WebResourceRequest?
                            ): Boolean {

                                val path =
                                    request?.url?.path.orEmpty()

                                if (
                                    path.equals(
                                        "/sms",
                                        ignoreCase = true
                                    ) ||
                                    path.contains(
                                        "sms-center",
                                        ignoreCase = true
                                    ) ||
                                    path.contains(
                                        "sms-actions-center",
                                        ignoreCase = true
                                    )
                                ) {
                                    showNativeSms = true
                                    return true
                                }

                                return false
                            }

                            override fun onPageStarted(
                                view: WebView?,
                                url: String?,
                                favicon: Bitmap?
                            ) {
                                if (showSplash) {
                                    statusText =
                                        "ERATGUARD AĞINA BAĞLANILIYOR..."
                                }
                            }

                            override fun onPageFinished(
                                view: WebView?,
                                url: String?
                            ) {
                                CookieManager
                                    .getInstance()
                                    .flush()

                                /*
                                 * Render'ın ara yükleme sayfasını
                                 * kullanıcıya göstermiyoruz.
                                 */
                                view?.evaluateJavascript(
                                    """
                                    (function() {
                                        var t =
                                            (document.body &&
                                             document.body.innerText)
                                             ? document.body.innerText
                                             : '';

                                        return t.substring(0, 4000);
                                    })();
                                    """.trimIndent()
                                ) { result ->

                                    val text =
                                        result
                                            .orEmpty()
                                            .lowercase()

                                    val renderLoading =
                                        text.contains(
                                            "application loading"
                                        ) ||
                                        text.contains(
                                            "render.com"
                                        )

                                    val currentUrl =
                                        url.orEmpty()

                                    val trustedEratGuardPage =
                                        try {
                                            val parsed =
                                                android.net.Uri.parse(
                                                    currentUrl
                                                )

                                            parsed.scheme.equals(
                                                "https",
                                                ignoreCase = true
                                            ) &&
                                            parsed.host.equals(
                                                "app.eratguard.com",
                                                ignoreCase = true
                                            )
                                        } catch (_: Exception) {
                                            false
                                        }

                                    val eratGuardContentReady =
                                        text.contains(
                                            "eratguard"
                                        ) &&
                                        (
                                            text.contains(
                                                "ana koruma"
                                            ) ||
                                            text.contains(
                                                "pro notification control"
                                            ) ||
                                            text.contains(
                                                "sistem aktif"
                                            )
                                        )

                                    val authPageReady =
                                        trustedEratGuardPage &&
                                        (
                                            currentUrl.contains(
                                                "/login",
                                                ignoreCase = true
                                            ) ||
                                            currentUrl.contains(
                                                "/register",
                                                ignoreCase = true
                                            ) ||
                                            currentUrl.contains(
                                                "/forgot-password",
                                                ignoreCase = true
                                            ) ||
                                            currentUrl.contains(
                                                "/reset-password",
                                                ignoreCase = true
                                            )
                                        ) &&
                                        text.contains("eratguard")

                                    val eratGuardReady =
                                        eratGuardContentReady ||
                                        authPageReady

                                    if (eratGuardReady) {

                                        if (!webReady) {
                                            android.util.Log.i(
                                                "ERATGUARD_TIMING",
                                                "READY elapsed=" +
                                                    (SystemClock.elapsedRealtime() - splashStartedAt) +
                                                    "ms"
                                            )
                                        }

                                        webReady = true

                                    } else if (renderLoading) {

                                        android.util.Log.i(
                                            "ERATGUARD_TIMING",
                                            "RENDER_LOADING elapsed=" +
                                                (SystemClock.elapsedRealtime() - splashStartedAt) +
                                                "ms"
                                        )

                                        handler.postDelayed({

                                            if (showSplash) {
                                                view?.loadUrl(
                                                    ERATGUARD_PANEL
                                                )
                                            }

                                        }, 2500)

                                    }
                                }
                            }
                        }

                    webView = this

                    loadUrl(ERATGUARD_PANEL)
                }
            }
        )

        // Yeni PNG'siz Compose/Canvas EratGuard Splash.
        // WebView arka planda yüklenmeye devam eder.
        if (showSplash) {
            EratGuardSplash(
                progress = progress,
                statusText = statusText
            )
        }
    }

    BackHandler(
        enabled =
            !showSplash &&
            webView?.canGoBack() == true
    ) {
        webView?.goBack()
    }

    DisposableEffect(Unit) {

        onDispose {

            handler.removeCallbacksAndMessages(null)

            webView?.stopLoading()
            webView?.destroy()
            webView = null
        }
    }
}
