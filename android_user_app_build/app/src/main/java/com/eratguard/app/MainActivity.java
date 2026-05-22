package com.eratguard.app;

import android.app.Activity;
import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Build;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.ClipDrawable;
import android.graphics.drawable.LayerDrawable;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.DecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.animation.ValueAnimator;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceError;
import android.webkit.ValueCallback;

public class MainActivity extends Activity {
    private WebView webView;
    private FrameLayout root;
    private FrameLayout splashView;

    private TextView splashPercent;
    private TextView splashStatus;
    private TextView splashSubStatus;
    private ProgressBar splashProgress;

    private int renderRetryCount = 0;
    private int currentProgress = 0;
    private boolean firstRealPageShown = false;
    private Handler mainHandler;

    private static final String APP_URL = "https://spamshield-peld.onrender.com/app-start";
    private static final String MAIN_HOST = "https://spamshield-peld.onrender.com";


    private void requestProtectionPermissions() {
        if (Build.VERSION.SDK_INT >= 23) {
            java.util.ArrayList<String> permissions = new java.util.ArrayList<>();

            if (checkSelfPermission(Manifest.permission.RECEIVE_SMS) != PackageManager.PERMISSION_GRANTED) {
                permissions.add(Manifest.permission.RECEIVE_SMS);
            }

            if (Build.VERSION.SDK_INT >= 33 &&
                    checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                permissions.add(Manifest.permission.POST_NOTIFICATIONS);
            }

            if (!permissions.isEmpty()) {
                requestPermissions(permissions.toArray(new String[0]), 701);
            }
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mainHandler = new Handler(Looper.getMainLooper());

        root = new FrameLayout(this);
        setContentView(root);

        showSplash();

        mainHandler.postDelayed(new Runnable() {
            @Override
            public void run() {
                showWebView();
            }
        }, 450);
    }

    private TextView makeText(String text, int sp, int color, boolean bold) {
        TextView v = new TextView(this);
        v.setText(text);
        v.setTextSize(sp);
        v.setTextColor(color);
        v.setGravity(Gravity.CENTER);
        if (bold) v.setTypeface(Typeface.DEFAULT_BOLD);
        return v;
    }

    private GradientDrawable roundedBg(int color, int strokeColor, int radius, int strokeWidth) {
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(color);
        bg.setCornerRadius(radius);
        bg.setStroke(strokeWidth, strokeColor);
        return bg;
    }

    private void showSplash() {
        splashView = new FrameLayout(this);
        splashView.setBackgroundColor(Color.rgb(1, 8, 5));

        ImageView art = new ImageView(this);
        art.setImageResource(R.drawable.splash_art);
        art.setAdjustViewBounds(true);
        art.setScaleType(ImageView.ScaleType.FIT_CENTER);

        splashView.addView(
                art,
                new FrameLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.MATCH_PARENT
                )
        );

        LinearLayout panel = new LinearLayout(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        panel.setPadding(dp(18), dp(14), dp(18), dp(14));
        panel.setBackground(
                roundedBg(
                        Color.argb(190, 2, 15, 8),
                        Color.argb(150, 135, 255, 50),
                        dp(18),
                        1
                )
        );

        splashStatus = makeText("Güvenli açılış başlatılıyor", 15, Color.WHITE, true);
        splashStatus.setGravity(Gravity.LEFT);

        splashSubStatus = makeText("EratGuard koruma ortamı hazırlanıyor...", 12, Color.rgb(210, 230, 205), false);
        splashSubStatus.setGravity(Gravity.LEFT);
        splashSubStatus.setPadding(0, dp(4), 0, dp(8));

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);

        splashProgress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        splashProgress.setMax(100);
        splashProgress.setProgress(0);
        splashProgress.setProgressDrawable(makeProgressDrawable());

        LinearLayout.LayoutParams barLp = new LinearLayout.LayoutParams(0, dp(12), 1);
        barLp.setMargins(0, 0, dp(12), 0);
        row.addView(splashProgress, barLp);

        splashPercent = makeText("%0", 16, Color.rgb(145, 255, 45), true);
        splashPercent.setGravity(Gravity.RIGHT);
        row.addView(
                splashPercent,
                new LinearLayout.LayoutParams(dp(56), ViewGroup.LayoutParams.WRAP_CONTENT)
        );

        panel.addView(splashStatus);
        panel.addView(splashSubStatus);
        panel.addView(row);

        FrameLayout.LayoutParams panelLp = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM
        );
        panelLp.setMargins(dp(22), 0, dp(22), dp(34));

        splashView.addView(panel, panelLp);

        root.addView(
                splashView,
                new FrameLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.MATCH_PARENT
                )
        );

        updateSplashProgress(7, "EratGuard başlatılıyor", "Güvenli ortam hazırlanıyor...");
    }

    private LayerDrawable makeProgressDrawable() {
        GradientDrawable background = new GradientDrawable();
        background.setColor(Color.argb(90, 255, 255, 255));
        background.setCornerRadius(dp(8));

        GradientDrawable progress = new GradientDrawable(
                GradientDrawable.Orientation.LEFT_RIGHT,
                new int[] {
                        Color.rgb(90, 220, 20),
                        Color.rgb(160, 255, 45),
                        Color.rgb(215, 255, 80)
                }
        );
        progress.setCornerRadius(dp(8));

        ClipDrawable clip = new ClipDrawable(progress, Gravity.LEFT, ClipDrawable.HORIZONTAL);

        LayerDrawable layer = new LayerDrawable(new android.graphics.drawable.Drawable[] {
                background,
                clip
        });
        layer.setId(0, android.R.id.background);
        layer.setId(1, android.R.id.progress);
        return layer;
    }

    private void updateSplashProgress(final int target, String status, String subStatus) {
        if (splashView == null || splashProgress == null) return;

        int safeTarget = Math.max(0, Math.min(100, target));
        if (safeTarget < currentProgress) safeTarget = currentProgress;

        if (splashStatus != null) splashStatus.setText(status);
        if (splashSubStatus != null) splashSubStatus.setText(subStatus);

        ValueAnimator animator = ValueAnimator.ofInt(currentProgress, safeTarget);
        animator.setDuration(360);
        animator.setInterpolator(new DecelerateInterpolator());
        animator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
            @Override
            public void onAnimationUpdate(ValueAnimator animation) {
                int value = (Integer) animation.getAnimatedValue();
                currentProgress = value;
                if (splashProgress != null) splashProgress.setProgress(value);
                if (splashPercent != null) splashPercent.setText("%" + value);
            }
        });
        animator.start();
    }

    private String statusForProgress(int p) {
        if (p < 18) return "EratGuard başlatılıyor";
        if (p < 35) return "Güvenli bağlantı kuruluyor";
        if (p < 55) return "Koruma modülleri hazırlanıyor";
        if (p < 72) return "Lisans ve oturum kontrol ediliyor";
        if (p < 90) return "Arayüz güvenli şekilde yükleniyor";
        return "Son kontroller yapılıyor";
    }

    private String subStatusForProgress(int p) {
        if (p < 18) return "Uygulama çekirdeği hazırlanıyor...";
        if (p < 35) return "Sunucu ile şifreli bağlantı kuruluyor...";
        if (p < 55) return "Risk analizi ve güvenlik bileşenleri hazırlanıyor...";
        if (p < 72) return "Kullanıcı ekranı ve lisans merkezi kontrol ediliyor...";
        if (p < 90) return "EratGuard arayüzü açılışa hazırlanıyor...";
        return "Neredeyse hazır, güvenli açılış tamamlanıyor...";
    }

    private void showWebView() {
        updateSplashProgress(12, "Güvenli bağlantı hazırlanıyor", "EratGuard sunucusuna bağlanılıyor...");

        webView = new WebView(this);
        webView.setVisibility(View.INVISIBLE);

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(true);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setSupportZoom(false);
        settings.setBuiltInZoomControls(false);
        settings.setDisplayZoomControls(false);
        settings.setLoadWithOverviewMode(true);
        settings.setUseWideViewPort(true);
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            settings.setSafeBrowsingEnabled(true);
        }

        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onProgressChanged(WebView view, int newProgress) {
                super.onProgressChanged(view, newProgress);

                if (firstRealPageShown) return;

                int mapped = 15 + (int) (newProgress * 0.76);
                if (mapped > 92) mapped = 92;

                updateSplashProgress(
                        mapped,
                        statusForProgress(mapped),
                        subStatusForProgress(mapped)
                );
            }
        });

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                String url = request.getUrl().toString();

                if (url.startsWith("https://spamshield-peld.onrender.com") || url.startsWith("https://eratshield.com")) {
                    return false;
                }

                return true;
            }

            @Override
            public void onPageStarted(WebView view, String url, android.graphics.Bitmap favicon) {
                super.onPageStarted(view, url, favicon);

                if (!firstRealPageShown) {
                    updateSplashProgress(
                            Math.max(currentProgress, 18),
                            "Güvenli bağlantı kuruluyor",
                            "EratGuard canlı servisleri kontrol ediliyor..."
                    );
                }
            }

            @Override
            public void onPageFinished(final WebView view, String url) {
                super.onPageFinished(view, url);

                if (firstRealPageShown || url == null || !url.startsWith(MAIN_HOST)) {
                    return;
                }

                updateSplashProgress(
                        Math.max(currentProgress, 88),
                        "Son kontroller yapılıyor",
                        "Render ve EratGuard arayüzü doğrulanıyor..."
                );

                view.evaluateJavascript(
                        "(function(){return ((document.title||'')+'\\n'+(document.body?document.body.innerText:''));})();",
                        new ValueCallback<String>() {
                            @Override
                            public void onReceiveValue(String value) {
                                String text = value == null ? "" : value.toLowerCase();

                                boolean renderColdStart =
                                        text.contains("render") ||
                                        text.contains("application loading") ||
                                        text.contains("incoming http request detected") ||
                                        text.contains("service waking up") ||
                                        text.contains("allocating compute resources") ||
                                        text.contains("preparing instance") ||
                                        text.contains("almost live");

                                if (renderColdStart) {
                                    view.setVisibility(View.INVISIBLE);

                                    int retryProgress = 72 + Math.min(18, renderRetryCount);
                                    updateSplashProgress(
                                            retryProgress,
                                            "Güvenli servisler hazırlanıyor",
                                            "EratGuard koruma sistemi başlatılıyor. Lütfen bekleyin..."
                                    );

                                    if (renderRetryCount < 20) {
                                        renderRetryCount++;
                                        mainHandler.postDelayed(new Runnable() {
                                            @Override
                                            public void run() {
                                                if (!firstRealPageShown && webView != null) {
                                                    webView.reload();
                                                }
                                            }
                                        }, 3500);
                                    } else {
                                        updateSplashProgress(
                                                92,
                                                "Bağlantı bekleniyor",
                                                "Sunucu geç yanıt verdi. Tekrar deneniyor..."
                                        );
                                    }
                                    return;
                                }

                                firstRealPageShown = true;
                                renderRetryCount = 0;

                                updateSplashProgress(
                                        100,
                                        "Güvenli açılış tamamlandı",
                                        "EratGuard hazır. Ana ekran açılıyor..."
                                );

                                mainHandler.postDelayed(new Runnable() {
                                    @Override
                                    public void run() {
                                        view.setVisibility(View.VISIBLE);

                                        if (splashView != null) {
                                            splashView.animate()
                                                    .alpha(0f)
                                                    .setDuration(280)
                                                    .withEndAction(new Runnable() {
                                                        @Override
                                                        public void run() {
                                                            if (splashView != null) {
                                                                root.removeView(splashView);
                                                                splashView = null;
                                                            }
                                                        }
                                                    })
                                                    .start();
                                        }
                                    }
                                }, 420);
                            }
                        }
                );
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                super.onReceivedError(view, request, error);

                if (!firstRealPageShown) {
                    updateSplashProgress(
                            Math.max(currentProgress, 35),
                            "Bağlantı tekrar deneniyor",
                            "Ağ veya sunucu yanıtı bekleniyor. EratGuard yeniden deniyor..."
                    );

                    mainHandler.postDelayed(new Runnable() {
                        @Override
                        public void run() {
                            if (!firstRealPageShown && webView != null) {
                                webView.reload();
                            }
                        }
                    }, 3500);
                }
            }
        });

        root.addView(
                webView,
                0,
                new FrameLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.MATCH_PARENT
                )
        );

        webView.clearCache(true);
        webView.clearHistory();
        webView.loadUrl(APP_URL);
    }

    private int dp(int value) {
        float density = getResources().getDisplayMetrics().density;
        return Math.round(value * density);
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }
}
