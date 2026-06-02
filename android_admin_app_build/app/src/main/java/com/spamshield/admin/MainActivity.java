package com.spamshield.admin;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Build;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.view.ViewGroup;
import android.view.View;
import android.graphics.drawable.Drawable;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.ImageView;
import android.animation.ValueAnimator;
import android.animation.ObjectAnimator;
import android.graphics.drawable.ClipDrawable;
import android.graphics.drawable.LayerDrawable;
import android.widget.ProgressBar;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceError;

public class MainActivity extends Activity {
    private WebView webView;
    private FrameLayout root;
    private FrameLayout splashView;

    private static final String APP_URL = "https://app.eratguard.com/admin/dashboard";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        root = new FrameLayout(this);
        setContentView(root);

        showSplash();

        new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
            @Override
            public void run() {
                showWebView();
            }
        }, 2200);
    }


    private TextView splashTip;
    private ProgressBar splashProgress;

    private TextView makeText(String text, int sp, int color, boolean bold) {
        TextView v = new TextView(this);
        v.setText(text);
        v.setTextSize(sp);
        v.setTextColor(color);
        v.setGravity(Gravity.CENTER);
        if (bold) v.setTypeface(Typeface.DEFAULT_BOLD);
        return v;
    }

    private TextView makeSplashCard(String icon, String text) {
        TextView card = makeText(icon + "\n" + text, 13, Color.WHITE, true);
        card.setGravity(Gravity.CENTER);
        card.setPadding(12, 14, 12, 14);

        GradientDrawable bg = new GradientDrawable();
        bg.setColor(Color.argb(92, 4, 32, 18));
        bg.setStroke(1, Color.argb(95, 140, 255, 90));
        bg.setCornerRadius(22);

        card.setBackground(bg);

        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1
        );
        lp.setMargins(6, 0, 6, 0);
        card.setLayoutParams(lp);
        return card;
    }





    private void showSplash() {
        splashView = new FrameLayout(this);
        splashView.setBackgroundColor(Color.rgb(1, 8, 5));

        ImageView art = new ImageView(this);
        art.setImageResource(R.drawable.eratguard_splash_target);
        art.setScaleType(ImageView.ScaleType.CENTER_CROP);
        art.setAdjustViewBounds(false);

        splashView.addView(
                art,
                new FrameLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.MATCH_PARENT
                )
        );

        LinearLayout realLoaderBox = new LinearLayout(this);
        realLoaderBox.setOrientation(LinearLayout.VERTICAL);
        realLoaderBox.setGravity(Gravity.CENTER);
        realLoaderBox.setPadding(22, 14, 22, 14);

        GradientDrawable loaderBg = new GradientDrawable();
        loaderBg.setColor(Color.argb(224, 1, 12, 6));
        loaderBg.setStroke(1, Color.argb(150, 135, 255, 86));
        loaderBg.setCornerRadius(22);
        realLoaderBox.setBackground(loaderBg);

        TextView loadingText = makeText("Güvenli bağlantı kuruluyor...", 15, Color.argb(238, 245, 255, 245), true);
        loadingText.setPadding(0, 0, 0, 8);

        splashProgress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        splashProgress.setMax(100);
        splashProgress.setProgress(0);
        splashProgress.setIndeterminate(false);

        GradientDrawable progressBg = new GradientDrawable();
        progressBg.setColor(Color.argb(165, 10, 38, 20));
        progressBg.setStroke(1, Color.argb(95, 130, 255, 80));
        progressBg.setCornerRadius(18);

        GradientDrawable progressFill = new GradientDrawable();
        progressFill.setColor(Color.rgb(135, 255, 70));
        progressFill.setCornerRadius(18);

        ClipDrawable progressClip = new ClipDrawable(progressFill, Gravity.LEFT, ClipDrawable.HORIZONTAL);
        LayerDrawable progressLayers = new LayerDrawable(new Drawable[]{progressBg, progressClip});
        progressLayers.setId(0, android.R.id.background);
        progressLayers.setId(1, android.R.id.progress);
        splashProgress.setProgressDrawable(progressLayers);

        LinearLayout.LayoutParams barLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                16
        );
        barLp.setMargins(0, 4, 0, 8);
        splashProgress.setLayoutParams(barLp);

        splashTip = makeText("0%", 22, Color.rgb(145, 255, 88), true);

        realLoaderBox.addView(loadingText);
        realLoaderBox.addView(splashProgress);
        realLoaderBox.addView(splashTip);

        FrameLayout.LayoutParams loaderLp = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        loaderLp.gravity = Gravity.BOTTOM | Gravity.CENTER_HORIZONTAL;
        loaderLp.setMargins(42, 0, 42, 116);

        splashView.addView(realLoaderBox, loaderLp);

        root.addView(
                splashView,
                new FrameLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.MATCH_PARENT
                )
        );

        ValueAnimator animator = ValueAnimator.ofInt(0, 96);
        animator.setDuration(1800);
        animator.addUpdateListener(animation -> {
            int value = (int) animation.getAnimatedValue();
            if (splashProgress != null) splashProgress.setProgress(value);
            if (splashTip != null) splashTip.setText(value + "%");
        });
        animator.start();
    }


    private void showWebView() {
        webView = new WebView(this);

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

        try {
            webView.clearCache(true);
            webView.clearHistory();
            android.webkit.CookieManager.getInstance().removeAllCookies(null);
            android.webkit.CookieManager.getInstance().flush();
            android.webkit.WebStorage.getInstance().deleteAllData();
        } catch (Exception ignored) {}

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            settings.setSafeBrowsingEnabled(true);
        }

        webView.setWebViewClient(new WebViewClient() {
            private boolean firstRealPageShown = false;

            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                String url = request.getUrl().toString();

                if (url.startsWith("https://app.eratguard.com")) {
                    return false;
                }

                return true;
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);

                if (!firstRealPageShown && url != null && url.startsWith("https://app.eratguard.com")) {
                    firstRealPageShown = true;
                    if (splashProgress != null) splashProgress.setProgress(100);
                    if (splashTip != null) splashTip.setText("100%");
                    if (splashView != null) {
                        new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
                            @Override
                            public void run() {
                                if (splashView != null) {
                                    root.removeView(splashView);
                                    splashView = null;
                                }
                            }
                        }, 260);
                    }
                }
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                super.onReceivedError(view, request, error);
                // Splash ekranda kalır; kullanıcı Render/Chrome hata sayfası görmez.
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

        webView.loadUrl(APP_URL + "?apk_v=6g_realurl_" + System.currentTimeMillis());
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
