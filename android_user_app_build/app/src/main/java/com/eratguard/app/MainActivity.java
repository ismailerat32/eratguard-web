package com.eratguard.app;

import android.app.Activity;
import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.graphics.Color;
import android.content.Intent;
import android.net.Uri;
import android.view.Gravity;
import android.view.View;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.TextView;

public class MainActivity extends Activity {

    private WebView webView;

    // ERATGUARD SIGNATURE RADIAL WEB DASHBOARD
    private static final String APP_URL = "https://app.eratguard.com/signature-radial";
    private static final String ALLOWED_HOST_1 = "app.eratguard.com";
    private static final String ALLOWED_HOST_2 = "eratguard.com";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestProtectionPermissions();
        showSignatureRadial();
    }

    private void requestProtectionPermissions() {
        if (Build.VERSION.SDK_INT >= 23) {
            java.util.ArrayList<String> permissions = new java.util.ArrayList<>();
            if (Build.VERSION.SDK_INT >= 33 &&
                    checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                permissions.add(Manifest.permission.POST_NOTIFICATIONS);
            }

            if (!permissions.isEmpty()) {
                requestPermissions(permissions.toArray(new String[0]), 701);
            }
        }
    }

    private void showSignatureRadial() {
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(Color.rgb(0, 8, 5));

        webView = new WebView(this);
        webView.setBackgroundColor(Color.rgb(0, 8, 5));

        WebSettings s = webView.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setDatabaseEnabled(true);
        s.setLoadWithOverviewMode(true);
        s.setUseWideViewPort(true);
        s.setBuiltInZoomControls(false);
        s.setDisplayZoomControls(false);
        s.setSupportZoom(false);
        s.setCacheMode(WebSettings.LOAD_DEFAULT);
        s.setMediaPlaybackRequiresUserGesture(false);

        webView.setOverScrollMode(View.OVER_SCROLL_NEVER);
        webView.setScrollBarStyle(View.SCROLLBARS_INSIDE_OVERLAY);

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                return handleUrl(view, uri);
            }

            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                return handleUrl(view, Uri.parse(url));
            }
        });

        root.addView(webView, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
        ));

        TextView badge = new TextView(this);
        badge.setText("SIGNATURE RADIAL");
        badge.setTextColor(Color.rgb(35, 255, 137));
        badge.setTextSize(11);
        badge.setGravity(Gravity.CENTER);
        badge.setAlpha(0.0f); // görünmez; sadece build marker
        root.addView(badge, new FrameLayout.LayoutParams(1, 1, Gravity.TOP | Gravity.LEFT));

        setContentView(root);
        webView.loadUrl(APP_URL);
    }

    private boolean handleUrl(WebView view, Uri uri) {
        if (uri == null) return false;

        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase();
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase();

        if (("https".equals(scheme) || "http".equals(scheme)) &&
                (host.equals(ALLOWED_HOST_1) || host.equals(ALLOWED_HOST_2) || host.endsWith(".eratguard.com"))) {
            return false;
        }

        try {
            Intent i = new Intent(Intent.ACTION_VIEW, uri);
            startActivity(i);
        } catch (Exception ignored) {}

        return true;
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
            return;
        }
        super.onBackPressed();
    }
}
