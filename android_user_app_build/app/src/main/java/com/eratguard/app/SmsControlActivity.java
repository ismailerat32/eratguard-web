package com.eratguard.app;

import android.Manifest;
import android.app.Activity;
import android.app.role.RoleManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.provider.Telephony;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public class SmsControlActivity extends Activity {
    private LinearLayout list;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        render();
    }

    private void render() {
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Color.rgb(2, 8, 6));

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(14), dp(14), dp(14), dp(22));

        scroll.addView(root, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        TextView brand = text("EratGuard", 24, Color.WHITE, true);
        brand.setGravity(Gravity.LEFT);
        root.addView(brand);

        TextView title = text("EratGuard SMS Koruma Merkezi", 28, Color.rgb(35, 255, 137), true);
        title.setGravity(Gravity.LEFT);
        title.setPadding(0, dp(4), 0, dp(6));
        root.addView(title);

        TextView desc = text(
                "Vites-4 hazırlık modu. Bu ekran, EratGuard'ı varsayılan SMS uygulaması yapma ve Vites-5 spam engelleme motoruna geçiş için hazırlanmıştır.",
                14,
                Color.rgb(190, 220, 200),
                false
        );
        desc.setGravity(Gravity.LEFT);
        desc.setPadding(0, 0, 0, dp(12));
        root.addView(desc);

        LinearLayout stats = card();
        root.addView(stats);

        list = stats;
        fillStatusRows();

        Button defaultBtn = button("Varsayılan SMS uygulaması yap");
        defaultBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                requestSmsPermissionsThenDefaultRole();
            }
        });
        root.addView(defaultBtn);

        Button refreshBtn = button("Durumu Yenile");
        refreshBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                render();
            }
        });
        root.addView(refreshBtn);

        Button backBtn = button("EratGuard'a Dön");
        backBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                finish();
            }
        });
        root.addView(backBtn);

        setContentView(scroll);
    }

    private void fillStatusRows() {
        SharedPreferences sp = getSharedPreferences("eratguard_zero_inbox", Context.MODE_PRIVATE);

        row("Varsayılan SMS", isDefaultSmsApp() ? "AKTİF" : "DEĞİL");
        row("RECEIVE_SMS izni", hasPermission(Manifest.permission.RECEIVE_SMS) ? "VAR" : "YOK");
        row("READ_SMS izni", hasPermission(Manifest.permission.READ_SMS) ? "VAR" : "YOK");
        row("SEND_SMS izni", hasPermission(Manifest.permission.SEND_SMS) ? "VAR" : "YOK");

        if (Build.VERSION.SDK_INT >= 33) {
            row("Bildirim izni", hasPermission(Manifest.permission.POST_NOTIFICATIONS) ? "VAR" : "YOK");
        } else {
            row("Bildirim izni", "ANDROID < 13");
        }

        row("Toplam olay", String.valueOf(sp.getInt("total_events", 0)));
        row("Critical sessiz yakalanan", String.valueOf(sp.getInt("critical_auto_deleted", 0)));
        row("Spam yakalanan", String.valueOf(sp.getInt("spam_detected", 0)));
        row("Şüpheli yakalanan", String.valueOf(sp.getInt("suspicious_detected", 0)));
        row("Güvenli görülen", String.valueOf(sp.getInt("safe_seen", 0)));
        row("MMS deliver", String.valueOf(sp.getInt("mms_deliver_seen", 0)));
        row("Respond via message", String.valueOf(sp.getInt("respond_via_message_seen", 0)));

        row("Son aksiyon", sp.getString("last_action", "-"));
        row("Son skor", String.valueOf(sp.getInt("last_score", 0)));
        row("Son gönderen", sp.getString("last_sender", "-"));
        row("Son sebep", sp.getString("last_reason", "-"));
    }

    private boolean hasPermission(String permission) {
        if (Build.VERSION.SDK_INT < 23) return true;
        try {
            return checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isDefaultSmsApp() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                RoleManager roleManager = (RoleManager) getSystemService(RoleManager.class);
                return roleManager != null &&
                        roleManager.isRoleAvailable(RoleManager.ROLE_SMS) &&
                        roleManager.isRoleHeld(RoleManager.ROLE_SMS);
            }

            String currentPackage = Telephony.Sms.getDefaultSmsPackage(this);
            return currentPackage != null && currentPackage.equals(getPackageName());
        } catch (Exception e) {
            return false;
        }
    }

    private void requestDefaultSmsRole() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                RoleManager roleManager = (RoleManager) getSystemService(RoleManager.class);
                if (roleManager != null &&
                        roleManager.isRoleAvailable(RoleManager.ROLE_SMS) &&
                        !roleManager.isRoleHeld(RoleManager.ROLE_SMS)) {
                    Intent intent = roleManager.createRequestRoleIntent(RoleManager.ROLE_SMS);
                    startActivityForResult(intent, 702);
                }
            } else {
                String currentPackage = Telephony.Sms.getDefaultSmsPackage(this);
                if (currentPackage == null || !currentPackage.equals(getPackageName())) {
                    Intent intent = new Intent(Telephony.Sms.Intents.ACTION_CHANGE_DEFAULT);
                    intent.putExtra(Telephony.Sms.Intents.EXTRA_PACKAGE_NAME, getPackageName());
                    startActivityForResult(intent, 702);
                }
            }
        } catch (Exception ignored) {
        }
    }

    private LinearLayout card() {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(14), dp(10), dp(14), dp(10));

        GradientDrawable bg = new GradientDrawable();
        bg.setColor(Color.rgb(7, 28, 17));
        bg.setCornerRadius(dp(20));
        bg.setStroke(1, Color.argb(90, 35, 255, 137));
        box.setBackground(bg);

        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        lp.setMargins(0, dp(8), 0, dp(12));
        box.setLayoutParams(lp);

        return box;
    }

    private void row(String left, String right) {
        LinearLayout r = new LinearLayout(this);
        r.setOrientation(LinearLayout.HORIZONTAL);
        r.setGravity(Gravity.CENTER_VERTICAL);
        r.setPadding(0, dp(9), 0, dp(9));

        TextView l = text(left, 14, Color.rgb(235, 255, 240), true);
        l.setGravity(Gravity.LEFT);

        TextView v = text(right, 14, Color.rgb(35, 255, 137), true);
        v.setGravity(Gravity.RIGHT);

        r.addView(l, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        r.addView(v, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));

        list.addView(r);
    }

    private Button button(String label) {
        Button b = new Button(this);
        b.setText(label);
        b.setTextSize(14);
        b.setTypeface(Typeface.DEFAULT_BOLD);
        b.setTextColor(Color.rgb(0, 22, 10));

        GradientDrawable bg = new GradientDrawable(
                GradientDrawable.Orientation.LEFT_RIGHT,
                new int[]{Color.rgb(255, 221, 53), Color.rgb(35, 255, 137)}
        );
        bg.setCornerRadius(dp(16));
        b.setBackground(bg);

        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(48)
        );
        lp.setMargins(0, dp(8), 0, 0);
        b.setLayoutParams(lp);

        return b;
    }

    private TextView text(String value, int sp, int color, boolean bold) {
        TextView t = new TextView(this);
        t.setText(value);
        t.setTextSize(sp);
        t.setTextColor(color);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    private int dp(int value) {
        float density = getResources().getDisplayMetrics().density;
        return Math.round(value * density);
    }
}
