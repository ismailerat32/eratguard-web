package com.eratguard.pro.spam.sms

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.media.AudioAttributes
import android.provider.Settings
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.eratguard.pro.MainActivity
import com.eratguard.pro.R
import com.eratguard.pro.spam.model.SpamVerdict

object SmsNotificationManager {

    private const val CHANNEL_ID =
        "eratguard_sms_protection"

    private const val CHANNEL_NAME =
        "SMS Koruması"

    fun notifyIncomingSms(
        context: Context,
        routed: SmsRouter.RouteResult
    ) {

        createChannel(context)

        if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }

        val title =
            when {
                routed.autoDeleted ->
                    "Kesin spam engellendi"

                routed.quarantined ->
                    "Şüpheli mesaj engellendi"

                routed.verdict == SpamVerdict.SAFE ->
                    "Yeni mesaj"

                else ->
                    "SMS koruması"
            }

        val text =
            when {
                routed.autoDeleted ->
                    "Yüksek güvenli spam mesajı cihazda saklanmadı."

                routed.quarantined ->
                    "Şüpheli mesaj EratGuard Karantina'ya alındı."

                routed.verdict == SpamVerdict.SAFE ->
                    "Yeni SMS Gelen Kutusu'na alındı."

                else ->
                    "Bir SMS EratGuard tarafından işlendi."
            }

        val launchIntent =
            context.packageManager
                .getLaunchIntentForPackage(
                    context.packageName
                )
                ?.apply {
                    flags =
                        android.content.Intent.FLAG_ACTIVITY_NEW_TASK or
                            android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP

                    putExtra(
                        MainActivity.EXTRA_OPEN_SMS_CENTER,
                        true
                    )
                }

        val contentIntent =
            launchIntent?.let {

                PendingIntent.getActivity(
                    context,
                    30001,
                    it,
                    PendingIntent.FLAG_UPDATE_CURRENT or
                        PendingIntent.FLAG_IMMUTABLE
                )
            }

        val notification =
            NotificationCompat.Builder(
                context,
                CHANNEL_ID
            )
                .setSmallIcon(R.drawable.ic_notification_eratguard)
                .setContentTitle(title)
                .setContentText(text)
                .setPriority(
                    NotificationCompat.PRIORITY_HIGH
                )
                .apply {
                    contentIntent?.let {
                        setContentIntent(it)
                    }
                }
                .setAutoCancel(true)
                .setVisibility(
                    NotificationCompat.VISIBILITY_PRIVATE
                )
                .setCategory(
                    NotificationCompat.CATEGORY_MESSAGE
                )
                .build()

        NotificationManagerCompat
            .from(context)
            .notify(
                (System.currentTimeMillis() and 0x7FFFFFFF)
                    .toInt(),
                notification
            )
    }

    private fun createChannel(
        context: Context
    ) {

        if (
            Build.VERSION.SDK_INT <
            Build.VERSION_CODES.O
        ) {
            return
        }

        val channel =
            NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description =
                    "EratGuard gelen SMS ve spam koruma bildirimleri"

                lockscreenVisibility =
                    android.app.Notification.VISIBILITY_PRIVATE

                val audioAttributes =
                    AudioAttributes.Builder()
                        .setUsage(
                            AudioAttributes.USAGE_NOTIFICATION
                        )
                        .setContentType(
                            AudioAttributes.CONTENT_TYPE_SONIFICATION
                        )
                        .build()

                setSound(
                    Settings.System.DEFAULT_NOTIFICATION_URI,
                    audioAttributes
                )

                enableVibration(true)
            }

        context
            .getSystemService(
                NotificationManager::class.java
            )
            .createNotificationChannel(
                channel
            )
    }
}
