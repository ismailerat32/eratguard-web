package com.eratguard.pro.spam.sms

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import com.eratguard.pro.domain.messaging.SmsIncomingAssembly
import com.eratguard.pro.domain.messaging.SmsIncomingProcessing

class IncomingSmsReceiver : BroadcastReceiver() {

    override fun onReceive(
        context: Context,
        intent: Intent
    ) {

        if (
            intent.action !=
            Telephony.Sms.Intents.SMS_DELIVER_ACTION
        ) {
            return
        }

        val messages =
            Telephony.Sms.Intents
                .getMessagesFromIntent(intent)

        if (messages.isNullOrEmpty()) {
            return
        }

        val assembled =
            SmsIncomingAssembly.assemble(
                parts =
                    messages.map { message ->
                        SmsIncomingAssembly.Part(
                            sender =
                                message
                                    .displayOriginatingAddress
                                    .orEmpty(),
                            body =
                                message
                                    .displayMessageBody
                                    .orEmpty(),
                            timestamp =
                                message.timestampMillis
                        )
                    },
                fallbackTimestamp =
                    System.currentTimeMillis()
            )
                ?: return

        val sender = assembled.sender
        val body = assembled.body
        val timestamp = assembled.timestamp

        /*
         * SMS parse/assembly receiver'ın hızlı yolunda tamamlandı.
         * Analiz + persistence + notification işlemleri provider I/O
         * içerebildiği için BroadcastReceiver ana yolundan çıkarılır.
         */
        val pendingResult = goAsync()
        val appContext = context.applicationContext

        SmsBroadcastAsyncRunner.execute(
            pendingResult = pendingResult
        ) {
            val prefs =
                appContext.getSharedPreferences(
                    "eratguard_sms_diagnostics",
                    Context.MODE_PRIVATE
                )

            /*
             * Routing ana işlemdir.
             *
             * Beklenmeyen bir hata oluşursa notification aşamasına
             * geçilmez ve failure diagnostics kalıcılaştırılır.
             */
            val routed =
                try {
                    SmsRouter.route(
                        context = appContext,
                        sender = sender,
                        body = body,
                        timestamp = timestamp
                    )
                } catch (_: Exception) {
                    val outcome =
                        SmsIncomingProcessing.routingFailed()

                    prefs.edit()
                        .putString(
                            "last_processing_status",
                            outcome.status.name
                        )
                        .putString(
                            "last_failed_stage",
                            outcome.failedStage?.name
                        )
                        .putLong(
                            "last_received_at",
                            timestamp
                        )
                        .commit()

                    return@execute
                }

            /*
             * Routing sonucu notification'dan önce diagnostics'e
             * yazılır. Böylece notification başarısız olsa bile
             * başarılı persistence/routing sonucu kaybolmaz.
             */
            prefs.edit()
                .putString(
                    "last_sender",
                    sender
                )
                .putInt(
                    "last_score",
                    routed.score
                )
                .putString(
                    "last_verdict",
                    routed.verdict.name
                )
                .putBoolean(
                    "last_inbox_inserted",
                    routed.inboxInserted
                )
                .putBoolean(
                    "last_quarantined",
                    routed.quarantined
                )
                .putBoolean(
                    "last_fail_safe",
                    routed.failSafeActivated
                )
                .putBoolean(
                    "last_high_confidence",
                    routed.highConfidenceSpam
                )
                .putBoolean(
                    "last_auto_deleted",
                    routed.autoDeleted
                )
                .putLong(
                    "last_received_at",
                    timestamp
                )
                .apply()

            /*
             * Notification ikincil yan etkidir.
             * Hatası routing sonucunu geri alamaz.
             */
            try {
                SmsNotificationManager.notifyIncomingSms(
                    context = appContext,
                    routed = routed
                )

                val outcome =
                    SmsIncomingProcessing.success()

                prefs.edit()
                    .putString(
                        "last_processing_status",
                        outcome.status.name
                    )
                    .remove("last_failed_stage")
                    .apply()

            } catch (_: Exception) {
                val outcome =
                    SmsIncomingProcessing.notificationFailed()

                prefs.edit()
                    .putString(
                        "last_processing_status",
                        outcome.status.name
                    )
                    .putString(
                        "last_failed_stage",
                        outcome.failedStage?.name
                    )
                    .apply()
            }
        }
    }
}
