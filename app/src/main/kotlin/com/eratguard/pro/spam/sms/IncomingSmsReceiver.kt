package com.eratguard.pro.spam.sms

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony

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

        val sender =
            messages.firstOrNull()
                ?.displayOriginatingAddress
                .orEmpty()

        val body =
            messages.joinToString(
                separator = ""
            ) {
                it.displayMessageBody.orEmpty()
            }

        val timestamp =
            messages.firstOrNull()
                ?.timestampMillis
                ?.takeIf { it > 0L }
                ?: System.currentTimeMillis()

        val routed =
            SmsRouter.route(
                context = context,
                sender = sender,
                body = body,
                timestamp = timestamp
            )

        context
            .getSharedPreferences(
                "eratguard_sms_diagnostics",
                Context.MODE_PRIVATE
            )
            .edit()
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
            .putLong(
                "last_received_at",
                timestamp
            )
            .apply()
    }
}
