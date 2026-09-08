package com.eratguard.pro.spam.sms

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class IncomingMmsReceiver : BroadcastReceiver() {

    override fun onReceive(
        context: Context,
        intent: Intent
    ) {
        val prefs =
            context.getSharedPreferences(
                "eratguard_sms_diagnostics",
                Context.MODE_PRIVATE
            )

        prefs.edit()
            .putLong(
                "last_mms_event",
                System.currentTimeMillis()
            )
            .apply()
    }
}
