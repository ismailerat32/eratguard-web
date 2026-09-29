package com.eratguard.pro.spam.sms

import android.content.BroadcastReceiver
import com.eratguard.pro.domain.messaging.SmsAsyncLifecycle
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

object SmsBroadcastAsyncRunner {

    private val executor: ExecutorService =
        Executors.newSingleThreadExecutor { runnable ->
            Thread(
                runnable,
                "eratguard-sms-callback"
            ).apply {
                isDaemon = false
            }
        }

    fun execute(
        pendingResult: BroadcastReceiver.PendingResult,
        work: () -> Unit
    ) {
        SmsAsyncLifecycle.execute(
            executor = executor,
            work = work,
            complete = {
                pendingResult.finish()
            }
        )
    }
}
