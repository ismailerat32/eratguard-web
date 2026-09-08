package com.eratguard.pro.spam.update

import android.content.Context
import androidx.work.Worker
import androidx.work.WorkerParameters

class FilterUpdateWorker(
    context: Context,
    params: WorkerParameters
) : Worker(context, params) {

    override fun doWork(): Result {

        /*
         * PHASE 1:
         * Worker altyapısı hazır.
         *
         * Sonraki aşamada:
         * - HTTPS filter endpoint
         * - paket sürümü
         * - dijital imza doğrulaması
         * - atomik güncelleme
         * - rollback
         *
         * eklenecek.
         */

        val prefs = applicationContext.getSharedPreferences(
            "eratguard_filter_state",
            Context.MODE_PRIVATE
        )

        prefs.edit()
            .putLong(
                "last_filter_check",
                System.currentTimeMillis()
            )
            .apply()

        return Result.success()
    }
}
