package com.eratguard.pro.spam.store

import android.content.Context

object SpamProtectionSettings {

    private const val PREFS_NAME =
        "eratguard_spam_protection_settings"

    private const val KEY_AUTO_DELETE_HIGH_CONFIDENCE =
        "auto_delete_high_confidence_spam"

    /*
     * Güvenlik gereği varsayılan KAPALI.
     *
     * Legacy API/key adı "auto delete" olarak korunuyor.
     * Mevcut davranış provider içindeki kayıtlı bir SMS'i silmek değildir.
     *
     * Ayar açıkken yalnızca yüksek güvenli spam olarak değerlendirilen
     * yeni gelen mesajın Inbox veya karantinaya persist edilmesi engellenir.
     *
     * Böylece gerçekte yapılmayan bir kalıcı provider silme işlemi
     * varmış gibi davranılmaz.
     */
    fun isAutoDeleteHighConfidenceEnabled(
        context: Context
    ): Boolean =
        context
            .getSharedPreferences(
                PREFS_NAME,
                Context.MODE_PRIVATE
            )
            .getBoolean(
                KEY_AUTO_DELETE_HIGH_CONFIDENCE,
                false
            )

    fun setAutoDeleteHighConfidenceEnabled(
        context: Context,
        enabled: Boolean
    ) {
        context
            .getSharedPreferences(
                PREFS_NAME,
                Context.MODE_PRIVATE
            )
            .edit()
            .putBoolean(
                KEY_AUTO_DELETE_HIGH_CONFIDENCE,
                enabled
            )
            .apply()
    }
}
