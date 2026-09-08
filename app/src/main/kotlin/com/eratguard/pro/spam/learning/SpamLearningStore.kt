package com.eratguard.pro.spam.learning

import android.content.Context

object SpamLearningStore {

    private const val PREFS =
        "eratguard_spam_learning"

    internal fun normalizeSender(
        sender: String
    ): String =
        SpamLearningCore.normalizeSender(
            sender
        )

    internal fun senderId(
        sender: String
    ): String =
        SpamLearningCore.senderId(
            sender
        )

    private fun spamKey(
        sender: String
    ): String =
        "spam_sender_${senderId(sender)}"

    private fun safeKey(
        sender: String
    ): String =
        "safe_sender_${senderId(sender)}"

    fun markSpam(
        context: Context,
        sender: String
    ) {

        if (normalizeSender(sender).isBlank()) {
            return
        }

        val prefs =
            context.getSharedPreferences(
                PREFS,
                Context.MODE_PRIVATE
            )

        val key =
            spamKey(sender)

        val current =
            prefs.getInt(
                key,
                0
            )

        prefs.edit()
            .putInt(
                key,
                current + 1
            )
            .apply()
    }

    fun markSafe(
        context: Context,
        sender: String
    ) {

        if (normalizeSender(sender).isBlank()) {
            return
        }

        val prefs =
            context.getSharedPreferences(
                PREFS,
                Context.MODE_PRIVATE
            )

        val key =
            safeKey(sender)

        val current =
            prefs.getInt(
                key,
                0
            )

        prefs.edit()
            .putInt(
                key,
                current + 1
            )
            .apply()
    }

    fun senderAdjustment(
        context: Context,
        sender: String
    ): Int {

        if (normalizeSender(sender).isBlank()) {
            return 0
        }

        val prefs =
            context.getSharedPreferences(
                PREFS,
                Context.MODE_PRIVATE
            )

        val spam =
            prefs.getInt(
                spamKey(sender),
                0
            )

        val safe =
            prefs.getInt(
                safeKey(sender),
                0
            )

        return SpamLearningCore.adjustment(
            spamCount = spam,
            safeCount = safe
        )
    }
}
