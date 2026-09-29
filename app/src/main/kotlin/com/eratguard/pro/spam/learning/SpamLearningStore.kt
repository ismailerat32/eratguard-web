package com.eratguard.pro.spam.learning

import android.content.Context

object SpamLearningStore {

    private const val PREFS =
        "eratguard_spam_learning"

    private val writeLock =
        Any()

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

        increment(
            context = context,
            key = spamKey(sender)
        )
    }

    fun markSafe(
        context: Context,
        sender: String
    ) {
        if (normalizeSender(sender).isBlank()) {
            return
        }

        increment(
            context = context,
            key = safeKey(sender)
        )
    }

    private fun increment(
        context: Context,
        key: String
    ) {
        synchronized(writeLock) {
            val prefs =
                context.getSharedPreferences(
                    PREFS,
                    Context.MODE_PRIVATE
                )

            val current =
                prefs.getInt(
                    key,
                    0
                )

            /*
             * Learning feedback is durable state.
             *
             * commit() is intentional here:
             * once markSpam()/markSafe() returns, the updated
             * counter has been synchronously persisted.
             *
             * Saturation prevents Int overflow from corrupting
             * long-lived learning state.
             */
            val next =
                if (current == Int.MAX_VALUE) {
                    Int.MAX_VALUE
                } else {
                    current + 1
                }

            prefs.edit()
                .putInt(
                    key,
                    next
                )
                .commit()
        }
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
