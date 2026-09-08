package com.eratguard.pro.spam.learning

import java.security.MessageDigest
import java.util.Locale

object SpamLearningCore {

    fun normalizeSender(
        sender: String
    ): String {

        val trimmed =
            sender.trim()

        if (trimmed.isBlank()) {
            return ""
        }

        val compact =
            trimmed.replace(
                Regex("""[\s()\-]"""),
                ""
            )

        return when {
            compact.startsWith("+") ->
                "+" +
                    compact.drop(1)
                        .filter(Char::isDigit)

            compact.startsWith("00") ->
                "+" +
                    compact.drop(2)
                        .filter(Char::isDigit)

            compact.all(Char::isDigit) ->
                compact

            else ->
                compact.lowercase(
                    Locale.ROOT
                )
        }
    }

    fun senderId(
        sender: String
    ): String {

        val normalized =
            normalizeSender(sender)

        if (normalized.isBlank()) {
            return ""
        }

        val digest =
            MessageDigest
                .getInstance("SHA-256")
                .digest(
                    normalized.toByteArray(
                        Charsets.UTF_8
                    )
                )

        return digest.joinToString("") {
            "%02x".format(it)
        }
    }

    fun adjustment(
        spamCount: Int,
        safeCount: Int
    ): Int {

        val spam =
            spamCount.coerceAtLeast(0)

        val safe =
            safeCount.coerceAtLeast(0)

        return ((spam - safe) * 10)
            .coerceIn(
                -30,
                30
            )
    }
}
