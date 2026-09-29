package com.eratguard.pro.domain.messaging

import java.security.MessageDigest

object SmsIncomingIdentity {

    fun fingerprint(
        sender: String,
        body: String,
        timestamp: Long
    ): String? {

        val normalizedSender = sender.trim()

        if (
            normalizedSender.isBlank() ||
            body.isBlank() ||
            timestamp <= 0L
        ) {
            return null
        }

        /*
         * SMS provider/vendor katmanlarında milisaniye hassasiyeti
         * farklılaşabileceğinden aynı saniyedeki aynı mantıksal
         * teslimat tek identity kabul edilir.
         */
        val second = timestamp / 1000L

        val raw =
            "$normalizedSender\u0000$body\u0000$second"

        val digest =
            MessageDigest
                .getInstance("SHA-256")
                .digest(
                    raw.toByteArray(Charsets.UTF_8)
                )

        return digest.joinToString("") {
            "%02x".format(it)
        }
    }
}
