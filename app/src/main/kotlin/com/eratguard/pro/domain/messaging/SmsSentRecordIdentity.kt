package com.eratguard.pro.domain.messaging

object SmsSentRecordIdentity {

    data class Fingerprint(
        val recipient: String,
        val body: String,
        val timestamp: Long
    )

    fun create(
        recipient: String,
        body: String,
        timestamp: Long
    ): Fingerprint? {

        val safeRecipient =
            recipient.trim()

        if (
            safeRecipient.isBlank() ||
            body.isBlank() ||
            timestamp <= 0L
        ) {
            return null
        }

        return Fingerprint(
            recipient = safeRecipient,
            body = body,
            timestamp = timestamp
        )
    }

    fun matches(
        fingerprint: Fingerprint,
        storedRecipient: String?,
        storedBody: String?,
        storedTimestamp: Long?
    ): Boolean {

        if (
            storedRecipient == null ||
            storedBody == null ||
            storedTimestamp == null
        ) {
            return false
        }

        return fingerprint.recipient ==
            storedRecipient.trim() &&
            fingerprint.body ==
                storedBody &&
            fingerprint.timestamp ==
                storedTimestamp
    }
}
