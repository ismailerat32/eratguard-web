package com.eratguard.pro.domain.messaging

object SmsMessageIdentity {

    enum class CallbackType {
        SENT,
        DELIVERED
    }

    fun nextMessageId(
        nowMillis: Long,
        previousMessageId: Long
    ): Long {

        val safeNow =
            nowMillis.coerceAtLeast(1L)

        return if (safeNow > previousMessageId) {
            safeNow
        } else {
            check(previousMessageId < Long.MAX_VALUE) {
                "messageId space exhausted"
            }

            previousMessageId + 1L
        }
    }

    fun requestCode(
        messageId: Long,
        partIndex: Int,
        callbackType: CallbackType
    ): Int {

        require(messageId > 0L) {
            "messageId must be positive"
        }

        require(partIndex >= 0) {
            "partIndex must be non-negative"
        }

        var value =
            messageId xor
                (messageId ushr 32)

        value =
            value xor
                (partIndex.toLong() *
                    0x9E3779B9L)

        value =
            value xor
                when (callbackType) {
                    CallbackType.SENT ->
                        0x13579BDFL

                    CallbackType.DELIVERED ->
                        0x2468ACE0L
                }

        value =
            value xor
                (value ushr 33)

        value *=
            -49064778989728563L

        value =
            value xor
                (value ushr 33)

        return (
            value and
                0x7FFFFFFFL
            ).toInt()
    }
}
