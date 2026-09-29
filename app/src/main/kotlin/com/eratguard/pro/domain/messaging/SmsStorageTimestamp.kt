package com.eratguard.pro.domain.messaging

object SmsStorageTimestamp {

    fun next(
        nowMillis: Long,
        previousTimestamp: Long
    ): Long {

        val safeNow =
            nowMillis.coerceAtLeast(1L)

        return if (safeNow > previousTimestamp) {
            safeNow
        } else {
            check(previousTimestamp < Long.MAX_VALUE) {
                "SMS storage timestamp space exhausted"
            }

            previousTimestamp + 1L
        }
    }
}
