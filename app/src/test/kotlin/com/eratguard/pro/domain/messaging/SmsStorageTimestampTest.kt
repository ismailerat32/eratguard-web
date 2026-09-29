package com.eratguard.pro.domain.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SmsStorageTimestampTest {

    @Test
    fun usesCurrentClockWhenAhead() {
        assertEquals(
            2000L,
            SmsStorageTimestamp.next(
                nowMillis = 2000L,
                previousTimestamp = 1000L
            )
        )
    }

    @Test
    fun advancesWhenClockEqualsPrevious() {
        assertEquals(
            1001L,
            SmsStorageTimestamp.next(
                nowMillis = 1000L,
                previousTimestamp = 1000L
            )
        )
    }

    @Test
    fun advancesWhenClockMovesBackward() {
        assertEquals(
            1001L,
            SmsStorageTimestamp.next(
                nowMillis = 900L,
                previousTimestamp = 1000L
            )
        )
    }

    @Test
    fun sameMillisecondAllocationsCanRemainUnique() {

        val first =
            SmsStorageTimestamp.next(
                nowMillis = 5000L,
                previousTimestamp = 0L
            )

        val second =
            SmsStorageTimestamp.next(
                nowMillis = 5000L,
                previousTimestamp = first
            )

        assertEquals(5000L, first)
        assertEquals(5001L, second)
        assertTrue(second > first)
    }

    @Test
    fun nonPositiveClockStillProducesPositiveTimestamp() {
        assertEquals(
            1L,
            SmsStorageTimestamp.next(
                nowMillis = 0L,
                previousTimestamp = 0L
            )
        )
    }

    @Test(expected = IllegalStateException::class)
    fun refusesOverflow() {
        SmsStorageTimestamp.next(
            nowMillis = Long.MAX_VALUE,
            previousTimestamp = Long.MAX_VALUE
        )
    }
}
