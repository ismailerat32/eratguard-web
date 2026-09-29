package com.eratguard.pro.domain.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SmsMessageIdentityTest {

    @Test
    fun currentTimeBecomesMessageIdWhenAhead() {
        assertEquals(
            2000L,
            SmsMessageIdentity.nextMessageId(
                nowMillis = 2000L,
                previousMessageId = 1000L
            )
        )
    }

    @Test
    fun sameMillisecondStillProducesNewMessageId() {
        assertEquals(
            2001L,
            SmsMessageIdentity.nextMessageId(
                nowMillis = 2000L,
                previousMessageId = 2000L
            )
        )
    }

    @Test
    fun clockMovingBackwardStillProducesNewMessageId() {
        assertEquals(
            2001L,
            SmsMessageIdentity.nextMessageId(
                nowMillis = 1500L,
                previousMessageId = 2000L
            )
        )
    }

    @Test
    fun generatedMessageIdIsPositive() {
        assertTrue(
            SmsMessageIdentity.nextMessageId(
                nowMillis = 0L,
                previousMessageId = 0L
            ) > 0L
        )
    }

    @Test
    fun sentAndDeliveredUseDifferentRequestCodes() {
        val messageId = 123456789L

        assertNotEquals(
            SmsMessageIdentity.requestCode(
                messageId,
                0,
                SmsMessageIdentity.CallbackType.SENT
            ),
            SmsMessageIdentity.requestCode(
                messageId,
                0,
                SmsMessageIdentity.CallbackType.DELIVERED
            )
        )
    }

    @Test
    fun differentPartsUseDifferentRequestCodes() {
        val messageId = 123456789L

        assertNotEquals(
            SmsMessageIdentity.requestCode(
                messageId,
                0,
                SmsMessageIdentity.CallbackType.SENT
            ),
            SmsMessageIdentity.requestCode(
                messageId,
                1,
                SmsMessageIdentity.CallbackType.SENT
            )
        )
    }

    @Test
    fun differentMessagesUseDifferentRequestCodesForSample() {
        assertNotEquals(
            SmsMessageIdentity.requestCode(
                123456789L,
                0,
                SmsMessageIdentity.CallbackType.SENT
            ),
            SmsMessageIdentity.requestCode(
                123456790L,
                0,
                SmsMessageIdentity.CallbackType.SENT
            )
        )
    }

    @Test
    fun requestCodeIsStable() {
        val first =
            SmsMessageIdentity.requestCode(
                987654321L,
                7,
                SmsMessageIdentity.CallbackType.DELIVERED
            )

        val second =
            SmsMessageIdentity.requestCode(
                987654321L,
                7,
                SmsMessageIdentity.CallbackType.DELIVERED
            )

        assertEquals(
            first,
            second
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun invalidMessageIdIsRejected() {
        SmsMessageIdentity.requestCode(
            0L,
            0,
            SmsMessageIdentity.CallbackType.SENT
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun negativePartIndexIsRejected() {
        SmsMessageIdentity.requestCode(
            1L,
            -1,
            SmsMessageIdentity.CallbackType.SENT
        )
    }
    @Test(expected = IllegalStateException::class)
    fun messageIdOverflowIsRejected() {
        SmsMessageIdentity.nextMessageId(
            nowMillis = Long.MAX_VALUE,
            previousMessageId = Long.MAX_VALUE
        )
    }


}
