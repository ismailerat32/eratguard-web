package com.eratguard.pro.domain.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SmsSentRecordIdentityTest {

    @Test
    fun validFingerprintIsCreated() {

        val result =
            SmsSentRecordIdentity.create(
                recipient = " 5551234567 ",
                body = "Merhaba",
                timestamp = 1000L
            )

        assertNotNull(result)

        assertEquals(
            "5551234567",
            result!!.recipient
        )

        assertEquals(
            "Merhaba",
            result.body
        )

        assertEquals(
            1000L,
            result.timestamp
        )
    }

    @Test
    fun blankRecipientIsRejected() {

        assertNull(
            SmsSentRecordIdentity.create(
                recipient = "   ",
                body = "Merhaba",
                timestamp = 1000L
            )
        )
    }

    @Test
    fun blankBodyIsRejected() {

        assertNull(
            SmsSentRecordIdentity.create(
                recipient = "5551234567",
                body = "",
                timestamp = 1000L
            )
        )
    }

    @Test
    fun invalidTimestampIsRejected() {

        assertNull(
            SmsSentRecordIdentity.create(
                recipient = "5551234567",
                body = "Merhaba",
                timestamp = 0L
            )
        )
    }

    @Test
    fun exactStoredRecordMatches() {

        val fingerprint =
            SmsSentRecordIdentity.create(
                recipient = "5551234567",
                body = "Merhaba",
                timestamp = 1000L
            )!!

        assertTrue(
            SmsSentRecordIdentity.matches(
                fingerprint = fingerprint,
                storedRecipient = "5551234567",
                storedBody = "Merhaba",
                storedTimestamp = 1000L
            )
        )
    }

    @Test
    fun differentTimestampDoesNotMatch() {

        val fingerprint =
            SmsSentRecordIdentity.create(
                recipient = "5551234567",
                body = "Merhaba",
                timestamp = 1000L
            )!!

        assertFalse(
            SmsSentRecordIdentity.matches(
                fingerprint = fingerprint,
                storedRecipient = "5551234567",
                storedBody = "Merhaba",
                storedTimestamp = 1001L
            )
        )
    }

    @Test
    fun differentBodyDoesNotMatch() {

        val fingerprint =
            SmsSentRecordIdentity.create(
                recipient = "5551234567",
                body = "Merhaba",
                timestamp = 1000L
            )!!

        assertFalse(
            SmsSentRecordIdentity.matches(
                fingerprint = fingerprint,
                storedRecipient = "5551234567",
                storedBody = "Başka mesaj",
                storedTimestamp = 1000L
            )
        )
    }

    @Test
    fun differentRecipientDoesNotMatch() {

        val fingerprint =
            SmsSentRecordIdentity.create(
                recipient = "5551234567",
                body = "Merhaba",
                timestamp = 1000L
            )!!

        assertFalse(
            SmsSentRecordIdentity.matches(
                fingerprint = fingerprint,
                storedRecipient = "5557654321",
                storedBody = "Merhaba",
                storedTimestamp = 1000L
            )
        )
    }

    @Test
    fun missingStoredFieldsDoNotMatch() {

        val fingerprint =
            SmsSentRecordIdentity.create(
                recipient = "5551234567",
                body = "Merhaba",
                timestamp = 1000L
            )!!

        assertFalse(
            SmsSentRecordIdentity.matches(
                fingerprint,
                null,
                "Merhaba",
                1000L
            )
        )

        assertFalse(
            SmsSentRecordIdentity.matches(
                fingerprint,
                "5551234567",
                null,
                1000L
            )
        )

        assertFalse(
            SmsSentRecordIdentity.matches(
                fingerprint,
                "5551234567",
                "Merhaba",
                null
            )
        )
    }
}
