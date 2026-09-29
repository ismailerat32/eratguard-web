package com.eratguard.pro.domain.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SmsIncomingIdentityTest {

    @Test
    fun sameLogicalSmsProducesSameFingerprint() {
        val a =
            SmsIncomingIdentity.fingerprint(
                "05321234567",
                "Merhaba",
                1_700_000_000_100L
            )

        val b =
            SmsIncomingIdentity.fingerprint(
                "05321234567",
                "Merhaba",
                1_700_000_000_900L
            )

        assertEquals(a, b)
    }

    @Test
    fun senderWhitespaceIsNormalized() {
        val a =
            SmsIncomingIdentity.fingerprint(
                " 05321234567 ",
                "Merhaba",
                1_700_000_000_100L
            )

        val b =
            SmsIncomingIdentity.fingerprint(
                "05321234567",
                "Merhaba",
                1_700_000_000_100L
            )

        assertEquals(a, b)
    }

    @Test
    fun differentSenderProducesDifferentFingerprint() {
        val a =
            SmsIncomingIdentity.fingerprint(
                "05321234567",
                "Merhaba",
                1_700_000_000_100L
            )

        val b =
            SmsIncomingIdentity.fingerprint(
                "05551234567",
                "Merhaba",
                1_700_000_000_100L
            )

        assertNotEquals(a, b)
    }

    @Test
    fun differentBodyProducesDifferentFingerprint() {
        val a =
            SmsIncomingIdentity.fingerprint(
                "05321234567",
                "Merhaba",
                1_700_000_000_100L
            )

        val b =
            SmsIncomingIdentity.fingerprint(
                "05321234567",
                "Merhaba!",
                1_700_000_000_100L
            )

        assertNotEquals(a, b)
    }

    @Test
    fun differentSecondProducesDifferentFingerprint() {
        val a =
            SmsIncomingIdentity.fingerprint(
                "05321234567",
                "Merhaba",
                1_700_000_000_100L
            )

        val b =
            SmsIncomingIdentity.fingerprint(
                "05321234567",
                "Merhaba",
                1_700_000_001_100L
            )

        assertNotEquals(a, b)
    }

    @Test
    fun blankSenderRejected() {
        assertNull(
            SmsIncomingIdentity.fingerprint(
                "   ",
                "Merhaba",
                1_700_000_000_100L
            )
        )
    }

    @Test
    fun blankBodyRejected() {
        assertNull(
            SmsIncomingIdentity.fingerprint(
                "05321234567",
                "   ",
                1_700_000_000_100L
            )
        )
    }

    @Test
    fun zeroTimestampRejected() {
        assertNull(
            SmsIncomingIdentity.fingerprint(
                "05321234567",
                "Merhaba",
                0L
            )
        )
    }

    @Test
    fun negativeTimestampRejected() {
        assertNull(
            SmsIncomingIdentity.fingerprint(
                "05321234567",
                "Merhaba",
                -1L
            )
        )
    }

    @Test
    fun fingerprintIsSha256Hex() {
        val id =
            SmsIncomingIdentity.fingerprint(
                "05321234567",
                "Merhaba",
                1_700_000_000_100L
            )

        assertTrue(id != null)
        assertEquals(64, id!!.length)
        assertTrue(
            id.all {
                it in '0'..'9' ||
                    it in 'a'..'f'
            }
        )
    }

    @Test
    fun canonicalInputPreservesLegacyQuarantineFingerprint() {
        val sender = "05321234567"
        val body = "Merhaba"
        val timestamp = 1_700_000_000_100L

        val second = timestamp / 1000L
        val raw = "$sender\u0000$body\u0000$second"

        val legacy =
            java.security.MessageDigest
                .getInstance("SHA-256")
                .digest(
                    raw.toByteArray(Charsets.UTF_8)
                )
                .joinToString("") {
                    "%02x".format(it)
                }

        val centralized =
            SmsIncomingIdentity.fingerprint(
                sender = sender,
                body = body,
                timestamp = timestamp
            )

        assertEquals(
            legacy,
            centralized
        )
    }

}
