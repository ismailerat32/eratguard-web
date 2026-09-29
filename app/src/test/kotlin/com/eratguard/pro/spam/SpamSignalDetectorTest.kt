package com.eratguard.pro.spam

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SpamSignalDetectorTest {

    @Test
    fun normalMessageHasNoAttackSignals() {
        val signals =
            SpamSignalDetector.detect(
                "Merhaba, akşam saat sekizde görüşelim."
            )

        assertFalse(signals.hasUrl)
        assertFalse(signals.hasShortUrl)
        assertEquals(0, signals.urgencyHits)
        assertEquals(0, signals.rewardHits)
        assertEquals(0, signals.financialHits)
        assertEquals(0, signals.credentialHits)
        assertEquals(0, signals.deliveryHits)
        assertFalse(signals.otpLike)
    }

    @Test
    fun urlIsDetected() {
        val signals =
            SpamSignalDetector.detect(
                "Detaylar https://example.com adresinde."
            )

        assertTrue(signals.hasUrl)
        assertFalse(signals.hasShortUrl)
    }

    @Test
    fun shortUrlIsDetectedAsUrlAndShortUrl() {
        val signals =
            SpamSignalDetector.detect(
                "Hemen https://bit.ly/test adresine girin."
            )

        assertTrue(signals.hasUrl)
        assertTrue(signals.hasShortUrl)
        assertTrue(signals.urgencyHits > 0)
    }

    @Test
    fun phishingThemesAreCounted() {
        val signals =
            SpamSignalDetector.detect(
                "Banka hesabınızı hemen doğrulayın ve şifrenizi güncelleyin."
            )

        assertTrue(signals.financialHits > 0)
        assertTrue(signals.credentialHits > 0)
        assertTrue(signals.urgencyHits > 0)
    }

    @Test
    fun rewardAndDeliveryThemesAreDetected() {
        val signals =
            SpamSignalDetector.detect(
                "Hediye kazandınız. Paket teslimatınız için işlem yapın."
            )

        assertTrue(signals.rewardHits > 0)
        assertTrue(signals.deliveryHits > 0)
    }

    @Test
    fun explicitOtpTextIsDetected() {
        val signals =
            SpamSignalDetector.detect(
                "Doğrulama kodunuz yakında gönderilecektir."
            )

        assertTrue(signals.otpLike)
    }

    @Test
    fun numericOtpPatternIsDetected() {
        val signals =
            SpamSignalDetector.detect(
                "Kodunuz 482913."
            )

        assertTrue(signals.otpLike)
    }
}
