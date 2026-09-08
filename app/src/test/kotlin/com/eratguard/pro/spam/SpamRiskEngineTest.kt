package com.eratguard.pro.spam

import com.eratguard.pro.spam.model.SpamVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SpamRiskEngineTest {

    @Test
    fun normalMessageIsSafe() {
        val result = SpamRiskEngine.analyze(
            sender = "+905551112233",
            message = "Merhaba, akşam saat 8 gibi görüşelim."
        )

        assertEquals(SpamVerdict.SAFE, result.verdict)
        assertTrue(result.score < 30)
    }

    @Test
    fun singleUrlIsQuarantinedAsSuspicious() {
        val result = SpamRiskEngine.analyze(
            sender = "+905551112233",
            message = "Detaylar için https://example.com adresine bakın."
        )

        assertEquals(SpamVerdict.SUSPICIOUS, result.verdict)
        assertTrue(result.score >= 30)
    }

    @Test
    fun rewardAndUrgencyIncreaseRisk() {
        val result = SpamRiskEngine.analyze(
            sender = "+905551112233",
            message = "Ödül kazandınız, hediyenizi hemen alın."
        )

        assertTrue(result.score >= 30)
        assertTrue(result.verdict != SpamVerdict.SAFE)
    }

    @Test
    fun rewardUrgencyAndLinkBecomeSpam() {
        val result = SpamRiskEngine.analyze(
            sender = "+905551112233",
            message = "Ödül kazandınız. Hediyenizi hemen alın https://example.com"
        )

        assertEquals(SpamVerdict.SPAM, result.verdict)
        assertTrue(result.score >= 55)
    }

    @Test
    fun bankCredentialAndLinkBecomeSpam() {
        val result = SpamRiskEngine.analyze(
            sender = "BANKA",
            message = "Banka hesabınızı doğrulayın ve şifrenizi güncelleyin: https://example.com"
        )

        assertEquals(SpamVerdict.SPAM, result.verdict)
        assertTrue(result.score >= 55)
    }

    @Test
    fun deliveryLinkIsNotAllowedToPassSafe() {
        val result = SpamRiskEngine.analyze(
            sender = "KARGO",
            message = "Paketiniz teslim edilemedi. Adresinizi güncelleyin: https://example.com"
        )

        assertTrue(
            result.verdict == SpamVerdict.SUSPICIOUS ||
                result.verdict == SpamVerdict.SPAM
        )
        assertTrue(result.score >= 30)
    }

    @Test
    fun normalOtpCanRemainSafe() {
        val result = SpamRiskEngine.analyze(
            sender = "BANKA",
            message = "Doğrulama kodunuz 482913. Bu kodu kimseyle paylaşmayın."
        )

        assertEquals(SpamVerdict.SAFE, result.verdict)
        assertTrue(result.score < 30)
    }

    @Test
    fun otpWithLinkIsNotTrusted() {
        val result = SpamRiskEngine.analyze(
            sender = "BANKA",
            message = "Doğrulama kodunuz 482913. İşlemi tamamlamak için https://example.com adresine girin."
        )

        assertTrue(result.verdict != SpamVerdict.SAFE)
    }

    @Test
    fun blankSenderAddsAggressiveRisk() {
        val normal = SpamRiskEngine.analyze(
            sender = "+905551112233",
            message = "Merhaba"
        )

        val blank = SpamRiskEngine.analyze(
            sender = "",
            message = "Merhaba"
        )

        assertEquals(normal.score + 15, blank.score)
    }

    @Test
    fun longMessageAddsRisk() {
        val short = SpamRiskEngine.analyze(
            sender = "+905551112233",
            message = "A".repeat(100)
        )

        val long = SpamRiskEngine.analyze(
            sender = "+905551112233",
            message = "A".repeat(501)
        )

        assertEquals(short.score + 5, long.score)
    }

    @Test
    fun scoreNeverExceeds100() {
        val result = SpamRiskEngine.analyze(
            sender = "",
            message = (
                "kazandınız ödül hediye acil hemen banka kart şifre doğrula " +
                    "kargo paket https://bit.ly/test "
                ).repeat(20)
        )

        assertTrue(result.score in 0..100)
        assertEquals(SpamVerdict.SPAM, result.verdict)
    }
}
