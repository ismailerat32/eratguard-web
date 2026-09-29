package com.eratguard.pro.domain.messaging

import com.eratguard.pro.spam.model.SpamVerdict
import org.junit.Assert.assertEquals
import org.junit.Test

class SmsRoutingPolicyTest {

    @Test
    fun safeMessageGoesToInbox() {
        val decision =
            SmsRoutingPolicy.decide(
                verdict = SpamVerdict.SAFE,
                highConfidenceSpam = false,
                autoDeleteHighConfidenceEnabled = false
            )

        assertEquals(
            SmsRoutingPolicy.Destination.INBOX,
            decision.destination
        )
    }

    @Test
    fun suspiciousMessageGoesToQuarantine() {
        val decision =
            SmsRoutingPolicy.decide(
                verdict = SpamVerdict.SUSPICIOUS,
                highConfidenceSpam = false,
                autoDeleteHighConfidenceEnabled = false
            )

        assertEquals(
            SmsRoutingPolicy.Destination.QUARANTINE,
            decision.destination
        )
    }

    @Test
    fun normalSpamGoesToQuarantine() {
        val decision =
            SmsRoutingPolicy.decide(
                verdict = SpamVerdict.SPAM,
                highConfidenceSpam = false,
                autoDeleteHighConfidenceEnabled = true
            )

        assertEquals(
            SmsRoutingPolicy.Destination.QUARANTINE,
            decision.destination
        )
    }

    @Test
    fun highConfidenceSpamStaysInQuarantineWhenAutoDeleteDisabled() {
        val decision =
            SmsRoutingPolicy.decide(
                verdict = SpamVerdict.SPAM,
                highConfidenceSpam = true,
                autoDeleteHighConfidenceEnabled = false
            )

        assertEquals(
            SmsRoutingPolicy.Destination.QUARANTINE,
            decision.destination
        )
    }

    @Test
    fun highConfidenceSpamIsAutoDeletedWhenUserEnabledIt() {
        val decision =
            SmsRoutingPolicy.decide(
                verdict = SpamVerdict.SPAM,
                highConfidenceSpam = true,
                autoDeleteHighConfidenceEnabled = true
            )

        assertEquals(
            SmsRoutingPolicy.Destination.DROP,
            decision.destination
        )
    }

    @Test
    fun suspiciousNeverAutoDeletesEvenWithHighConfidenceFlag() {
        val decision =
            SmsRoutingPolicy.decide(
                verdict = SpamVerdict.SUSPICIOUS,
                highConfidenceSpam = true,
                autoDeleteHighConfidenceEnabled = true
            )

        assertEquals(
            SmsRoutingPolicy.Destination.QUARANTINE,
            decision.destination
        )
    }

    @Test
    fun safeNeverAutoDeletesEvenWithHighConfidenceFlag() {
        val decision =
            SmsRoutingPolicy.decide(
                verdict = SpamVerdict.SAFE,
                highConfidenceSpam = true,
                autoDeleteHighConfidenceEnabled = true
            )

        assertEquals(
            SmsRoutingPolicy.Destination.INBOX,
            decision.destination
        )
    }
}
