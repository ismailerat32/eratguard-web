package com.eratguard.pro.spam

import com.eratguard.pro.spam.model.SpamVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SpamRiskPolicyTest {

    @Test
    fun scoreBelowSuspiciousThresholdIsSafe() {
        assertEquals(
            SpamVerdict.SAFE,
            SpamRiskPolicy.verdictFor(29)
        )
    }

    @Test
    fun suspiciousThresholdIsInclusive() {
        assertEquals(
            SpamVerdict.SUSPICIOUS,
            SpamRiskPolicy.verdictFor(30)
        )
    }

    @Test
    fun scoreBelowSpamThresholdIsSuspicious() {
        assertEquals(
            SpamVerdict.SUSPICIOUS,
            SpamRiskPolicy.verdictFor(54)
        )
    }

    @Test
    fun spamThresholdIsInclusive() {
        assertEquals(
            SpamVerdict.SPAM,
            SpamRiskPolicy.verdictFor(55)
        )
    }

    @Test
    fun verdictInputIsBounded() {
        assertEquals(
            SpamVerdict.SAFE,
            SpamRiskPolicy.verdictFor(-999)
        )

        assertEquals(
            SpamVerdict.SPAM,
            SpamRiskPolicy.verdictFor(999)
        )
    }

    @Test
    fun highConfidenceThresholdIsInclusive() {
        assertFalse(
            SpamRiskPolicy.isHighConfidenceScore(79)
        )

        assertTrue(
            SpamRiskPolicy.isHighConfidenceScore(80)
        )
    }
}
