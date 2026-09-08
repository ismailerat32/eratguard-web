package com.eratguard.pro.spam

import com.eratguard.pro.spam.model.SpamResult
import com.eratguard.pro.spam.model.SpamVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SpamDecisionEngineTest {

    @Test
    fun spamLearningCanRaiseSafeMessageToSuspicious() {
        val base = SpamResult(
            score = 10,
            verdict = SpamVerdict.SAFE,
            reasons = emptyList()
        )

        val result = SpamDecisionCore.applyLearning(
            base = base,
            learningAdjustment = 30
        )

        assertEquals(40, result.score)
        assertEquals(SpamVerdict.SUSPICIOUS, result.verdict)
    }

    @Test
    fun safeLearningCannotRescueConfirmedSpam() {
        val base = SpamResult(
            score = 70,
            verdict = SpamVerdict.SPAM,
            reasons = listOf("Güçlü phishing sinyali")
        )

        val result = SpamDecisionCore.applyLearning(
            base = base,
            learningAdjustment = -30
        )

        assertEquals(70, result.score)
        assertEquals(SpamVerdict.SPAM, result.verdict)

        assertTrue(
            result.reasons.any {
                it.contains("Agresif koruma")
            }
        )
    }

    @Test
    fun strongSuspiciousMessageGetsOnlyLimitedSafeReduction() {
        val base = SpamResult(
            score = 50,
            verdict = SpamVerdict.SUSPICIOUS,
            reasons = emptyList()
        )

        val result = SpamDecisionCore.applyLearning(
            base = base,
            learningAdjustment = -30
        )

        assertEquals(40, result.score)
        assertEquals(SpamVerdict.SUSPICIOUS, result.verdict)
    }

    @Test
    fun weakRiskCanStillBenefitFromSafeLearning() {
        val base = SpamResult(
            score = 25,
            verdict = SpamVerdict.SAFE,
            reasons = emptyList()
        )

        val result = SpamDecisionCore.applyLearning(
            base = base,
            learningAdjustment = -30
        )

        assertEquals(0, result.score)
        assertEquals(SpamVerdict.SAFE, result.verdict)
    }

    @Test
    fun decisionScoreNeverExceeds100() {
        val base = SpamResult(
            score = 90,
            verdict = SpamVerdict.SPAM,
            reasons = emptyList()
        )

        val result = SpamDecisionCore.applyLearning(
            base = base,
            learningAdjustment = 30
        )

        assertEquals(100, result.score)
        assertEquals(SpamVerdict.SPAM, result.verdict)
    }

    @Test
    fun positiveAdjustmentIsLimitedToThirty() {
        val base = SpamResult(
            score = 0,
            verdict = SpamVerdict.SAFE,
            reasons = emptyList()
        )

        val result = SpamDecisionCore.applyLearning(
            base = base,
            learningAdjustment = 999
        )

        assertEquals(30, result.score)
        assertEquals(SpamVerdict.SUSPICIOUS, result.verdict)
    }

    @Test
    fun negativeAdjustmentIsLimitedToMinusThirtyForWeakMessages() {
        val base = SpamResult(
            score = 20,
            verdict = SpamVerdict.SAFE,
            reasons = emptyList()
        )

        val result = SpamDecisionCore.applyLearning(
            base = base,
            learningAdjustment = -999
        )

        assertEquals(0, result.score)
        assertEquals(SpamVerdict.SAFE, result.verdict)
    }
}
