package com.eratguard.pro.spam

import com.eratguard.pro.spam.model.SpamVerdict

object SpamRiskPolicy {

    const val SUSPICIOUS_SCORE = 30
    const val SPAM_SCORE = 55
    const val HIGH_CONFIDENCE_SCORE = 80

    fun verdictFor(
        score: Int
    ): SpamVerdict {
        val normalized =
            score.coerceIn(
                0,
                100
            )

        return when {
            normalized >= SPAM_SCORE ->
                SpamVerdict.SPAM

            normalized >= SUSPICIOUS_SCORE ->
                SpamVerdict.SUSPICIOUS

            else ->
                SpamVerdict.SAFE
        }
    }

    fun isHighConfidenceScore(
        score: Int
    ): Boolean =
        score >= HIGH_CONFIDENCE_SCORE
}
