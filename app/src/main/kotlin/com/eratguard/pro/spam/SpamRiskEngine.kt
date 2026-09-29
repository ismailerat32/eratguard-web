package com.eratguard.pro.spam

import com.eratguard.pro.spam.model.SpamResult
import com.eratguard.pro.spam.model.SpamVerdict

object SpamRiskEngine {

    fun analyze(
        sender: String,
        message: String
    ): SpamResult {

        val signals =
            SpamSignalDetector.detect(
                message
            )

        val scored =
            SpamRiskScorer.score(
                sender = sender,
                message = message,
                signals = signals
            )

        val verdict =
            SpamRiskPolicy.verdictFor(
                scored.score
            )

        val highConfidenceSpam =
            verdict == SpamVerdict.SPAM &&
                SpamRiskPolicy.isHighConfidenceScore(
                    scored.score
                ) &&
                scored.strongAttackCombination

        val reasons =
            scored.reasons.toMutableList()

        if (highConfidenceSpam) {
            reasons +=
                "Çok güçlü spam/phishing sinyal kombinasyonu"
        }

        return SpamResult(
            score = scored.score,
            verdict = verdict,
            reasons = reasons,
            highConfidenceSpam = highConfidenceSpam
        )
    }
}
