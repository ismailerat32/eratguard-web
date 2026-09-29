package com.eratguard.pro.spam

import com.eratguard.pro.spam.model.SpamResult
import com.eratguard.pro.spam.model.SpamVerdict

object SpamDecisionCore {

    fun applyLearning(
        base: SpamResult,
        learningAdjustment: Int
    ): SpamResult {

        /*
         * AGGRESSIVE LEARNING POLICY
         *
         * Öğrenme sistemi riski yükseltebilir.
         *
         * Ancak güçlü bir SPAM kararını geçmişteki SAFE
         * işaretlemeleri kurtaramaz.
         *
         * Böylece saldırgan bir mesaj, güvenilir görünen veya
         * daha önce güvenli işaretlenmiş bir göndericiden gelse
         * bile güçlü risk sinyalleri varsa korunmaya devam eder.
         */

        val rawAdjustment =
            learningAdjustment.coerceIn(
                -30,
                30
            )

        val adjustment =
            when {
                /*
                 * Base motor zaten SPAM dediyse negatif öğrenmeye
                 * izin verme. Pozitif spam geçmişi skoru artırabilir.
                 */
                base.verdict == SpamVerdict.SPAM ->
                    rawAdjustment.coerceAtLeast(0)

                /*
                 * Çok güçlü şüpheli mesajlarda SAFE geçmişinin
                 * etkisini sınırla.
                 */
                base.score >= 45 ->
                    rawAdjustment.coerceAtLeast(-10)

                /*
                 * Diğer mesajlarda normal öğrenme çalışabilir.
                 */
                else ->
                    rawAdjustment
            }

        val finalScore =
            (base.score + adjustment)
                .coerceIn(
                    0,
                    100
                )

        /*
         * Nihai eşikler RiskEngine ile aynı:
         *
         * 55+   SPAM
         * 30-54 SUSPICIOUS
         * <30   SAFE
         *
         * SUSPICIOUS ve SPAM SmsRouter tarafından
         * karantinaya gönderilir.
         */
        val verdict =
            SpamRiskPolicy.verdictFor(
                finalScore
            )

        val reasons =
            base.reasons.toMutableList()

        if (adjustment != 0) {
            reasons +=
                "Yerel öğrenme skoru: " +
                    (if (adjustment > 0) "+" else "") +
                    adjustment
        }

        if (
            rawAdjustment < 0 &&
            adjustment != rawAdjustment
        ) {
            reasons +=
                "Agresif koruma: güvenli geçmişin risk düşürme etkisi sınırlandı"
        }

        /*
         * RiskEngine tarafından verilen yüksek güvenli spam
         * bilgisini öğrenme katmanında kaybetme.
         *
         * Bu bayrak yalnızca nihai karar hâlâ SPAM ise korunur.
         */
        val highConfidenceSpam =
            base.highConfidenceSpam &&
                verdict == SpamVerdict.SPAM

        return SpamResult(
            score = finalScore,
            verdict = verdict,
            reasons = reasons,
            highConfidenceSpam = highConfidenceSpam
        )
    }
}
