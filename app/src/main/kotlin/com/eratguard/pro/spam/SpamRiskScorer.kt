package com.eratguard.pro.spam

object SpamRiskScorer {

    data class ScoreResult(
        val score: Int,
        val reasons: List<String>,
        val strongAttackCombination: Boolean
    )

    fun score(
        sender: String,
        message: String,
        signals: SpamSignalDetector.Signals
    ): ScoreResult {

        var score = 0
        val reasons = mutableListOf<String>()

        val hasUrl = signals.hasUrl
        val hasShortUrl = signals.hasShortUrl
        val urgencyHits = signals.urgencyHits
        val rewardHits = signals.rewardHits
        val financialHits = signals.financialHits
        val credentialHits = signals.credentialHits
        val deliveryHits = signals.deliveryHits
        val otpLike = signals.otpLike

        /*
         * TEKİL SİNYALLER
         */

        if (hasUrl) {
            score += 30
            reasons += "Mesaj bağlantı içeriyor"
        }

        if (hasShortUrl) {
            score += 30
            reasons += "Kısaltılmış bağlantı tespit edildi"
        }

        if (urgencyHits > 0) {
            val added =
                (urgencyHits * 12)
                    .coerceAtMost(30)

            score += added
            reasons +=
                "Aciliyet baskısı tespit edildi ($urgencyHits)"
        }

        if (rewardHits > 0) {
            val added =
                (rewardHits * 15)
                    .coerceAtMost(35)

            score += added
            reasons +=
                "Ödül/kazanç vaadi tespit edildi ($rewardHits)"
        }

        if (financialHits > 0) {
            val added =
                (financialHits * 10)
                    .coerceAtMost(25)

            score += added
            reasons +=
                "Finansal içerik tespit edildi ($financialHits)"
        }

        if (credentialHits > 0) {
            val added =
                (credentialHits * 15)
                    .coerceAtMost(35)

            score += added
            reasons +=
                "Kimlik veya hesap doğrulama isteği tespit edildi ($credentialHits)"
        }

        if (deliveryHits > 0) {
            val added =
                (deliveryHits * 8)
                    .coerceAtMost(20)

            score += added
            reasons +=
                "Kargo/teslimat teması tespit edildi ($deliveryHits)"
        }

        if (sender.isBlank()) {
            score += 15
            reasons += "Gönderici bilgisi eksik"
        }

        if (message.length > 500) {
            score += 5
            reasons += "Olağandışı uzun mesaj"
        }

        /*
         * YÜKSEK RİSK KOMBİNASYONLARI
         */

        if (hasUrl && credentialHits > 0) {
            score += 35
            reasons +=
                "Bağlantı ile kimlik/hesap işlemi isteniyor"
        }

        if (hasUrl && financialHits > 0) {
            score += 30
            reasons +=
                "Finansal içerik bağlantı ile birlikte kullanılıyor"
        }

        if (hasUrl && deliveryHits > 0) {
            score += 25
            reasons +=
                "Kargo/teslimat bahanesiyle bağlantıya yönlendirme"
        }

        if (hasUrl && rewardHits > 0) {
            score += 35
            reasons +=
                "Ödül/kazanç vaadi bağlantı ile birlikte kullanılıyor"
        }

        if (urgencyHits > 0 && credentialHits > 0) {
            score += 30
            reasons +=
                "Aciliyet baskısı ile hesap/kimlik işlemi isteniyor"
        }

        if (financialHits > 0 && credentialHits > 0) {
            score += 30
            reasons +=
                "Finansal içerik ile hassas bilgi/doğrulama isteği birlikte"
        }

        if (rewardHits > 0 && urgencyHits > 0) {
            score += 20
            reasons +=
                "Ödül vaadi ve aciliyet baskısı birlikte"
        }

        /*
         * OTP KORUMASI
         */

        if (
            otpLike &&
            !hasUrl &&
            financialHits == 0 &&
            rewardHits == 0 &&
            urgencyHits == 0
        ) {
            score -= 20
            reasons +=
                "Normal OTP/doğrulama mesajı olasılığı"
        }

        val boundedScore =
            score.coerceIn(
                0,
                100
            )

        val strongAttackCombination =
            (
                hasShortUrl &&
                    (
                        credentialHits > 0 ||
                            financialHits > 0 ||
                            rewardHits > 0 ||
                            urgencyHits > 0 ||
                            deliveryHits > 0
                    )
            ) ||
                (
                    hasUrl &&
                        rewardHits > 0 &&
                        urgencyHits > 0
                ) ||
                (
                    hasUrl &&
                        credentialHits > 0 &&
                        urgencyHits > 0
                ) ||
                (
                    hasUrl &&
                        financialHits > 0 &&
                        credentialHits > 0
                )

        return ScoreResult(
            score = boundedScore,
            reasons = reasons,
            strongAttackCombination =
                strongAttackCombination
        )
    }
}
