package com.eratguard.pro.spam

import com.eratguard.pro.spam.model.SpamResult
import com.eratguard.pro.spam.model.SpamVerdict

object SpamRiskEngine {

    private val urlRegex =
        Regex("""(?i)\b(?:https?://|www\.)\S+""")

    private val shortLinkRegex =
        Regex("""(?i)\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|is\.gd|rb\.gy|shorturl\.at)/\S*""")

    private val urgencyWords = listOf(
        "acil",
        "hemen",
        "son gün",
        "son gun",
        "son şans",
        "son sans",
        "24 saat içinde",
        "hesabınız kapatılacak",
        "hesabiniz kapatilacak",
        "askıya alınacak",
        "askiya alinacak",
        "erişiminiz durdurulacak",
        "erisiminiz durdurulacak"
    )

    private val rewardWords = listOf(
        "kazandınız",
        "kazandiniz",
        "kazandın",
        "kazandin",
        "ödül",
        "odul",
        "hediye",
        "bedava",
        "bonus",
        "çekiliş",
        "cekilis",
        "tl kazand",
        "ücretsiz",
        "ucretsiz"
    )

    private val financialWords = listOf(
        "banka",
        "kart",
        "kredi kartı",
        "kredi karti",
        "hesap",
        "iban",
        "ödeme",
        "odeme",
        "havale",
        "eft"
    )

    private val credentialWords = listOf(
        "şifre",
        "sifre",
        "parola",
        "pin",
        "kimlik",
        "tc kimlik",
        "kart bilgileri",
        "kart bilgilerinizi",
        "cvv",
        "giriş yap",
        "giris yap",
        "doğrula",
        "dogrula",
        "onayla",
        "güncelle",
        "guncelle"
    )

    private val deliveryWords = listOf(
        "kargo",
        "paket",
        "teslimat",
        "kurye",
        "teslim edilemedi",
        "teslim edilememiştir",
        "teslim edilememistir"
    )

    private val otpWords = listOf(
        "doğrulama kodu",
        "dogrulama kodu",
        "tek kullanımlık",
        "tek kullanimlik",
        "otp",
        "güvenlik kodu",
        "guvenlik kodu"
    )

    fun analyze(
        sender: String,
        message: String
    ): SpamResult {

        var score = 0
        val reasons = mutableListOf<String>()

        val normalized = message
            .lowercase()
            .trim()

        val hasUrl =
            urlRegex.containsMatchIn(normalized)

        val hasShortUrl =
            shortLinkRegex.containsMatchIn(normalized)

        val urgencyHits =
            urgencyWords.count { normalized.contains(it) }

        val rewardHits =
            rewardWords.count { normalized.contains(it) }

        val financialHits =
            financialWords.count { normalized.contains(it) }

        val credentialHits =
            credentialWords.count { normalized.contains(it) }

        val deliveryHits =
            deliveryWords.count { normalized.contains(it) }

        val otpLike =
            otpWords.any { normalized.contains(it) } ||
                Regex("""\b\d{4,8}\b""").containsMatchIn(normalized)

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
            reasons += "Aciliyet baskısı tespit edildi ($urgencyHits)"
        }

        if (rewardHits > 0) {
            val added =
                (rewardHits * 15)
                    .coerceAtMost(35)

            score += added
            reasons += "Ödül/kazanç vaadi tespit edildi ($rewardHits)"
        }

        if (financialHits > 0) {
            val added =
                (financialHits * 10)
                    .coerceAtMost(25)

            score += added
            reasons += "Finansal içerik tespit edildi ($financialHits)"
        }

        if (credentialHits > 0) {
            val added =
                (credentialHits * 15)
                    .coerceAtMost(35)

            score += added
            reasons += "Kimlik veya hesap doğrulama isteği tespit edildi ($credentialHits)"
        }

        if (deliveryHits > 0) {
            val added =
                (deliveryHits * 8)
                    .coerceAtMost(20)

            score += added
            reasons += "Kargo/teslimat teması tespit edildi ($deliveryHits)"
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
         *
         * Bunlar tek tek kelime sayımından daha önemlidir.
         */

        if (hasUrl && credentialHits > 0) {
            score += 35
            reasons += "Bağlantı ile kimlik/hesap işlemi isteniyor"
        }

        if (hasUrl && financialHits > 0) {
            score += 30
            reasons += "Finansal içerik bağlantı ile birlikte kullanılıyor"
        }

        if (hasUrl && deliveryHits > 0) {
            score += 25
            reasons += "Kargo/teslimat bahanesiyle bağlantıya yönlendirme"
        }

        if (hasUrl && rewardHits > 0) {
            score += 35
            reasons += "Ödül/kazanç vaadi bağlantı ile birlikte kullanılıyor"
        }

        if (urgencyHits > 0 && credentialHits > 0) {
            score += 30
            reasons += "Aciliyet baskısı ile hesap/kimlik işlemi isteniyor"
        }

        if (financialHits > 0 && credentialHits > 0) {
            score += 30
            reasons += "Finansal içerik ile hassas bilgi/doğrulama isteği birlikte"
        }

        if (rewardHits > 0 && urgencyHits > 0) {
            score += 20
            reasons += "Ödül vaadi ve aciliyet baskısı birlikte"
        }

        /*
         * OTP KORUMASI
         *
         * Normal doğrulama kodunun sırf sayı ve 'doğrulama' içerdiği için
         * yanlışlıkla karantinaya düşmesini azaltır.
         *
         * Ancak OTP mesajında link veya finansal/kimlik avı sinyali varsa
         * indirim uygulanmaz.
         */
        if (
            otpLike &&
            !hasUrl &&
            financialHits == 0 &&
            rewardHits == 0 &&
            urgencyHits == 0
        ) {
            score -= 20
            reasons += "Normal OTP/doğrulama mesajı olasılığı"
        }

        score =
            score.coerceIn(
                0,
                100
            )

        /*
         * AGGRESSIVE POLICY
         *
         * 0-29  : SAFE
         * 30-54 : SUSPICIOUS -> SmsRouter tarafından karantina
         * 55+   : SPAM       -> SmsRouter tarafından karantina
         */
        val verdict =
            when {
                score >= 55 ->
                    SpamVerdict.SPAM

                score >= 30 ->
                    SpamVerdict.SUSPICIOUS

                else ->
                    SpamVerdict.SAFE
            }

        return SpamResult(
            score = score,
            verdict = verdict,
            reasons = reasons
        )
    }
}
