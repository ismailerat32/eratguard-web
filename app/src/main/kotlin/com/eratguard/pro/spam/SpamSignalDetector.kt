package com.eratguard.pro.spam

object SpamSignalDetector {

    data class Signals(
        val hasUrl: Boolean,
        val hasShortUrl: Boolean,
        val urgencyHits: Int,
        val rewardHits: Int,
        val financialHits: Int,
        val credentialHits: Int,
        val deliveryHits: Int,
        val otpLike: Boolean
    )

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

    private val numericOtpRegex =
        Regex("""\b\d{4,8}\b""")

    fun detect(
        message: String
    ): Signals {
        val normalized =
            message
                .lowercase()
                .trim()

        return Signals(
            hasUrl =
                urlRegex.containsMatchIn(normalized),

            hasShortUrl =
                shortLinkRegex.containsMatchIn(normalized),

            urgencyHits =
                urgencyWords.count {
                    normalized.contains(it)
                },

            rewardHits =
                rewardWords.count {
                    normalized.contains(it)
                },

            financialHits =
                financialWords.count {
                    normalized.contains(it)
                },

            credentialHits =
                credentialWords.count {
                    normalized.contains(it)
                },

            deliveryHits =
                deliveryWords.count {
                    normalized.contains(it)
                },

            otpLike =
                otpWords.any {
                    normalized.contains(it)
                } ||
                    numericOtpRegex.containsMatchIn(
                        normalized
                    )
        )
    }
}
