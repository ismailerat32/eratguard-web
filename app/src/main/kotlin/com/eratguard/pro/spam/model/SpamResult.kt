package com.eratguard.pro.spam.model

enum class SpamVerdict {
    SAFE,
    SUSPICIOUS,
    SPAM
}

data class SpamResult(
    val score: Int,
    val verdict: SpamVerdict,
    val reasons: List<String>,

    /*
     * HIGH CONFIDENCE SPAM
     *
     * true olması tek başına mesajı silmez.
     *
     * Bu alan yalnızca çok güçlü ve birbiriyle ilişkili
     * spam/phishing sinyalleri bulunduğunu belirtir.
     *
     * Otomatik kalıcı silme daha sonra ayrıca:
     *
     * 1) verdict == SPAM
     * 2) highConfidenceSpam == true
     * 3) kullanıcı "Kesin spam'i otomatik sil" ayarını açmış
     *
     * koşullarının tamamına bağlanacaktır.
     */
    val highConfidenceSpam: Boolean = false
)
