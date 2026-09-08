package com.eratguard.pro.spam.model

enum class SpamVerdict {
    SAFE,
    SUSPICIOUS,
    SPAM
}

data class SpamResult(
    val score: Int,
    val verdict: SpamVerdict,
    val reasons: List<String>
)
