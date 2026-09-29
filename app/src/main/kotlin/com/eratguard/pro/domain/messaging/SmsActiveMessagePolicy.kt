package com.eratguard.pro.domain.messaging

object SmsActiveMessagePolicy {

    fun mayUpdateUiProjection(
        callbackMessageId: Long,
        activeMessageId: Long
    ): Boolean =
        callbackMessageId > 0L &&
            callbackMessageId == activeMessageId
}
