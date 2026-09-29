package com.eratguard.pro.domain.messaging

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SmsActiveMessagePolicyTest {

    @Test
    fun activeMessageCallbackMayUpdateUi() {
        assertTrue(
            SmsActiveMessagePolicy.mayUpdateUiProjection(
                callbackMessageId = 200L,
                activeMessageId = 200L
            )
        )
    }

    @Test
    fun olderMessageCallbackCannotTakeUiOwnership() {
        assertFalse(
            SmsActiveMessagePolicy.mayUpdateUiProjection(
                callbackMessageId = 100L,
                activeMessageId = 200L
            )
        )
    }

    @Test
    fun newerUnexpectedCallbackCannotTakeUiOwnership() {
        assertFalse(
            SmsActiveMessagePolicy.mayUpdateUiProjection(
                callbackMessageId = 300L,
                activeMessageId = 200L
            )
        )
    }

    @Test
    fun invalidMessageIdCannotUpdateUi() {
        assertFalse(
            SmsActiveMessagePolicy.mayUpdateUiProjection(
                callbackMessageId = 0L,
                activeMessageId = 0L
            )
        )
    }
}
