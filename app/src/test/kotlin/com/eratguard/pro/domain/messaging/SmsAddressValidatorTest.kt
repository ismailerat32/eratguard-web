package com.eratguard.pro.domain.messaging

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SmsAddressValidatorTest {

    @Test
    fun internationalNumberIsAccepted() {
        assertTrue(
            SmsAddressValidator.isReplyable(
                "+905551112233"
            )
        )
    }

    @Test
    fun formattedNumberIsAccepted() {
        assertTrue(
            SmsAddressValidator.isReplyable(
                "+90 (555) 111-22-33"
            )
        )
    }

    @Test
    fun localFormattedNumberIsAccepted() {
        assertTrue(
            SmsAddressValidator.isReplyable(
                "0555 111 22 33"
            )
        )
    }

    @Test
    fun shortCodeWithThreeDigitsIsAccepted() {
        assertTrue(
            SmsAddressValidator.isReplyable(
                "555"
            )
        )
    }

    @Test
    fun blankAddressIsRejected() {
        assertFalse(
            SmsAddressValidator.isReplyable(
                "   "
            )
        )
    }

    @Test
    fun twoDigitAddressIsRejected() {
        assertFalse(
            SmsAddressValidator.isReplyable(
                "12"
            )
        )
    }

    @Test
    fun alphanumericSenderIsRejected() {
        assertFalse(
            SmsAddressValidator.isReplyable(
                "MADAME COCO"
            )
        )
    }

    @Test
    fun embeddedPlusIsRejected() {
        assertFalse(
            SmsAddressValidator.isReplyable(
                "12+34"
            )
        )
    }

    @Test
    fun multiplePlusCharactersAreRejected() {
        assertFalse(
            SmsAddressValidator.isReplyable(
                "++905551112233"
            )
        )
    }

    @Test
    fun punctuationOutsidePhoneFormattingIsRejected() {
        assertFalse(
            SmsAddressValidator.isReplyable(
                "0555.111.2233"
            )
        )
    }
}
