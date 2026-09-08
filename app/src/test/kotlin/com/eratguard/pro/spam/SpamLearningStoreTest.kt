package com.eratguard.pro.spam

import com.eratguard.pro.spam.learning.SpamLearningCore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SpamLearningStoreTest {

    @Test
    fun blankSenderHasNoIdentity() {

        assertEquals(
            "",
            SpamLearningCore.normalizeSender("")
        )

        assertEquals(
            "",
            SpamLearningCore.senderId("")
        )
    }

    @Test
    fun spamLearningIncreasesByTen() {

        assertEquals(
            10,
            SpamLearningCore.adjustment(
                spamCount = 1,
                safeCount = 0
            )
        )

        assertEquals(
            20,
            SpamLearningCore.adjustment(
                spamCount = 2,
                safeCount = 0
            )
        )
    }

    @Test
    fun safeLearningDecreasesByTen() {

        assertEquals(
            -10,
            SpamLearningCore.adjustment(
                spamCount = 0,
                safeCount = 1
            )
        )
    }

    @Test
    fun positiveAdjustmentStopsAtThirty() {

        assertEquals(
            30,
            SpamLearningCore.adjustment(
                spamCount = 20,
                safeCount = 0
            )
        )
    }

    @Test
    fun negativeAdjustmentStopsAtMinusThirty() {

        assertEquals(
            -30,
            SpamLearningCore.adjustment(
                spamCount = 0,
                safeCount = 20
            )
        )
    }

    @Test
    fun internationalFormattingMapsToSameSender() {

        val a =
            SpamLearningCore.normalizeSender(
                "+90 555 111 22 33"
            )

        val b =
            SpamLearningCore.normalizeSender(
                "0090-555-111-22-33"
            )

        assertEquals(
            a,
            b
        )
    }

    @Test
    fun alphanumericSenderIsCaseInsensitive() {

        assertEquals(
            SpamLearningCore.normalizeSender(
                "KARGO"
            ),
            SpamLearningCore.normalizeSender(
                "kargo"
            )
        )
    }

    @Test
    fun sha256SenderIdIsStable() {

        val a =
            SpamLearningCore.senderId(
                "+90 555 111 22 33"
            )

        val b =
            SpamLearningCore.senderId(
                "00905551112233"
            )

        assertEquals(
            a,
            b
        )

        assertEquals(
            64,
            a.length
        )

        assertTrue(
            a.matches(
                Regex("[0-9a-f]{64}")
            )
        )
    }

    @Test
    fun differentSendersHaveDifferentIds() {

        val a =
            SpamLearningCore.senderId(
                "+905551112233"
            )

        val b =
            SpamLearningCore.senderId(
                "+905559998877"
            )

        assertNotEquals(
            a,
            b
        )
    }

    @Test
    fun negativeCountsCannotCreateFalseLearning() {

        assertEquals(
            0,
            SpamLearningCore.adjustment(
                spamCount = -10,
                safeCount = -20
            )
        )
    }
}
